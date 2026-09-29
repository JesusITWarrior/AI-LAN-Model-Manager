package custom

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

const (
	testPlanExec   = "/usr/local/bin/probe"
	testProviderID = "probe-provider"
	testCallerID   = "caller-1"
	testActionID   = "probe"
)

func posixCaps() CommandPlanGlobalCaps {
	return CommandPlanGlobalCaps{
		MaxTimeoutMs:        60_000,
		MaxOutputBytes:      1_048_576,
		MaxExecutableLength: 200,
		MaxSlots:            8,
		MaxEnvEntries:       8,
	}
}

// validBinding builds a simple valid binding that authorizes testPlanExec under root.
func validBinding() CustomActionBinding {
	return CustomActionBinding{
		ProviderID:     testProviderID,
		CallerID:       testCallerID,
		AllowedRoots:   []string{"/usr/local/bin"},
		AllowedEnvKeys: []string{},
		Slots:          []CommandPlaceSlot{},
		ValueBinds:     map[string]any{},
	}
}

func probeTemplate() CustomActionTemplate {
	return CustomActionTemplate{
		ActionID:       testActionID,
		Executable:     testPlanExec,
		Argv:           []string{"probe", "--host"},
		Env:            map[string]string{},
		TimeoutMs:      5000,
		MaxOutputBytes: 8192,
	}
}

// plan builds a valid plan, failing the test on any deviation.
func plan(t *testing.T, template CustomActionTemplate, binding CustomActionBinding, caps CommandPlanGlobalCaps, flavor PathFlavor) *CustomCommandPlan {
	t.Helper()
	p, err := Plan(template, binding, caps, flavor)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	return p
}

func validPlan(t *testing.T) *CustomCommandPlan {
	return plan(t, probeTemplate(), validBinding(), posixCaps(), flavorPosix)
}

func nowZero() time.Time {
	return time.Date(2026, 9, 26, 22, 1, 2, 987654321, time.FixedZone("t", -5*60*60))
}

// validJSON builds a post-verify-able observation body.
func validJSON(observedAt string, extra map[string]any) []byte {
	body := map[string]any{
		"providerId": testProviderID,
		"operation":  "probe",
		"actionId":   testActionID,
		"observedAt": observedAt,
		"payload":    map[string]any{"ok": true},
	}
	for k, v := range extra {
		body[k] = v
	}
	raw, _ := json.Marshal(body)
	return raw
}

// funcRunner adapts a func to the Runner interface (used by every test).
type funcRunner func(ctx context.Context, plan *CustomCommandPlan, outputBound int) ([]byte, error)

func (f funcRunner) Run(ctx context.Context, plan *CustomCommandPlan, outputBound int) ([]byte, error) {
	return f(ctx, plan, outputBound)
}

// --- success path -----------------------------------------------------------

// TestSuccessPathBoundedVerified requires a post-verified, bounded observation to
// return with a frozen, payload-backed observation.
func TestSuccessPathBoundedVerified(t *testing.T) {
	observedAt := nowZero().UTC().Format(time.RFC3339Nano)
	runner := funcRunner(func(ctx context.Context, plan *CustomCommandPlan, outputBound int) ([]byte, error) {
		return validJSON(observedAt, nil), nil
	})
	e, err := New(validPlan(t), OpProbe, StaticAuthorization(), func() time.Time { return nowZero() })
	if err != nil {
		t.Fatal(err)
	}
	obs, err := e.Fake(runner).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if obs.Provider() != testProviderID || obs.Operation() != OpProbe || obs.Action() != testActionID {
		t.Fatalf("unexpected binding: %s/%s/%s", obs.Provider(), obs.Operation(), obs.Action())
	}
	if !obs.PayloadFrozen() {
		t.Fatal("observation payload must be deep-frozen")
	}
	snap := obs.PayloadSnapshot()
	if snap == nil || snap["ok"] != true {
		t.Fatalf("payload snapshot = %v", snap)
	}
}

// TestEverySupportedOperationBinds requires probe, inventory, load, drain, and
// unload each plan and execute when the actionId matches its operation.
func TestEverySupportedOperationBinds(t *testing.T) {
	for _, op := range []Operation{OpProbe, OpInventory, OpLoad, OpDrain, OpUnload} {
		template := probeTemplate()
		template.ActionID = string(op)
		p := plan(t, template, validBinding(), posixCaps(), flavorPosix)
		e, err := New(p, op, StaticAuthorization(), func() time.Time { return nowZero() })
		if err != nil {
			t.Fatalf("%s New: %v", op, err)
		}
		spawner := funcRunner(func(ctx context.Context, plan *CustomCommandPlan, outputBound int) ([]byte, error) {
			return validJSON(nowZero().UTC().Format(time.RFC3339Nano), map[string]any{"operation": string(op), "actionId": string(op)}), nil
		})
		obs, err := e.Fake(spawner).Run(context.Background())
		if err != nil {
			t.Fatalf("%s Run: %v", op, err)
		}
		if obs.Operation() != op {
			t.Fatalf("%s operation mismatch", op)
		}
	}
}

// --- denial-before-exec -----------------------------------------------------

// TestAuthorizationDeniedBeforeExecution requires a denied Authorization to
// prevent the process from starting (the runner is never consulted).
func TestAuthorizationDeniedBeforeExecution(t *testing.T) {
	started := false
	spawner := funcRunner(func(ctx context.Context, plan *CustomCommandPlan, outputBound int) ([]byte, error) {
		started = true
		return nil, nil
	})
	e, err := New(validPlan(t), OpProbe, staticDenied{}, func() time.Time { return nowZero() })
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Fake(spawner).Run(context.Background())
	if err != ErrCustomDenied {
		t.Fatalf("error = %v, want ErrCustomDenied", err)
	}
	if started {
		t.Fatal("process must not start when authorization is denied")
	}
}

// staticDenied denies every request (redacted reason).
func TestNilAuthorizationFailsClosed(t *testing.T) {
	if _, err := New(validPlan(t), OpProbe, nil, func() time.Time { return nowZero() }); err != ErrCustomDenied {
		t.Fatalf("error = %v, want ErrCustomDenied", err)
	}
}

type panicAuthorization struct{}

func (panicAuthorization) Authorize(*CustomCommandPlan, Operation) (bool, string) { panic("secret") }

func TestPanickingAuthorizationFailsClosed(t *testing.T) {
	e, err := New(validPlan(t), OpProbe, panicAuthorization{}, func() time.Time { return nowZero() })
	if err != nil {
		t.Fatal(err)
	}
	started := false
	_, err = e.Fake(funcRunner(func(context.Context, *CustomCommandPlan, int) ([]byte, error) {
		started = true
		return nil, nil
	})).Run(context.Background())
	if err != ErrCustomDenied || started {
		t.Fatalf("error = %v, started = %v", err, started)
	}
}

type staticDenied struct{}

func (staticDenied) Authorize(*CustomCommandPlan, Operation) (bool, string) {
	return false, "redacted reason"
}

// TestAuthorizationRevokedImmediatelyBeforeRun requires an authorization that is
// allowed until just before Run to report ErrCustomDenied (revoked).
func TestAuthorizationRevokedImmediatelyBeforeRun(t *testing.T) {
	allow := true
	spawner := funcRunner(func(ctx context.Context, plan *CustomCommandPlan, outputBound int) ([]byte, error) {
		return nil, nil
	})
	authz := &revokedAuth{allow: &allow}
	e, err := New(validPlan(t), OpProbe, authz, func() time.Time { return nowZero() })
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Fake(spawner).Run(context.Background())
	if err != ErrCustomDenied {
		t.Fatalf("error = %v, want ErrCustomDenied (revoked)", err)
	}
	if authz.allow != nil && *authz.allow {
		t.Fatal("allow flag must have flipped to false before Run")
	}
}

// revokedAuth flips allow to false on Authorize (a revoked authorization).
type revokedAuth struct{ allow *bool }

func (a *revokedAuth) Authorize(*CustomCommandPlan, Operation) (bool, string) {
	*a.allow = false
	return *a.allow, "redacted"
}

// --- cancellation -----------------------------------------------------------

// TestCancellationRefusedBeforeSpawn requires a cancelled context to fail before
// the process starts.
func TestCancellationRefusedBeforeSpawn(t *testing.T) {
	spawner := funcRunner(func(ctx context.Context, plan *CustomCommandPlan, outputBound int) ([]byte, error) {
		t.Fatal("process must not start with a cancelled context")
		return nil, nil
	})
	e, err := New(validPlan(t), OpProbe, StaticAuthorization(), func() time.Time { return nowZero() })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = e.Fake(spawner).Run(ctx)
	if err != ErrCustomCancelled {
		t.Fatalf("error = %v, want ErrCustomCancelled", err)
	}
}

// TestContextCancelledByRunner requires a runner that returns context.Canceled
// to report ErrCustomCancelled.
func TestContextCancelledByRunner(t *testing.T) {
	spawner := funcRunner(func(ctx context.Context, plan *CustomCommandPlan, outputBound int) ([]byte, error) {
		return nil, context.Canceled
	})
	e, err := New(validPlan(t), OpProbe, StaticAuthorization(), func() time.Time { return nowZero() })
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Fake(spawner).Run(context.Background())
	if err != ErrCustomCancelled {
		t.Fatalf("error = %v, want ErrCustomCancelled", err)
	}
}

// --- timeout ----------------------------------------------------------------

// TestTimeoutRequiresPerPlanTimeout requires a runner that blocks to be killed by
// the per-plan timeout and report ErrCustomTimeout.
func TestTimeoutRequiresPerPlanTimeout(t *testing.T) {
	spawner := funcRunner(func(ctx context.Context, plan *CustomCommandPlan, outputBound int) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	p := plan(t, probeTemplate(), validBinding(), posixCaps(), flavorPosix)
	e, err := New(p, OpProbe, StaticAuthorization(), func() time.Time { return nowZero() })
	if err != nil {
		t.Fatal(err)
	}
	// Force a tiny 15ms plan timeout directly.
	e.plan.timeoutMs = 15
	_, err = e.Fake(spawner).Run(context.Background())
	if err != ErrCustomTimeout {
		t.Fatalf("error = %v, want ErrCustomTimeout", err)
	}
}

// --- output overflow --------------------------------------------------------

// TestOutputOverflowRequiresBound requires a runner exceeding the output bound to
// report ErrCustomOutputOverflow.
func TestOutputOverflowRequiresBound(t *testing.T) {
	big := make([]byte, 4096)
	for i := range big {
		big[i] = 'x'
	}
	spawner := funcRunner(func(ctx context.Context, plan *CustomCommandPlan, outputBound int) ([]byte, error) {
		return big, nil
	})
	p := plan(t, probeTemplate(), validBinding(), posixCaps(), flavorPosix)
	e, err := New(p, OpProbe, StaticAuthorization(), func() time.Time { return nowZero() })
	if err != nil {
		t.Fatal(err)
	}
	// Force a tiny 64-byte output bound directly.
	e.outputBound = 64
	_, err = e.Fake(spawner).Run(context.Background())
	if err != ErrCustomOutputOverflow {
		t.Fatalf("error = %v, want ErrCustomOutputOverflow", err)
	}
}

// --- malformed output -------------------------------------------------------

// TestMalformedOutputRejected requires non-JSON, missing fields, and empty output
// to report ErrCustomMalformed.
func TestMalformedOutputRejected(t *testing.T) {
	cases := []string{"", "not json", "{}", `{"providerId":"x"}`, `{"providerId":"probe-provider","providerId":"probe-provider","operation":"probe","actionId":"probe","observedAt":"2026-09-27T03:01:02.987654321Z","payload":{}}`, `{"providerId":"probe-provider","operation":"probe","actionId":"probe","observedAt":"2026-09-27T03:01:02.987654321Z","payload":{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":{"k":{"l":{"m":{"n":{"o":{"p":{"q":1}}}}}}}}}}}}}}}}}}`}
	for _, raw := range cases {
		spawner := funcRunner(func(ctx context.Context, plan *CustomCommandPlan, outputBound int) ([]byte, error) {
			return []byte(raw), nil
		})
		e, err := New(validPlan(t), OpProbe, StaticAuthorization(), func() time.Time { return nowZero() })
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.Fake(spawner).Run(context.Background()); err != ErrCustomMalformed {
			t.Fatalf("output %q error = %v, want ErrCustomMalformed", raw, err)
		}
	}
}

// --- redaction --------------------------------------------------------------

// TestFailureRedactsExecutableAndArgv requires a generic process failure to be
// redacted to ErrCustomExecution (never the executable, argv, or OS detail).
func TestFailureRedactsExecutableAndArgv(t *testing.T) {
	spawner := funcRunner(func(ctx context.Context, plan *CustomCommandPlan, outputBound int) ([]byte, error) {
		return []byte("sensitive-path=" + plan.Executable()), fmt.Errorf("exec: /usr/local/bin/probe failed: permission denied")
	})
	e, err := New(validPlan(t), OpProbe, StaticAuthorization(), func() time.Time { return nowZero() })
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Fake(spawner).Run(context.Background())
	if err != ErrCustomExecution {
		t.Fatalf("error = %v, want ErrCustomExecution", err)
	}
}

// TestSensitivePayloadRedactedAsHostile requires an output containing a credential,
// endpoint, or LAN address to be redacted to ErrCustomHostile (never returned).
func TestSensitivePayloadRedactedAsHostile(t *testing.T) {
	observedAt := nowZero().UTC().Format(time.RFC3339Nano)
	body := map[string]any{
		"providerId": testProviderID,
		"operation":  "probe",
		"actionId":   testActionID,
		"observedAt": observedAt,
		"secret":     "secret-token-https://localhost:5173",
	}
	raw, _ := json.Marshal(body)
	spawner := funcRunner(func(ctx context.Context, plan *CustomCommandPlan, outputBound int) ([]byte, error) {
		return raw, nil
	})
	e, err := New(validPlan(t), OpProbe, StaticAuthorization(), func() time.Time { return nowZero() })
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Fake(spawner).Run(context.Background())
	if err != ErrCustomHostile {
		t.Fatalf("error = %v, want ErrCustomHostile", err)
	}
}

// --- operation/action/provider binding --------------------------------------

// TestOperationActionProviderBinding requires a mismatched provider, action, or
// operation to be rejected (fail closed).
func TestOperationActionProviderBinding(t *testing.T) {
	observedAt := nowZero().UTC().Format(time.RFC3339Nano)
	cases := []map[string]any{
		{"providerId": "other", "operation": "probe", "actionId": testActionID, "payload": map[string]any{}},
		{"providerId": testProviderID, "operation": "load", "actionId": testActionID, "payload": map[string]any{}},
		{"providerId": testProviderID, "operation": "probe", "actionId": "load", "payload": map[string]any{}},
	}
	for _, c := range cases {
		raw := c
		raw["observedAt"] = observedAt
		jsoned, _ := json.Marshal(raw)
		spawner := funcRunner(func(ctx context.Context, plan *CustomCommandPlan, outputBound int) ([]byte, error) {
			return jsoned, nil
		})
		e, err := New(validPlan(t), OpProbe, StaticAuthorization(), func() time.Time { return nowZero() })
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.Fake(spawner).Run(context.Background()); err != ErrCustomOperationMismatch {
			t.Fatalf("binding case = %v, want ErrCustomOperationMismatch", err)
		}
	}
}

// TestOperationMismatchedPlanAction requires a plan whose actionId is not bound to
// the requested operation to fail at construction.
func TestOperationMismatchedPlanAction(t *testing.T) {
	p := validPlan(t) // actionId "probe"
	if _, err := New(p, OpLoad, StaticAuthorization(), func() time.Time { return nowZero() }); err != ErrCustomOperationMismatch {
		t.Fatalf("New with load op error = %v, want ErrCustomOperationMismatch", err)
	}
	if _, err := New(p, OpDrain, StaticAuthorization(), func() time.Time { return nowZero() }); err != ErrCustomOperationMismatch {
		t.Fatalf("New with drain op error = %v, want ErrCustomOperationMismatch", err)
	}
}

// --- stale / hostile timestamps ---------------------------------------------

// TestStaleObservationRejected requires an observedAt older than the staleness
// window to be rejected with ErrCustomStale.
func TestStaleObservationRejected(t *testing.T) {
	old := nowZero().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	spawner := funcRunner(func(ctx context.Context, plan *CustomCommandPlan, outputBound int) ([]byte, error) {
		return validJSON(old, nil), nil
	})
	e, err := New(validPlan(t), OpProbe, StaticAuthorization(), func() time.Time { return nowZero() })
	if err != nil {
		t.Fatal(err)
	}
	obs, err := e.Fake(spawner).Run(context.Background())
	if err != ErrCustomStale {
		t.Fatalf("obs = %v, error = %v, want ErrCustomStale", obs, err)
	}
}

// TestHostileFutureTimestampRejected requires a future observedAt to be rejected
// with ErrCustomHostile.
func TestHostileFutureTimestampRejected(t *testing.T) {
	future := nowZero().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	spawner := funcRunner(func(ctx context.Context, plan *CustomCommandPlan, outputBound int) ([]byte, error) {
		return validJSON(future, nil), nil
	})
	e, err := New(validPlan(t), OpProbe, StaticAuthorization(), func() time.Time { return nowZero() })
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Fake(spawner).Run(context.Background())
	if err != ErrCustomHostile {
		t.Fatalf("error = %v, want ErrCustomHostile", err)
	}
}

// --- detached / immutable returned observations -----------------------------

// TestReturnedObservationIsDetached requires the returned payload be immutable and
// every snapshot be independent from later mutation.
func TestReturnedObservationIsDetached(t *testing.T) {
	observedAt := nowZero().UTC().Format(time.RFC3339Nano)
	inner := map[string]any{"nested": map[string]any{"k": "v"}, "list": []any{"a", "b"}}
	spawner := funcRunner(func(ctx context.Context, plan *CustomCommandPlan, outputBound int) ([]byte, error) {
		return validJSON(observedAt, map[string]any{"payload": inner}), nil
	})
	e, err := New(validPlan(t), OpProbe, StaticAuthorization(), func() time.Time { return nowZero() })
	if err != nil {
		t.Fatal(err)
	}
	obs, err := e.Fake(spawner).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !obs.PayloadFrozen() {
		t.Fatal("payload must be deep-frozen")
	}
	snap1 := obs.PayloadSnapshot()
	if nested, ok := snap1["nested"].(map[string]any); ok {
		nested["k"] = "changed"
	}
	if list, ok := snap1["list"].([]any); ok {
		list[0] = "changed"
	}
	snap2 := obs.PayloadSnapshot()
	internalPayload := obs.PayloadSnapshot()
	if v, ok := internalPayload["nested"].(map[string]any); !ok || v["k"] != "v" {
		t.Fatal("internal payload must remain v")
	}
	if v, ok := snap2["nested"].(map[string]any); !ok || v["k"] != "v" {
		t.Fatalf("internal payload was mutated via snapshot: %v", snap2["nested"])
	}
}

// TestPayloadDeepCopyIndependence requires two snapshots to be independent copies
// that do not alias each other's mutable structure.
func TestPayloadDeepCopyIndependence(t *testing.T) {
	observedAt := nowZero().UTC().Format(time.RFC3339Nano)
	inner := map[string]any{"a": map[string]any{"x": 1}}
	spawner := funcRunner(func(ctx context.Context, plan *CustomCommandPlan, outputBound int) ([]byte, error) {
		return validJSON(observedAt, map[string]any{"payload": inner}), nil
	})
	e, err := New(validPlan(t), OpProbe, StaticAuthorization(), func() time.Time { return nowZero() })
	if err != nil {
		t.Fatal(err)
	}
	obs, err := e.Fake(spawner).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s1 := obs.PayloadSnapshot()
	s2 := obs.PayloadSnapshot()
	s1["a"].(map[string]any)["x"] = 999
	if s2["a"].(map[string]any)["x"] != float64(1) {
		t.Fatal("snapshots must not alias each other")
	}
}

// TestReturnedObservationImmutableAndFrozen checks the package doc claim that the
// returned payload is deeply immutable: attempts to mutate the snapshot do not
// propagate to later snapshots or the internal payload.
func TestReturnedObservationImmutableAndFrozen(t *testing.T) {
	observedAt := nowZero().UTC().Format(time.RFC3339Nano)
	inner := map[string]any{"k": "v"}
	spawner := funcRunner(func(ctx context.Context, plan *CustomCommandPlan, outputBound int) ([]byte, error) {
		return validJSON(observedAt, map[string]any{"payload": inner}), nil
	})
	e, err := New(validPlan(t), OpProbe, StaticAuthorization(), func() time.Time { return nowZero() })
	if err != nil {
		t.Fatal(err)
	}
	obs, err := e.Fake(spawner).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = strings.TrimSpace(obs.Provider())
	snap := obs.PayloadSnapshot()
	snap["k"] = "changed"
	if got := obs.PayloadSnapshot()["k"]; got != "v" {
		t.Fatalf("payload should be immutable: got %v", got)
	}
}
