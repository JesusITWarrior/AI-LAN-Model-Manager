// Execution runs a validated custom command plan against the local host: it
// rechecks explicit local authorization immediately before spawning, then runs
// ONLY the plan's exact executable and argv (built child environment solely from
// the plan, never ambient environment), bounds stdout/stderr bytes, honors
// context cancellation and a per-plan timeout, redacts every failure to a stable
// machine code (never an executable, argv, env value, hostile output,
// credential/endpoint, OS detail, or process output), and post-verifies the
// returned observation against the runtime contract (operation/action/provider
// binding, freshness, absence of hostile values) before the controller may trust
// it. The normalized observation it returns is detached and deeply immutable.
//
// The operation allowlist is exactly probe, inventory, load, drain, unload. No
// controller credential or endpoint is ever passed: the child environment is
// assembled only from the plan, and no network destination is accepted.
package custom

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"sort"
	"time"
)

// Stable machine codes. Every error this package emits is one of these: they leak
// nothing (no path, argv, env value, endpoint, credential, OS detail, or hostile
// process output).
var (
	ErrCustomExecution         = errors.New("ERR_CUSTOM_EXECUTION") // generic spawn failure, redacted
	ErrCustomDenied            = errors.New("ERR_CUSTOM_DENIED")    // authorization denied or revoked
	ErrCustomOperationMismatch = errors.New("ERR_CUSTOM_OPERATION_MISMATCH")
	ErrCustomStale             = errors.New("ERR_CUSTOM_STALE")
	ErrCustomHostile           = errors.New("ERR_CUSTOM_HOSTILE")
	ErrCustomMalformed         = errors.New("ERR_CUSTOM_MALFORMED")
	ErrCustomCancelled         = errors.New("ERR_CUSTOM_CANCELLED")
	ErrCustomTimeout           = errors.New("ERR_CUSTOM_TIMEOUT")
	ErrCustomOutputOverflow    = errors.New("ERR_CUSTOM_OUTPUT_OVERFLOW")
)

// DefaultStaleWindow bounds how far an observation's observedAt may predate now
// before the observation is treated as stale.
const DefaultStaleWindow = 3 * time.Second

// DefaultTimeout is used when a plan declares a non-positive timeout.
const DefaultTimeout = 5 * time.Second

// Operation is one of the five lifecycle operations this adapter supports.
type Operation string

const (
	OpProbe     Operation = "probe"
	OpInventory Operation = "inventory"
	OpLoad      Operation = "load"
	OpDrain     Operation = "drain"
	OpUnload    Operation = "unload"
)

// operationActions maps each supported operation to the exact plan actionId that
// operation is bound to. A plan whose actionId differs from its operation is a
// binding failure and is rejected (fail closed).
var operationActions = map[Operation]string{
	OpProbe:     "probe",
	OpInventory: "inventory",
	OpLoad:      "load",
	OpDrain:     "drain",
	OpUnload:    "unload",
}

// Authorization rechecks local permission immediately before each spawn. The
// returned machine reason is redacted from the caller; only the boolean gates
// execution. Fail closed: any denied or revoked state returns false and prevents
// starting the process.
type Authorization interface {
	Authorize(plan *CustomCommandPlan, operation Operation) (allowed bool, reason string)
}

// StaticAuthorization always authorizes. It exists for tests and for callers who
// bind authorization externally; production must supply a stateful Authorization.
func StaticAuthorization() Authorization { return staticAuthorization{} }

type staticAuthorization struct{}

func (staticAuthorization) Authorize(*CustomCommandPlan, Operation) (bool, string) { return true, "" }

func safelyAuthorize(authz Authorization, plan *CustomCommandPlan, operation Operation) (allowed bool) {
	defer func() {
		if recover() != nil {
			allowed = false
		}
	}()
	allowed, _ = authz.Authorize(plan, operation)
	return allowed
}

// Runner spawns a bounded process for a plan. The default production runner uses
// exec.CommandContext and never inherits ambient environment. Tests inject a fake
// to exercise every branch deterministically without spawning real processes.
type Runner interface {
	// Run executes the plan under ctx and bounds output at outputBound bytes. It
	// returns the captured combined output (empty on output overflow) and the
	// raw process error (which may contain the executable path; callers redact).
	Run(ctx context.Context, plan *CustomCommandPlan, outputBound int) (output []byte, runErr error)
}

// SystemRunner is the production Runner: it spawns the plan's exact executable
// with argv only, a pure child environment (built solely from the plan), and a
// combined output buffer bounded at outputBound bytes.
type SystemRunner struct{}

// NewSystemRunner returns a production SystemRunner.
func NewSystemRunner() SystemRunner { return SystemRunner{} }

// Run spawns the plan under ctx and bounds output. It returns ErrOutputOverflow
// when the process writes beyond the bound, regardless of the process exit.
func (SystemRunner) Run(ctx context.Context, plan *CustomCommandPlan, outputBound int) ([]byte, error) {
	cmd := exec.CommandContext(ctx, plan.Executable(), plan.Argv()...)
	cmd.Env = toEnv(plan.Env()) // child environment is built solely from the plan; never ambient env.
	buffer := &boundedBuffer{limit: outputBound}
	cmd.Stdout, cmd.Stderr = buffer, buffer
	runErr := cmd.Run()
	if buffer.exceeded {
		return nil, ErrCustomOutputOverflow
	}
	return buffer.Bytes(), runErr
}

// Execution is a single validated command execution bound to one operation.
type Execution struct {
	plan        *CustomCommandPlan
	operation   Operation
	authz       Authorization
	now         func() time.Time
	outputBound int
	staleWindow time.Duration
	runner      Runner
}

// New builds an Execution for one operation bound to one plan. It fails closed
// (nil) when the plan is nil, the operation is unsupported, or the plan's action
// is not bound to the operation.
func New(plan *CustomCommandPlan, operation Operation, authz Authorization, now func() time.Time) (*Execution, error) {
	if plan == nil {
		return nil, ErrCustomOperationMismatch
	}
	actionBound, bound := operationActions[operation]
	if !bound || plan.ActionID() != actionBound {
		return nil, ErrCustomOperationMismatch
	}
	if plan.CallerID() == "" || plan.ProviderID() == "" {
		return nil, ErrCustomOperationMismatch
	}
	if now == nil {
		now = time.Now
	}
	if authz == nil {
		return nil, ErrCustomDenied
	}
	outputLimit := plan.MaxOutputBytes()
	if outputLimit < 1 {
		outputLimit = maxOutputBytes
	}
	return &Execution{
		plan:        plan,
		operation:   operation,
		authz:       authz,
		now:         now,
		outputBound: outputLimit,
		staleWindow: DefaultStaleWindow,
		runner:      NewSystemRunner(),
	}, nil
}

// NewSystem builds an Execution that runs on the real host (SystemRunner).
func NewSystem(plan *CustomCommandPlan, operation Operation, authz Authorization, now func() time.Time) (*Execution, error) {
	e, err := New(plan, operation, authz, now)
	if err != nil {
		return nil, err
	}
	e.runner = NewSystemRunner()
	return e, nil
}

// WithStaleWindow returns a copy of the Execution with a custom staleness window.
func (e *Execution) WithStaleWindow(d time.Duration) *Execution {
	if e == nil {
		return nil
	}
	cp := *e
	cp.staleWindow = d
	return &cp
}

// Fake scripts a Runner on an Execution for tests: it returns the given output
// and error, honoring a nil error as success.
func (e *Execution) Fake(runner Runner) *Execution {
	if e == nil {
		return nil
	}
	cp := *e
	cp.runner = runner
	return &cp
}

// Run rechecks authorization, then executes the plan's exact executable and argv
// under a per-plan timeout, bounds output, redacts failure, and post-verifies the
// returned observation.
func (e *Execution) Run(ctx context.Context) (*Observation, error) {
	if e == nil || e.plan == nil {
		return nil, ErrCustomOperationMismatch
	}
	// Pre-spawn cancellation: fail closed without starting the process.
	if err := ctx.Err(); err != nil {
		return nil, errorFromCtx(err)
	}
	// Recheck explicit local authorization immediately before execution. Denied or
	// revoked state (including absent authorization) must prevent starting.
	allowed := safelyAuthorize(e.authz, e.plan, e.operation)
	if !allowed {
		return nil, ErrCustomDenied
	}
	if e.runner == nil {
		return nil, ErrCustomExecution
	}
	timeout := time.Duration(e.plan.TimeoutMs()) * time.Millisecond
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	output, runErr := e.runner.Run(runCtx, e.plan, e.outputBound)
	// The process was terminated by the derived context (timeout or external
	// cancellation) before it could complete: report the stable code.
	if err := runCtx.Err(); err != nil {
		return nil, errorFromCtx(err)
	}
	if errors.Is(runErr, ErrCustomOutputOverflow) || len(output) > e.outputBound {
		return nil, ErrCustomOutputOverflow
	}
	if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
		return nil, errorFromCtx(runErr)
	}
	if runErr != nil {
		// Redact the OS/exec error (it may contain the executable path and argv).
		return nil, ErrCustomExecution
	}
	observation, err := e.verify([]byte(output))
	if err != nil {
		return nil, err
	}
	return observation, nil
}

// verify post-verifies the raw process output against the runtime contract: it
// must be a JSON object binding to the plan's provider/action/operation, carry a
// present, non-stale observedAt, and contain no sensitive public value. The
// returned observation's payload is detached and deeply frozen.
func (e *Execution) verify(raw []byte) (*Observation, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, ErrCustomMalformed
	}
	if err := validateJSON(raw); err != nil {
		return nil, ErrCustomMalformed
	}
	var public any
	if err := json.Unmarshal(raw, &public); err != nil {
		return nil, ErrCustomMalformed
	}
	if containsSensitive(public) {
		return nil, ErrCustomHostile
	}
	var head struct {
		ProviderID string         `json:"providerId"`
		Operation  string         `json:"operation"`
		ActionID   string         `json:"actionId"`
		ObservedAt string         `json:"observedAt"`
		Payload    map[string]any `json:"payload"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&head); err != nil {
		return nil, ErrCustomMalformed
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, ErrCustomMalformed
	}
	if head.ProviderID == "" || head.Operation == "" || head.ActionID == "" || head.Payload == nil {
		return nil, ErrCustomMalformed
	}
	if head.ProviderID != e.plan.ProviderID() {
		return nil, ErrCustomOperationMismatch
	}
	if Operation(head.Operation) != e.operation {
		return nil, ErrCustomOperationMismatch
	}
	if head.ActionID != e.plan.ActionID() {
		return nil, ErrCustomOperationMismatch
	}
	observedAt, err := parseObservedAt(head.ObservedAt)
	if err != nil {
		return nil, err
	}
	now := e.now()
	if now.Sub(observedAt) > e.staleWindow {
		return nil, ErrCustomStale
	}
	if observedAt.After(now.Add(e.staleWindow)) {
		return nil, ErrCustomHostile
	}
	return &Observation{
		providerID: head.ProviderID,
		operation:  e.operation,
		actionID:   head.ActionID,
		payload:    deepFreeze(head.Payload),
		observedAt: head.ObservedAt,
	}, nil
}

// --- observation ------------------------------------------------------------

// Observation is a provider-neutral, normalized, post-verified observation. Its
// Payload is detached and deeply frozen at creation, so it is immutable and every
// snapshot is independent (value-copy/deep-copy semantics).
type Observation struct {
	providerID string
	operation  Operation
	actionID   string
	payload    any
	observedAt string
}

// Provider returns the bound provider id.
func (o *Observation) Provider() string { return o.providerID }

// Operation returns the bound operation.
func (o *Observation) Operation() Operation { return o.operation }

// Action returns the bound action id.
func (o *Observation) Action() string { return o.actionID }

// ObservedWhen returns the observation's observedAt timestamp (as given).
func (o *Observation) ObservedWhen() string { return o.observedAt }

// PayloadSnapshot returns an independent, unwrapped deep copy of the payload.
// Mutating the returned map never affects the internal observation payload.
func (o *Observation) PayloadSnapshot() map[string]any {
	if o == nil {
		return nil
	}
	raw := thaw(o.payload)
	if m, ok := raw.(map[string]any); ok {
		return m
	}
	return nil
}

// PayloadFrozen reports whether the observation payload was deep-frozen at
// post-verification.
func (o *Observation) PayloadFrozen() bool {
	_, ok := o.payload.(frozenValue)
	return ok
}

// --- helpers ----------------------------------------------------------------

type frozenValue struct{ value any }

func deepFreeze(v any) any { return frozenValue{deepCopy(v)} }

func thaw(v any) any {
	if frozen, ok := v.(frozenValue); ok {
		return deepCopy(frozen.value)
	}
	return deepCopy(v)
}

func (o *Observation) unfreeze(v any) any {
	if f, ok := v.(frozenValue); ok {
		return f.value
	}
	return v
}

func deepCopy(v any) any {
	switch value := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(value))
		for k, elem := range value {
			out[k] = deepCopy(elem)
		}
		return out
	case []any:
		out := make([]any, len(value))
		for i, elem := range value {
			out[i] = deepCopy(elem)
		}
		return out
	default:
		return value
	}
}

func errorFromCtx(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrCustomTimeout
	}
	return ErrCustomCancelled
}

func validateJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	nodes := 0
	if err := consumeJSON(decoder, 0, &nodes); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrCustomMalformed
	}
	return nil
}

func consumeJSON(decoder *json.Decoder, depth int, nodes *int) error {
	if depth > 16 || *nodes >= 10_000 {
		return ErrCustomMalformed
	}
	*nodes++
	token, err := decoder.Token()
	if err != nil {
		return ErrCustomMalformed
	}
	delim, container := token.(json.Delim)
	if !container {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return ErrCustomMalformed
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrCustomMalformed
			}
			seen[key] = struct{}{}
			if err := consumeJSON(decoder, depth+1, nodes); err != nil {
				return err
			}
		}
		closeToken, err := decoder.Token()
		if err != nil || closeToken != json.Delim('}') {
			return ErrCustomMalformed
		}
	case '[':
		for decoder.More() {
			if err := consumeJSON(decoder, depth+1, nodes); err != nil {
				return err
			}
		}
		closeToken, err := decoder.Token()
		if err != nil || closeToken != json.Delim(']') {
			return ErrCustomMalformed
		}
	default:
		return ErrCustomMalformed
	}
	return nil
}

func parseObservedAt(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, ErrCustomMalformed
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Time{}, ErrCustomMalformed
}

// containsSensitive reports whether any string anywhere in the payload contains a
// credential, token, endpoint, or LAN address (hostile value).
func containsSensitive(v any) bool {
	switch value := v.(type) {
	case map[string]any:
		for _, elem := range value {
			if containsSensitive(elem) {
				return true
			}
		}
		return false
	case []any:
		for _, elem := range value {
			if containsSensitive(elem) {
				return true
			}
		}
		return false
	default:
		if s, ok := value.(string); ok {
			return sensitive.MatchString(s)
		}
		return false
	}
}

// boundedBuffer truncates combined output at a limit and flags overflow, so a
// process cannot flood the controller.
type boundedBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - b.Len()
	if len(p) > remaining {
		if remaining > 0 {
			_, _ = b.Buffer.Write(p[:remaining])
		}
		b.exceeded = true
		return len(p), ErrCustomOutputOverflow
	}
	return b.Buffer.Write(p)
}

// toEnv converts the plan's pure environment map to a child environment in the
// same form exec.Command expects. It is built solely from the plan and never
// reads ambient environment.
func toEnv(env map[string]string) []string {
	if len(env) == 0 {
		return []string{}
	}
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+env[key])
	}
	return out
}
