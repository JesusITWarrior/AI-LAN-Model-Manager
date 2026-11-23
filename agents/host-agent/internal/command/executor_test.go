package command

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type adapter struct {
	mu    sync.Mutex
	calls int
	fail  bool
}

func (a *adapter) Execute(_ context.Context, op string, p json.RawMessage) (any, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	if a.fail {
		return nil, errors.New("sensitive path")
	}
	return map[string]any{"operation": op}, nil
}
func req() Request {
	r := Request{RequestID: "request-1", JobID: "job-1", HostID: "host-1", Operation: "probe", IdempotencyKey: "idem-1", Sequence: 1, Deadline: "2026-09-28T09:00:00.000Z", Capability: Capability{Operation: "observe", TargetKind: "host", TargetID: "host-1", HostID: "host-1", ExpiresAt: "2026-09-28T09:00:00.000Z"}, Params: json.RawMessage(`{}`)}
	r.Capability.RequestDigest, _ = authorizationDigest(r)
	return r
}
func TestExecutesInjectedAdapterAndReplaysIdentical(t *testing.T) {
	a := &adapter{}
	e := New("host-1", a, func() time.Time { return time.Date(2026, 9, 28, 8, 0, 0, 0, time.UTC) })
	one, err := e.Execute(context.Background(), req())
	if err != nil {
		t.Fatal(err)
	}
	two, err := e.Execute(context.Background(), req())
	if err != nil || one.Status != "succeeded" || two.Status != "succeeded" || a.calls != 1 {
		t.Fatal(one, two, err, a.calls)
	}
}
func TestRejectsDivergenceUnknownExpiredAndRedactsFailure(t *testing.T) {
	a := &adapter{fail: true}
	e := New("host-1", a, func() time.Time { return time.Date(2026, 9, 28, 8, 0, 0, 0, time.UTC) })
	one, err := e.Execute(context.Background(), req())
	if err != nil || one.ErrorCode == nil || *one.ErrorCode != "ADAPTER_FAILED" {
		t.Fatal(one, err)
	}
	changed := req()
	changed.Params = json.RawMessage(`{"x":1}`)
	// Keeping the old capability digest proves exact-command binding rejects mutation.
	if _, err = e.Execute(context.Background(), changed); err == nil {
		t.Fatal("divergent replay")
	}
	unknown := req()
	unknown.IdempotencyKey = "other"
	unknown.Operation = "shell"
	if _, err = e.Execute(context.Background(), unknown); err == nil {
		t.Fatal("unknown")
	}
	expired := req()
	expired.IdempotencyKey = "expired"
	expired.Deadline = "2026-09-28T08:00:00.000Z"
	if _, err = e.Execute(context.Background(), expired); err == nil {
		t.Fatal("expired")
	}
}

type retryDrainAdapter struct{ calls int }

func (a *retryDrainAdapter) Execute(context.Context, string, json.RawMessage) (any, error) {
	a.calls++
	if a.calls == 1 {
		return nil, ErrServingActive
	}
	return map[string]any{"activeRequests": 0}, nil
}
func TestRunningDrainReplayReexecutesAfterRequestsComplete(t *testing.T) {
	a := &retryDrainAdapter{}
	e := New("host-1", a, func() time.Time { return time.Date(2026, 9, 28, 8, 0, 0, 0, time.UTC) })
	r := req()
	r.Operation = "drain"
	r.Capability.Operation = "model-drain"
	model := "model-1"
	r.Capability.TargetKind = "model"
	r.Capability.TargetID = model
	r.Capability.ModelID = &model
	r.Capability.RequestDigest, _ = authorizationDigest(r)
	first, err := e.Execute(context.Background(), r)
	if err != nil || first.Status != "running" {
		t.Fatalf("first = %#v, %v", first, err)
	}
	second, err := e.Execute(context.Background(), r)
	if err != nil || second.Status != "succeeded" || a.calls != 2 {
		t.Fatalf("second/calls = %#v/%d, %v", second, a.calls, err)
	}
}

func TestPersistentReplaySurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "command-replay.json")
	now := func() time.Time { return time.Date(2026, 9, 28, 8, 0, 0, 0, time.UTC) }
	firstAdapter := &adapter{}
	first, err := NewPersistent("host-1", firstAdapter, now, path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := first.Execute(context.Background(), req())
	if err != nil {
		t.Fatal(err)
	}
	secondAdapter := &adapter{}
	restarted, err := NewPersistent("host-1", secondAdapter, now, path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := restarted.Execute(context.Background(), req())
	if err != nil || got.Status != want.Status || secondAdapter.calls != 0 {
		t.Fatalf("replay = %#v, %v, calls=%d", got, err, secondAdapter.calls)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, %v", info, err)
	}
}

type contextAdapter struct{}

func (contextAdapter) Execute(ctx context.Context, _ string, _ json.RawMessage) (any, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func TestExecutionTimeoutAndCancellationAreReported(t *testing.T) {
	base := time.Date(2026, 9, 28, 8, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		cancel bool
		want   string
	}{{"timeout", false, "TIMEOUT"}, {"cancel", true, "CANCELLED"}} {
		t.Run(tc.name, func(t *testing.T) {
			r := req()
			r.IdempotencyKey = tc.name
			r.Deadline = base.Add(20 * time.Millisecond).Format("2006-01-02T15:04:05.000Z")
			r.Capability.ExpiresAt = base.Add(time.Minute).Format("2006-01-02T15:04:05.000Z")
			r.Capability.RequestDigest, _ = authorizationDigest(r)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			result, err := New("host-1", contextAdapter{}, func() time.Time { return base }).Execute(ctx, r)
			if err != nil || result.ErrorCode == nil || *result.ErrorCode != tc.want {
				t.Fatalf("result=%#v err=%v", result, err)
			}
		})
	}
}
func TestReplayStoreIsBoundedAndFailedPersistenceRetainsExecutedOutcome(t *testing.T) {
	path := filepath.Join(t.TempDir(), "too-many.json")
	entries := map[string]entry{}
	for i := 0; i < maxReplayEntries+1; i++ {
		entries[time.Unix(int64(i), 0).String()] = entry{}
	}
	raw, _ := json.Marshal(entries)
	if os.WriteFile(path, raw, 0o600) != nil {
		t.Fatal("write")
	}
	if _, err := NewPersistent("host-1", &adapter{}, nil, path); err == nil {
		t.Fatal("unbounded replay accepted")
	}
	bad := t.TempDir()
	a := &adapter{}
	executor := New("host-1", a, func() time.Time { return time.Date(2026, 9, 28, 8, 0, 0, 0, time.UTC) })
	executor.store = bad
	for range 2 {
		result, err := executor.Execute(context.Background(), req())
		if !errors.Is(err, ErrReplayPersistence) || result.Status != "succeeded" {
			t.Fatalf("known outcome/uncertainty lost: %#v, %v", result, err)
		}
	}
	if a.calls != 1 {
		t.Fatalf("executed outcome was repeated: calls=%d", a.calls)
	}
}

func TestLookupReplayStatesAndDetachedResponse(t *testing.T) {
	e := New("host-1", &adapter{}, func() time.Time { return time.Date(2026, 9, 28, 8, 0, 0, 0, time.UTC) })
	r := req()
	if got, err := e.LookupReplay(r); err != nil || got.State != ReplayMissing {
		t.Fatalf("missing = %#v, %v", got, err)
	}
	n := uint8(50)
	code := "x"
	nested := map[string]any{"items": []any{map[string]any{"n": &n}}}
	e.seen[r.IdempotencyKey] = entry{Digest: r.Capability.RequestDigest, Response: Response{Status: "running", Observation: nested, Progress: &n, ErrorCode: &code}}
	got, err := e.LookupReplay(r)
	if err != nil || got.State != ReplayRunning {
		t.Fatalf("running = %#v, %v", got, err)
	}
	got.Response.Progress = nil
	got.Response.ErrorCode = nil
	clonedPointer := got.Response.Observation.(map[string]any)["items"].([]any)[0].(map[string]any)["n"].(*uint8)
	*clonedPointer = 0
	if e.seen[r.IdempotencyKey].Response.Progress == nil || *e.seen[r.IdempotencyKey].Response.Progress != 50 {
		t.Fatal("lookup leaked pointer state")
	}
	changed := r
	changed.Params = json.RawMessage(`{"x":1}`)
	changed.Capability.RequestDigest, _ = authorizationDigest(changed)
	if got, err := e.LookupReplay(changed); err != nil || got.State != ReplayDivergent {
		t.Fatalf("divergent = %#v, %v", got, err)
	}
	e.persistenceErr = ErrReplayPersistence
	if got, err := e.LookupReplay(r); err != nil || got.State != ReplayUncertain || got.PersistenceErr != ErrReplayPersistence {
		t.Fatalf("uncertain = %#v, %v", got, err)
	}
}

func TestLookupReplayRejectsNilForeignMalformedAndForgedRequests(t *testing.T) {
	e := New("host-1", &adapter{}, func() time.Time { return time.Date(2026, 9, 28, 8, 0, 0, 0, time.UTC) })
	r := req()
	for name, bad := range map[string]Request{
		"foreign host": func() Request { x := r; x.HostID = "host-2"; return x }(),
		"forged digest": func() Request {
			x := r
			x.Capability.RequestDigest = "0000000000000000000000000000000000000000000000000000000000000000"
			return x
		}(),
		"malformed request id": func() Request { x := r; x.RequestID = "!"; return x }(),
		"malformed deadline":   func() Request { x := r; x.Deadline = "bad"; return x }(),
	} {
		if got, err := e.LookupReplay(bad); !errors.Is(err, ErrReplayLookup) || got != (ReplayLookup{}) {
			t.Fatalf("%s: got %#v err=%v", name, got, err)
		}
	}
	var nilExecutor *Executor
	if got, err := nilExecutor.LookupReplay(r); !errors.Is(err, ErrReplayLookup) || got != (ReplayLookup{}) {
		t.Fatalf("nil: got %#v err=%v", got, err)
	}
}

func TestLookupReplayPreservesPersistentFileAndTerminalState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "command-replay.json")
	now := func() time.Time { return time.Date(2026, 9, 28, 8, 0, 0, 0, time.UTC) }
	a := &adapter{}
	e, err := NewPersistent("host-1", a, now, path)
	if err != nil {
		t.Fatal(err)
	}
	r := req()
	if _, err = e.Execute(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	infoBefore, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.LookupReplay(r)
	if err != nil || got.State != ReplayTerminal || a.calls != 1 {
		t.Fatalf("lookup=%#v err=%v calls=%d", got, err, a.calls)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	infoAfter, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) || infoBefore.Size() != infoAfter.Size() || !infoBefore.ModTime().Equal(infoAfter.ModTime()) || infoBefore.Mode() != infoAfter.Mode() {
		t.Fatalf("lookup changed replay file: bytes=%v/%v before=%v after=%v", len(before), len(after), infoBefore, infoAfter)
	}
}

func TestConcurrentLookupAndExecuteDoNotDuplicate(t *testing.T) {
	a := &adapter{}
	e := New("host-1", a, func() time.Time { return time.Date(2026, 9, 28, 8, 0, 0, 0, time.UTC) })
	r := req()
	var wg sync.WaitGroup
	wg.Add(2)
	var executeErr, lookupErr error
	var lookup ReplayLookup
	go func() { defer wg.Done(); _, executeErr = e.Execute(context.Background(), r) }()
	go func() { defer wg.Done(); lookup, lookupErr = e.LookupReplay(r) }()
	wg.Wait()
	if executeErr != nil || lookupErr != nil || (lookup.State != ReplayMissing && lookup.State != ReplayTerminal) || a.calls != 1 {
		t.Fatalf("execute=%v lookup=%#v/%v calls=%d", executeErr, lookup, lookupErr, a.calls)
	}
}
