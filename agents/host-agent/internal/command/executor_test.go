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
func TestReplayStoreIsBoundedAndFailedPersistenceDoesNotCreateFalseReplay(t *testing.T) {
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
	if _, err := executor.Execute(context.Background(), req()); err == nil {
		t.Fatal("persistence unexpectedly succeeded")
	}
	if _, err := executor.Execute(context.Background(), req()); err == nil {
		t.Fatal("persistence unexpectedly succeeded")
	}
	if a.calls != 2 {
		t.Fatalf("failed result was falsely replayed: calls=%d", a.calls)
	}
}
