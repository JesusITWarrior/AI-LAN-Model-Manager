package fleet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/command"
)

func lifetimeRunner(t *testing.T, executor *command.Executor) *CommandRunner {
	t.Helper()
	r, err := NewCommandRunner(executor)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCommandRunnerHandoffOrdinaryFailureACKOnlyRelease(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "retry-ACK", true: "expired-400-held"}[expired], func(t *testing.T) {
			ctxA, cancelA := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancelA()
			first := runnerRequest("first", time.Now().Add(time.Minute))
			if expired {
				first = runnerRequest("first", time.Now().Add(100*time.Millisecond))
			}
			second := runnerRequest("second", time.Now().Add(time.Minute))
			adapter := &ordinaryFailureAdapter{}
			r := lifetimeRunner(t, command.New("host-1", adapter, time.Now))
			var original command.Response
			postsA := 0
			a := signedCommandClient(t, nil, func(n int) *command.Request {
				if n == 1 {
					return &first
				}
				return &second
			}, func(v command.Response) int { original = v; postsA++; cancelA(); return 400 })
			if err := r.Run(ctxA, a); err != nil {
				t.Fatal(err)
			}
			if err := r.Quiesce(context.Background()); err != nil {
				t.Fatal(err)
			}
			if r.pending == nil || !reflect.DeepEqual(*r.pending, original) || adapter.calls != 1 {
				t.Fatal("A lost full pending response")
			}
			ctxB, cancelB := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancelB()
			postsB := 0
			b := signedCommandClient(t, nil, func(int) *command.Request { return &second }, func(v command.Response) int {
				postsB++
				if v.JobID == first.JobID {
					if !reflect.DeepEqual(v, original) || adapter.calls != 1 {
						t.Fatal("handoff changed response or executed before ACK")
					}
					if expired {
						if postsB == 2 {
							cancelB()
						}
						return 400
					}
					if postsB == 1 {
						return 503
					}
					return 200
				}
				cancelB()
				return 200
			})
			if err := r.Run(ctxB, b); err != nil {
				t.Fatal(err)
			}
			if err := r.Quiesce(context.Background()); err != nil {
				t.Fatal(err)
			}
			if postsA != 1 || postsB < 2 {
				t.Fatal("missing generation-specific retries")
			}
			if expired {
				if adapter.calls != 1 || r.pending == nil || !reflect.DeepEqual(*r.pending, original) || !r.reportedExpiredPending {
					t.Fatal("expired result released or rewritten")
				}
			} else if adapter.calls != 2 || r.pending != nil {
				t.Fatal("successful exact ACK did not release and admit next request")
			}
		})
	}
}

func TestCommandRunnerHandoffRetainsUncertaintyFullResponse(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[fail], func(t *testing.T) {
			first := runnerRequest("uncertain", time.Now().Add(time.Minute))
			later := runnerRequest("later", time.Now().Add(time.Minute))
			adapter := &persistenceFailureAdapter{path: filepath.Join(t.TempDir(), "replay.json"), fail: fail}
			executor, err := command.NewPersistent("host-1", adapter, time.Now, adapter.path)
			if err != nil {
				t.Fatal(err)
			}
			r := lifetimeRunner(t, executor)
			for generation := 0; generation < 2; generation++ {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				client := signedCommandClient(t, nil, func(n int) *command.Request {
					if n == 3 {
						cancel()
					}
					if generation == 0 && n == 1 {
						return &first
					}
					return &later
				}, func(command.Response) int { t.Fatal("uncertainty posted"); return 200 })
				if err := r.Run(ctx, client); err != nil {
					t.Fatal(err)
				}
				cancel()
				if err := r.Quiesce(context.Background()); err != nil {
					t.Fatal(err)
				}
				if !r.persistenceUncertain || r.pending == nil || r.done == nil || adapter.calls != 1 || r.executor != executor {
					t.Fatal("uncertainty owner changed")
				}
				retained, err := executor.Execute(context.Background(), first)
				if !errors.Is(err, command.ErrReplayPersistence) || !reflect.DeepEqual(*r.pending, retained) {
					t.Fatal("full original response not retained")
				}
			}
		})
	}
}

type lateRunnerAdapter struct {
	entered chan context.Context
	release chan struct{}
	calls   atomic.Int32
}

func (a *lateRunnerAdapter) Execute(ctx context.Context, _ string, _ json.RawMessage) (any, error) {
	a.calls.Add(1)
	a.entered <- ctx
	<-a.release
	return map[string]any{"complete": "original observation", "nested": map[string]any{"count": float64(7)}}, nil
}

func TestCommandRunnerQuiesceCapturesCompletionAfterCancelAndWaits(t *testing.T) {
	adapter := &lateRunnerAdapter{entered: make(chan context.Context, 1), release: make(chan struct{})}
	executor := command.New("host-1", adapter, time.Now)
	r := lifetimeRunner(t, executor)
	first := runnerRequest("late", time.Now().Add(time.Minute))
	ctx, cancel := context.WithCancel(context.Background())
	client := signedCommandClient(t, nil, func(int) *command.Request { return &first }, func(command.Response) int { t.Fatal("unexpected result before completion"); return 200 })
	runDone := make(chan error, 1)
	go func() { runDone <- r.Run(ctx, client) }()
	executionCtx := <-adapter.entered
	cancel()
	select {
	case <-runDone:
	case <-time.After(3 * time.Second):
		t.Fatal("Run failed to exit")
	}
	if executionCtx.Err() == nil {
		t.Fatal("Run exit failed to cancel active adapter")
	}
	if r.pending != nil || r.done == nil {
		t.Fatal("in-flight barrier lost")
	}
	quiesced := make(chan error, 1)
	go func() { quiesced <- r.Quiesce(context.Background()) }()
	select {
	case <-quiesced:
		t.Fatal("quiescence abandoned noncooperative adapter")
	case <-time.After(20 * time.Millisecond):
	}
	close(adapter.release)
	select {
	case err := <-quiesced:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("late completion lost")
	}
	retained, err := executor.Execute(context.Background(), first)
	if err != nil || r.pending == nil || !reflect.DeepEqual(*r.pending, retained) || adapter.calls.Load() != 1 {
		t.Fatal("quiescence altered full completion")
	}
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	b := signedCommandClient(t, nil, func(int) *command.Request { return nil }, func(v command.Response) int {
		if !reflect.DeepEqual(v, retained) {
			t.Fatal("B changed completion")
		}
		cancelB()
		return 400
	})
	if err := r.Run(ctxB, b); err != nil {
		t.Fatal(err)
	}
	if adapter.calls.Load() != 1 {
		t.Fatal("completion reexecuted")
	}
}

func TestCommandRunnerQuiesceRootCancelKeepsBarrier(t *testing.T) {
	adapter := &lateRunnerAdapter{entered: make(chan context.Context, 1), release: make(chan struct{})}
	r := lifetimeRunner(t, command.New("host-1", adapter, time.Now))
	first := runnerRequest("blocked", time.Now().Add(time.Minute))
	ctx, cancel := context.WithCancel(context.Background())
	client := signedCommandClient(t, nil, func(int) *command.Request { return &first }, func(command.Response) int { return 200 })
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx, client) }()
	<-adapter.entered
	cancel()
	<-done
	root, cancelRoot := context.WithCancel(context.Background())
	cancelRoot()
	if err := r.Quiesce(root); !errors.Is(err, context.Canceled) {
		t.Fatalf("root cancellation: %v", err)
	}
	if r.done == nil || r.pending != nil || adapter.calls.Load() != 1 {
		t.Fatal("cancelled quiescence cleared owner")
	}
	close(adapter.release)
	if err := r.Quiesce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.pending == nil {
		t.Fatal("completion lost after cancelled quiescence")
	}
}

func TestNewCommandRunnerRejectsInvalidConfiguration(t *testing.T) {
	if _, err := NewCommandRunner(nil); err == nil {
		t.Fatal("nil executor accepted")
	}
	if _, err := NewCommandRunner(command.New("host-1", &ordinaryFailureAdapter{}, time.Now), nil, nil); err == nil {
		t.Fatal("multiple relays accepted")
	}
}

type lateStreamRunnerAdapter struct {
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int32
	events  []json.RawMessage
}

func (*lateStreamRunnerAdapter) Execute(context.Context, string, json.RawMessage) (any, error) {
	return nil, command.ErrCommand
}
func (a *lateStreamRunnerAdapter) ExecuteStream(_ context.Context, _ command.Request, emit command.StreamEmitter) error {
	a.calls.Add(1)
	// Intentionally noncooperative synthetic adapter: cancellation alone cannot
	// prove it has stopped using the captured generation's stream client.
	if err := emit(context.Background(), a.events[0]); err != nil {
		return err
	}
	close(a.entered)
	<-a.release
	return emit(context.Background(), a.events[1])
}

func TestCommandRunnerStreamHandoffJoinsOldClientBeforeNewSequenceLane(t *testing.T) {
	raw, err := os.ReadFile("../command/testdata/stream-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Request command.Request   `json:"request"`
		Events  []json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	request := fixture.Request
	request.HostID = "host-1"
	request.Capability.HostID = "host-1"
	request.Deadline = time.Now().Add(time.Minute).UTC().Format("2006-01-02T15:04:05.000Z")
	request.Capability.ExpiresAt = request.Deadline
	wire, _ := json.Marshal(request)
	var bound map[string]any
	if err := json.Unmarshal(wire, &bound); err != nil {
		t.Fatal(err)
	}
	delete(bound["capability"].(map[string]any), "requestDigest")
	wire, _ = json.Marshal(bound)
	sum := sha256.Sum256(wire)
	request.Capability.RequestDigest = hex.EncodeToString(sum[:])
	for i, eventRaw := range fixture.Events {
		var event map[string]any
		if err := json.Unmarshal(eventRaw, &event); err != nil {
			t.Fatal(err)
		}
		event["hostId"] = request.HostID
		event["commandDigest"] = request.Capability.RequestDigest
		fixture.Events[i], _ = json.Marshal(event)
	}
	adapter := &lateStreamRunnerAdapter{entered: make(chan struct{}), release: make(chan struct{}), events: fixture.Events}
	executor := command.New("host-1", adapter, time.Now)
	r := lifetimeRunner(t, executor)
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	a := signedCommandClient(t, nil, func(int) *command.Request { return &request }, func(command.Response) int { t.Fatal("ordinary stream result"); return 400 })
	var oldPosts atomic.Int32
	a.streamHTTP = &http.Client{Transport: commandRoundTrip(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/agent/v1/streams/event" {
			t.Error("unexpected old-generation stream path")
		}
		oldPosts.Add(1)
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
	})}
	exited := make(chan error, 1)
	go func() { exited <- r.Run(ctxA, a) }()
	select {
	case <-adapter.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("stream not entered")
	}
	cancelA()
	<-exited
	quiesced := make(chan error, 1)
	go func() { quiesced <- r.Quiesce(context.Background()) }()
	select {
	case <-quiesced:
		t.Fatal("old stream client abandoned")
	case <-time.After(20 * time.Millisecond):
	}
	if oldPosts.Load() != 1 {
		t.Fatal("unexpected event count")
	}
	close(adapter.release)
	select {
	case err := <-quiesced:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stream quiescence did not join")
	}
	if oldPosts.Load() != 2 || a.streamSequence != 2 || r.pending == nil || !r.activeStream || r.activeDigest != request.Capability.RequestDigest {
		t.Fatal("old stream activity/binding lost")
	}
	retained, err := executor.ExecuteStream(context.Background(), request, func(context.Context, []byte) error { t.Fatal("stream replayed"); return nil })
	if err != nil || !reflect.DeepEqual(*r.pending, retained) {
		t.Fatal("full stream outcome changed")
	}
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	// Only now may another generation load sequence state or rotate identity.
	b := signedCommandClient(t, nil, func(int) *command.Request { return nil }, func(command.Response) int { t.Fatal("ordinary result"); return 400 })
	var newPosts int
	b.streamHTTP = &http.Client{Transport: commandRoundTrip(func(req *http.Request) (*http.Response, error) {
		newPosts++
		if req.URL.Path != "/agent/v1/streams/result" {
			t.Error("event restarted in B")
		}
		var envelope struct {
			Payload struct {
				CommandDigest string           `json:"commandDigest"`
				Result        command.Response `json:"result"`
			} `json:"payload"`
		}
		if json.NewDecoder(req.Body).Decode(&envelope) != nil || envelope.Payload.CommandDigest != request.Capability.RequestDigest || !reflect.DeepEqual(envelope.Payload.Result, retained) {
			t.Error("stream binding/outcome changed")
		}
		cancelB()
		return &http.Response{StatusCode: 503, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"ok":false}`))}, nil
	})}
	if err := r.Run(ctxB, b); err != nil {
		t.Fatal(err)
	}
	if newPosts != 1 || oldPosts.Load() != 2 || a.streamSequence != 2 || b.streamSequence != 1 || adapter.calls.Load() != 1 || r.pending != nil {
		t.Fatal("stream one-shot contract changed or old client used after quiescence")
	}
}

func TestCommandRunnerEveryCancellationExitRetainsAndCancelsActive(t *testing.T) {
	for _, branch := range []string{"result-send", "poll-error", "poll-retry-wait", "loop-wait"} {
		t.Run(branch, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			executionCtx, cancelExecution := context.WithCancel(context.Background())
			defer cancelExecution()
			r := lifetimeRunner(t, command.New("host-1", &ordinaryFailureAdapter{}, time.Now))
			r.cancelActive = cancelExecution
			r.done = make(chan commandCompletion, 1)
			r.activeJob = "retained"
			original := command.Response{JobID: "retained", Status: "failed", Observation: map[string]any{"nested": []any{"unchanged"}}}
			c := signedCommandClient(t, nil, func(int) *command.Request {
				if branch == "loop-wait" {
					cancel()
				}
				return nil
			}, func(command.Response) int { cancel(); return 503 })
			if branch == "result-send" {
				r.pending = &original
			}
			if branch == "poll-error" || branch == "poll-retry-wait" {
				c.http = &http.Client{Transport: commandRoundTrip(func(*http.Request) (*http.Response, error) {
					if branch == "poll-error" {
						cancel()
					} else {
						time.AfterFunc(20*time.Millisecond, cancel)
					}
					return nil, errors.New("synthetic transport unavailable")
				})}
			}
			if err := r.Run(ctx, c); err != nil {
				t.Fatal(err)
			}
			if executionCtx.Err() == nil || r.done == nil || r.activeJob != "retained" {
				t.Fatal("exit abandoned active owner")
			}
			if r.pending == nil {
				r.done <- commandCompletion{response: original}
			}
			if err := r.Quiesce(context.Background()); err != nil {
				t.Fatal(err)
			}
			if r.pending == nil || !reflect.DeepEqual(*r.pending, original) {
				t.Fatal("exit/quiescence lost completion")
			}
		})
	}
}

func TestCommandRunnerLateUncertainCompletionRetainsFullOutcomeAndReportsExpiry(t *testing.T) {
	for _, status := range []string{"succeeded", "failed"} {
		t.Run(status, func(t *testing.T) {
			adapter := &ordinaryFailureAdapter{}
			r := lifetimeRunner(t, command.New("host-1", adapter, time.Now))
			code := "ADAPTER_FAILED"
			original := command.Response{RequestID: "original-request", JobID: "original-job", HostID: "host-1", Sequence: 7, Status: status, ObservedAt: "2026-11-04T12:00:00.000Z", Observation: map[string]any{"nested": map[string]any{"retained": []any{"complete", float64(7)}}}}
			if status == "failed" {
				original.ErrorCode = &code
			}
			r.activeJob = original.JobID
			r.activeDeadline = time.Now().Add(-time.Minute)
			r.done = make(chan commandCompletion, 1)
			// Model a completed executor's opaque uncertainty metadata, independent of
			// whether its replay failure was before or after publication. Real pre/post
			// publication injection and poison retention are tested in package command;
			// the runner must not reinterpret either provenance or the full outcome.
			r.done <- commandCompletion{response: original, persistenceUncertain: true}
			if err := r.Quiesce(context.Background()); err != nil {
				t.Fatal(err)
			}
			for generation := 0; generation < 3; generation++ {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				request := runnerRequest("never-execute", time.Now().Add(time.Minute))
				client := signedCommandClient(t, nil, func(int) *command.Request { cancel(); return &request }, func(command.Response) int { t.Fatal("uncertain response sent"); return 200 })
				if err := r.Run(ctx, client); err != nil {
					t.Fatal(err)
				}
				cancel()
				if err := r.Quiesce(context.Background()); err != nil {
					t.Fatal(err)
				}
				if r.pending == nil || !reflect.DeepEqual(*r.pending, original) || !r.persistenceUncertain || !r.reportedExpiredPending || r.done == nil || adapter.calls != 0 {
					t.Fatal("uncertainty, expiry or full response lost across generation")
				}
			}
		})
	}
}
