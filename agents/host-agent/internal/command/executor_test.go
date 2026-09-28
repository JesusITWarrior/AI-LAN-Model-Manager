package command

import (
	"context"
	"encoding/json"
	"errors"
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
	return Request{RequestID: "request-1", JobID: "job-1", HostID: "host-1", Operation: "probe", IdempotencyKey: "idem-1", Sequence: 1, Deadline: "2026-09-28T09:00:00.000Z", Params: json.RawMessage(`{}`)}
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
