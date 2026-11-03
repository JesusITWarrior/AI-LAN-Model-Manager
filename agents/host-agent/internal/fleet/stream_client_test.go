package fleet

import (
	bytespkg "bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/command"
)

type blockedReadStreamAdapter struct {
	entered  string
	calls    atomic.Int32
	releases atomic.Int32
	finished chan struct{}
}

func (*blockedReadStreamAdapter) Execute(context.Context, string, json.RawMessage) (any, error) {
	return nil, command.ErrCommand
}
func (a *blockedReadStreamAdapter) ExecuteStream(ctx context.Context, _ command.Request, _ command.StreamEmitter) error {
	a.calls.Add(1)
	defer func() { a.releases.Add(1); close(a.finished) }()
	if err := os.WriteFile(a.entered, []byte("entered"), 0600); err != nil {
		return err
	}
	<-ctx.Done()
	return ctx.Err()
}

type syntheticStreamAdapter struct {
	calls    atomic.Int32
	events   []json.RawMessage
	finished chan struct{}
}

func (*syntheticStreamAdapter) Execute(context.Context, string, json.RawMessage) (any, error) {
	return nil, command.ErrCommand
}
func (a *syntheticStreamAdapter) ExecuteStream(ctx context.Context, r command.Request, emit command.StreamEmitter) error {
	a.calls.Add(1)
	if a.finished != nil {
		defer func() { a.finished <- struct{}{} }()
	}
	for index, raw := range a.events {
		eventIndex := index
		var event map[string]any
		if json.Unmarshal(raw, &event) != nil {
			return command.ErrStream
		}
		event["hostId"], event["jobId"], event["requestId"], event["commandDigest"] = r.HostID, r.JobID, r.RequestID, r.Capability.RequestDigest
		event["index"] = eventIndex
		event["chunk"].(map[string]any)["id"] = r.RequestID
		out, _ := json.Marshal(event)
		if err := emit(ctx, out); err != nil {
			return err
		}
	}
	return nil
}

// Driven only by the TypeScript synthetic TLS fixture; never a model/provider.
func TestCrossLanguageStreamHelper(t *testing.T) {
	directory := os.Getenv("LANMM_STREAM_CERT_DIR")
	if directory == "" {
		t.Skip("cross-language helper")
	}
	mode := os.Getenv("LANMM_STREAM_MODE")
	c, err := NewHTTPSClient(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if mode == "close-read" {
		a := &blockedReadStreamAdapter{entered: filepath.Join(directory, "provider-read-entered"), finished: make(chan struct{})}
		executor := command.New("agent-1", a, time.Now)
		ended := make(chan error, 1)
		go func() { ended <- c.RunCommands(ctx, executor) }()
		select {
		case <-a.finished:
		case <-time.After(5 * time.Second):
			t.Fatal("provider read not cancelled by control poll")
		}
		time.Sleep(1400 * time.Millisecond)
		cancel()
		select {
		case <-ended:
		case <-time.After(time.Second):
			t.Fatal("runner blocked")
		}
		if a.calls.Load() != 1 || a.releases.Load() != 1 {
			t.Fatal("lease/reexecution count")
		}
		fmt.Println("STREAM_CLOSE_READ_CALLS=1 RELEASES=1")
		return
	}
	if mode == "runner" {
		raw, err := os.ReadFile("../command/testdata/stream-v1.json")
		if err != nil {
			t.Fatal(err)
		}
		var f struct {
			Events []json.RawMessage `json:"events"`
		}
		if json.Unmarshal(raw, &f) != nil {
			t.Fatal("fixture")
		}
		a := &syntheticStreamAdapter{events: f.Events, finished: make(chan struct{}, 1)}
		executor := command.New("agent-1", a, time.Now)
		ended := make(chan error, 1)
		go func() { ended <- c.RunCommands(ctx, executor) }()
		select {
		case <-a.finished:
		case <-ctx.Done():
			t.Fatal("runner blocked")
		}
		time.Sleep(1600 * time.Millisecond)
		cancel()
		select {
		case err := <-ended:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("runner cancellation blocked")
		}
		if a.calls.Load() != 1 {
			t.Fatal("runner reexecuted")
		}
		fmt.Println("STREAM_RUNNER_CALLS=1")
		return
	}
	if mode == "unauthorized" {
		c.hostID = "foreign-host"
	}
	if mode == "unauthorized" || mode == "revoked" || mode == "source-mismatch" {
		if c.SendStreamEvent(ctx, []byte(`{}`)) == nil {
			t.Fatal("unauthorized stream accepted")
		}
	}
	if mode == "source-mismatch" {
		fmt.Println("STREAM_REJECTED")
		return
	}
	work, err := c.pollCommandWork(ctx, 0)
	if mode == "unauthorized" || mode == "revoked" || mode == "source-mismatch" {
		if err == nil {
			t.Fatal("unauthorized poll accepted")
		}
		fmt.Println("STREAM_REJECTED")
		return
	}
	if err != nil || work.stream == nil {
		t.Fatalf("stream poll: %v", err)
	}
	r := *work.stream
	raw, err := os.ReadFile("../command/testdata/stream-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Events []json.RawMessage `json:"events"`
	}
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("fixture")
	}
	if mode == "budget" {
		events := make([]json.RawMessage, 130, 131)
		for i := range events {
			events[i] = fixture.Events[0]
		}
		fixture.Events = append(events, fixture.Events[1])
	}
	adapter := &syntheticStreamAdapter{events: fixture.Events}
	replayPath := filepath.Join(directory, "stream-replay.json")
	executor, err := command.NewPersistent(r.HostID, adapter, time.Now, replayPath)
	if err != nil {
		t.Fatal(err)
	}
	if mode == "normal" || mode == "slow" || mode == "budget" || mode == "cancel" || mode == "deadline" || mode == "restart" {
		runCtx, stop := context.WithCancel(ctx)
		defer stop()
		done := make(chan command.Response, 1)
		go func() {
			result, e := executor.ExecuteStream(runCtx, r, c.SendStreamEvent)
			if e != nil {
				done <- command.Response{}
				return
			}
			done <- result
		}()
		polls := 0
		for {
			select {
			case result := <-done:
				if result.Status == "" {
					t.Fatal("executor rejected")
				}
				if mode == "normal" || mode == "slow" || mode == "budget" {
					if result.Status != "succeeded" {
						t.Fatalf("outcome %s", result.Status)
					}
				} else if result.Status == "succeeded" {
					t.Fatal("false success")
				}
				sendErr := c.SendStreamResult(ctx, result, r.Capability.RequestDigest)
				if mode == "normal" || mode == "slow" || mode == "budget" {
					if sendErr != nil {
						t.Fatal("terminal result refused")
					}
					conflict := result
					conflict.Status = "failed"
					code := "STREAM_FAILED"
					conflict.ErrorCode = &code
					conflict.Progress = nil
					if c.SendStreamResult(ctx, conflict, r.Capability.RequestDigest) == nil {
						t.Fatal("conflicting terminal accepted")
					}
				}
				reloaded, loadErr := command.NewPersistent(r.HostID, adapter, time.Now, replayPath)
				if loadErr != nil {
					t.Fatal(loadErr)
				}
				replay, e := reloaded.ExecuteStream(ctx, r, func(context.Context, []byte) error { t.Error("regenerated output"); return nil })
				if (e == nil && replay.Status != result.Status) || adapter.calls.Load() != 1 || ((mode == "normal" || mode == "slow" || mode == "budget") && e != nil) {
					t.Fatal("replay")
				}
				fmt.Printf("STREAM_OUTCOME=%s POLLS=%d CALLS=%d\n", result.Status, polls, adapter.calls.Load())
				return
			case <-ctx.Done():
				t.Fatal("stream helper deadline")
			case <-time.After(20 * time.Millisecond):
				next, e := c.pollCommandWork(ctx, 0)
				if e != nil {
					continue
				}
				polls++
				if next.stream != nil {
					t.Fatal("stream requeued")
				}
				for _, id := range next.CancelledJobIDs {
					if id == r.JobID {
						stop()
					}
				}
			}
		}
	}
	var event map[string]any
	_ = json.Unmarshal(fixture.Events[0], &event)
	event["hostId"], event["jobId"], event["requestId"], event["commandDigest"] = r.HostID, r.JobID, r.RequestID, r.Capability.RequestDigest
	event["chunk"].(map[string]any)["id"] = r.RequestID
	if mode == "foreign" {
		event["requestId"] = "foreign"
	}
	if mode == "order" {
		event["index"] = 1
	}
	bytes, _ := json.Marshal(event)
	if mode == "duplicate" {
		bytes = []byte(strings.Replace(string(bytes), `"index":0`, `"index":0,"index":0`, 1))
	}
	if mode == "bom" {
		bytes = append([]byte{239, 187, 191}, bytes...)
	}
	if mode == "envelope-duplicate" || mode == "envelope-bom" || mode == "replay" {
		sequence, e := c.streamNext()
		if e != nil {
			t.Fatal(e)
		}
		env, e := c.agentEnvelope("agent.stream.event", sequence, struct {
			EventBase64 string `json:"eventBase64"`
		}{base64.StdEncoding.EncodeToString(bytes)})
		if e != nil {
			t.Fatal(e)
		}
		envelope, _ := json.Marshal(env)
		post := func(raw []byte) int {
			request, e := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/agent/v1/streams/event", bytespkg.NewReader(raw))
			if e != nil {
				t.Fatal(e)
			}
			request.Header.Set("Content-Type", "application/json")
			response, e := c.streamHTTP.Do(request)
			if e != nil {
				t.Fatal(e)
			}
			defer response.Body.Close()
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBody+1))
			return response.StatusCode
		}
		if mode == "envelope-duplicate" {
			envelope = []byte(strings.Replace(string(envelope), `"messageType":"agent.stream.event"`, `"messageType":"agent.stream.event","messageType":"agent.stream.event"`, 1))
		}
		if mode == "envelope-bom" {
			envelope = append([]byte{239, 187, 191}, envelope...)
		}
		if mode == "replay" {
			if post(envelope) != 200 {
				t.Fatal("first publication")
			}
			if post(envelope) == 200 {
				t.Fatal("accepted signed replay")
			}
			var terminal map[string]any
			_ = json.Unmarshal(fixture.Events[1], &terminal)
			terminal["hostId"], terminal["jobId"], terminal["requestId"], terminal["commandDigest"] = r.HostID, r.JobID, r.RequestID, r.Capability.RequestDigest
			terminal["chunk"].(map[string]any)["id"] = r.RequestID
			final, _ := json.Marshal(terminal)
			if c.SendStreamEvent(ctx, final) != nil {
				t.Fatal("replay poisoned stream validator")
			}
			result := command.Response{HostID: r.HostID, JobID: r.JobID, RequestID: r.RequestID, Sequence: r.Sequence, Status: "succeeded", ObservedAt: time.Now().UTC().Format("2006-01-02T15:04:05.000Z")}
			if c.SendStreamResult(ctx, result, r.Capability.RequestDigest) != nil {
				t.Fatal("replay terminal result")
			}
			fmt.Println("STREAM_REPLAY_REJECTED")
			return
		}
		if post(envelope) == 200 {
			t.Fatal("accepted lossy envelope parse")
		}
		fmt.Println("STREAM_REJECTED")
		return
	}
	if mode == "missing" || mode == "conflict" {
		status := "succeeded"
		if mode == "conflict" {
			status = "running"
		}
		result := command.Response{HostID: r.HostID, JobID: r.JobID, RequestID: r.RequestID, Sequence: r.Sequence, Status: status, ObservedAt: time.Now().UTC().Format("2006-01-02T15:04:05.000Z")}
		if c.SendStreamResult(ctx, result, r.Capability.RequestDigest) == nil {
			t.Fatal("accepted missing/conflicting terminal")
		}
	} else if c.SendStreamEvent(ctx, bytes) == nil {
		t.Fatal("accepted invalid raw event")
	}
	fmt.Println("STREAM_REJECTED")
}
