package command

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider/ollama"
)

func streamFixture(t *testing.T) (Request, []json.RawMessage) {
	t.Helper()
	raw, err := os.ReadFile("testdata/stream-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Request json.RawMessage   `json:"request"`
		Events  []json.RawMessage `json:"events"`
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("fixture")
	}
	r, err := ParseStreamCommand(f.Request)
	if err != nil {
		t.Fatal(err)
	}
	return r, f.Events
}
func compactEvent(t *testing.T, raw []byte) []byte {
	t.Helper()
	var v any
	if json.Unmarshal(raw, &v) != nil {
		t.Fatal("json")
	}
	out, _ := json.Marshal(v)
	return out
}
func TestStreamCrossLanguageContract(t *testing.T) {
	r, events := streamFixture(t)
	v, err := NewStreamValidator(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if _, err = v.Accept(e); err != nil {
			t.Fatal(err)
		}
	}
	if v.Finish() != nil {
		t.Fatal("terminal")
	}
	if _, err = v.Accept(events[1]); err == nil {
		t.Fatal("duplicate terminal")
	}
	if _, err = New(r.HostID, adapterFunc(func(context.Context, string, json.RawMessage) (any, error) {
		t.Fatal("buffered executed")
		return nil, nil
	}), streamClock).Execute(context.Background(), r); err == nil {
		t.Fatal("buffered accepted")
	}
	for _, field := range []string{"upstreamFrameBytes", "maxEventBytes", "maxTotalEventBytes", "maxEvents"} {
		var params map[string]any
		_ = json.Unmarshal(r.Params, &params)
		params[field] = params[field].(float64) - 1
		changed := r
		changed.Params, _ = json.Marshal(params)
		raw, _ := json.Marshal(changed)
		if _, err = ParseStreamCommand(raw); err == nil {
			t.Fatal("digest tamper", field)
		}
	}
	for _, field := range []string{"providerId", "modelId", "model", "requestId", "maxRequestBytes", "maxResponseBytes", "messages"} {
		var p map[string]any
		_ = json.Unmarshal(r.Params, &p)
		c := p["chat"].(map[string]any)
		switch c[field].(type) {
		case float64:
			c[field] = c[field].(float64) - 1
		default:
			c[field] = "tampered"
		}
		changed := r
		changed.Params, _ = json.Marshal(p)
		raw, _ := json.Marshal(changed)
		if _, err = ParseStreamCommand(raw); err == nil {
			t.Fatal("chat tamper", field)
		}
	}
	raw, _ := json.Marshal(r)
	dup := strings.Replace(string(raw), `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1)
	if _, err = ParseStreamCommand([]byte(dup)); err == nil {
		t.Fatal("duplicate param")
	}
}
func TestStreamRejectsMalformedAndForeignEvents(t *testing.T) {
	r, events := streamFixture(t)
	base := string(compactEvent(t, events[0]))
	mutations := []string{
		strings.Replace(base, `"index":0`, `"index":1`, 1), strings.Replace(base, `"hostId":"synthetic-host"`, `"hostId":"foreign"`, 1),
		strings.Replace(base, `"jobId":"synthetic-job"`, `"jobId":"foreign"`, 1), strings.Replace(base, `"requestId":"synthetic-request"`, `"requestId":"foreign"`, 1),
		strings.Replace(base, r.Capability.RequestDigest, strings.Repeat("0", 64), 1), strings.Replace(base, `"model":"synthetic-model:fixture"`, `"model":"foreign"`, 1),
		strings.Replace(base, `"id":"synthetic-request"`, `"id":"foreign"`, 1), strings.Replace(base, `"content":`, `"thinking":"private","content":`, 1),
		strings.Replace(base, `"index":0`, `"index":0,"index":0`, 1), strings.Replace(base, `"chunk":{`, `"chunk":{"usage":null,`, 1),
		strings.Replace(base, "synthetic δ", `\ud800`, 1), strings.Replace(base, `"schemaVersion":1`, `"schemaVersion":1,"unknown":0`, 1),
	}
	for i, raw := range mutations {
		v, _ := NewStreamValidator(r)
		if _, err := v.Accept([]byte(raw)); err == nil {
			t.Fatalf("accepted mutation %d", i)
		}
		if v.Finish() == nil {
			t.Fatal("invalid finish")
		}
	}
	v, _ := NewStreamValidator(r)
	_, _ = v.Accept(events[0])
	if _, err := v.Accept(events[0]); err == nil {
		t.Fatal("duplicate delta")
	}
	if _, err := v.Accept(events[1]); err == nil {
		t.Fatal("poisoned validator recovered")
	}
	for _, usage := range []ollama.ChatUsage{{PromptTokens: maxSafeInteger, CompletionTokens: 1, TotalTokens: maxSafeInteger + 1}, {PromptTokens: 1, CompletionTokens: 2, TotalTokens: 4}} {
		var terminal StreamEvent
		_ = json.Unmarshal(events[1], &terminal)
		terminal.Chunk.Usage = &usage
		raw, _ := json.Marshal(terminal)
		v, _ := NewStreamValidator(r)
		_, _ = v.Accept(events[0])
		if _, err := v.Accept(raw); err == nil {
			t.Fatal("overflow/usage")
		}
	}
}
func TestStreamBoundsAndEOF(t *testing.T) {
	r, events := streamFixture(t)
	for _, mode := range []string{"frame", "total", "count"} {
		var p StreamParams
		_ = json.Unmarshal(r.Params, &p)
		p.MaxEventBytes = 1024
		p.MaxTotalEventBytes = 1024
		if mode == "count" {
			p.MaxTotalEventBytes = 4096
			p.MaxEvents = 1
		}
		changed := r
		changed.Params, _ = json.Marshal(p)
		changed.Capability.RequestDigest, _ = authorizationDigest(changed)
		v, err := NewStreamValidator(changed)
		if err != nil {
			t.Fatal(err)
		}
		var e StreamEvent
		_ = json.Unmarshal(events[0], &e)
		e.CommandDigest = changed.Capability.RequestDigest
		if mode == "frame" {
			e.Chunk.Choices[0].Delta.Content = strings.Repeat("x", 1024)
		}
		if mode == "total" {
			e.Chunk.Choices[0].Delta.Content = strings.Repeat("x", 400)
		}
		raw, _ := json.Marshal(e)
		_, err = v.Accept(raw)
		if mode == "frame" {
			if err == nil {
				t.Fatal("frame bound")
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			_ = json.Unmarshal(events[1], &e)
			e.CommandDigest = changed.Capability.RequestDigest
			raw, _ = json.Marshal(e)
			if _, err = v.Accept(raw); err == nil {
				t.Fatal("total/count bound")
			}
		}
		if v.Finish() == nil {
			t.Fatal("EOF succeeded")
		}
	}
	v, _ := NewStreamValidator(r)
	if v.Finish() == nil {
		t.Fatal("empty EOF")
	}
}
func streamClock() time.Time { return time.Date(2026, 11, 3, 21, 0, 0, 0, time.UTC) }

type streamAdapter struct {
	run   func(context.Context, ollama.ChatRequest, func(context.Context, ollama.ChatChunk) error) error
	calls atomic.Int32
}

func (a *streamAdapter) Load(context.Context, provider.LoadModelCommand) (provider.LifecycleResult, error) {
	return provider.LifecycleResult{}, nil
}
func (a *streamAdapter) Unload(context.Context, provider.UnloadModelCommand) (provider.LifecycleResult, error) {
	return provider.LifecycleResult{}, nil
}
func (a *streamAdapter) Probe(context.Context) (provider.ProviderProbe, error) {
	return provider.ProviderProbe{}, nil
}
func (a *streamAdapter) ListInstalled(context.Context) ([]provider.InstalledModel, error) {
	return []provider.InstalledModel{{ProviderID: "synthetic-provider", ModelID: "synthetic-model-id", CanonicalName: "synthetic-model:fixture"}}, nil
}
func (a *streamAdapter) ListRunning(context.Context) ([]provider.RunningModel, error) {
	return []provider.RunningModel{{ProviderID: "synthetic-provider", CanonicalName: "synthetic-model:fixture"}}, nil
}
func (a *streamAdapter) ChatStream(ctx context.Context, r ollama.ChatRequest, emit func(context.Context, ollama.ChatChunk) error) error {
	a.calls.Add(1)
	return a.run(ctx, r, emit)
}
func streamRegistry(a *streamAdapter) *Registry {
	r := NewRegistry(streamClock)
	r.clients["synthetic-provider"] = a
	return r
}
func fixtureChunks(t *testing.T) []ollama.ChatChunk {
	_, events := streamFixture(t)
	out := []ollama.ChatChunk{}
	for _, raw := range events {
		var e StreamEvent
		_ = json.Unmarshal(raw, &e)
		out = append(out, *e.Chunk)
	}
	return out
}
func TestStreamPublicationCancellationDrainAndRelease(t *testing.T) {
	r, _ := streamFixture(t)
	chunks := fixtureChunks(t)
	entered := make(chan struct{})
	a := &streamAdapter{run: func(ctx context.Context, in ollama.ChatRequest, emit func(context.Context, ollama.ChatChunk) error) error {
		if in.RequestID != r.RequestID || in.Model != "synthetic-model:fixture" || in.MaxResponseBytes != 262144 || len(in.Messages) != 1 || in.Messages[0].Content != "synthetic" {
			t.Error("request binding")
		}
		return emit(ctx, chunks[0])
	}}
	registry := streamRegistry(a)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- registry.ExecuteStream(ctx, r, func(ctx context.Context, _ []byte) error { close(entered); <-ctx.Done(); return ctx.Err() })
	}()
	<-entered
	if _, err := registry.runDrain(context.Background(), "synthetic-provider", "synthetic-model:fixture"); !errors.Is(err, ErrServingActive) {
		t.Fatal("drain released before publisher outcome", err)
	}
	// A concurrent observation of disappearance must not erase the active handle.
	registry.syncRunning(nil)
	registry.mu.Lock()
	active := len(registry.active[modelKey("synthetic-provider", "synthetic-model:fixture")])
	registry.mu.Unlock()
	if active != 1 {
		t.Fatal("observation erased lease")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked emitter ignored cancellation")
	}
	registry.mu.Lock()
	active = len(registry.active[modelKey("synthetic-provider", "synthetic-model:fixture")])
	registry.mu.Unlock()
	if active != 0 {
		t.Fatal("lease leaked")
	}
}
func TestStreamTerminalOwnershipAndReplay(t *testing.T) {
	request, _ := streamFixture(t)
	chunks := fixtureChunks(t)
	for _, mode := range []string{"success", "missing-terminal", "provider-error-after-terminal", "publish-error", "cancel-at-terminal"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a := &streamAdapter{run: func(ctx context.Context, _ ollama.ChatRequest, emit func(context.Context, ollama.ChatChunk) error) error {
				if err := emit(ctx, chunks[0]); err != nil {
					return err
				}
				if mode == "missing-terminal" {
					return nil
				}
				if err := emit(ctx, chunks[1]); err != nil {
					return err
				}
				if mode == "provider-error-after-terminal" {
					return ErrStream
				}
				return nil
			}}
			registry := streamRegistry(a)
			executor, err := NewPersistent(request.HostID, registry, streamClock, filepath.Join(t.TempDir(), "replay.json"))
			if err != nil {
				t.Fatal(err)
			}
			kinds := []string{}
			response, err := executor.ExecuteStream(ctx, request, func(_ context.Context, raw []byte) error {
				var e StreamEvent
				_ = json.Unmarshal(raw, &e)
				kinds = append(kinds, e.Kind)
				if mode == "publish-error" {
					return errors.New("synthetic publish failure")
				}
				if mode == "cancel-at-terminal" && e.Kind == "succeeded" {
					cancel()
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			want := "failed"
			if mode == "success" || mode == "cancel-at-terminal" {
				want = "succeeded"
			}
			if response.Status != want {
				t.Fatalf("status %s want %s", response.Status, want)
			}
			terminalCount := 0
			for _, k := range kinds {
				if k != "chunk" {
					terminalCount++
				}
			}
			if mode == "publish-error" {
				if terminalCount != 0 {
					t.Fatal("second terminal after publish failure")
				}
			} else if terminalCount != 1 {
				t.Fatal("terminal ownership", kinds)
			}
			reloaded, err := NewPersistent(request.HostID, registry, streamClock, executor.store)
			if err != nil {
				t.Fatal(err)
			}
			replay, err := reloaded.ExecuteStream(context.Background(), request, func(context.Context, []byte) error { t.Fatal("replayed output"); return nil })
			if err != nil || replay.Status != want || a.calls.Load() != 1 {
				t.Fatal("replay regenerated", replay, err)
			}
		})
	}
	// An interrupted durable marker is indeterminate, never a stream restart.
	path := filepath.Join(t.TempDir(), "interrupted.json")
	raw, _ := json.Marshal(map[string]entry{request.IdempotencyKey: {Digest: request.Capability.RequestDigest, Response: Response{Status: "running"}}})
	_ = os.WriteFile(path, raw, 0600)
	a := &streamAdapter{run: func(context.Context, ollama.ChatRequest, func(context.Context, ollama.ChatChunk) error) error {
		t.Fatal("restarted interrupted stream")
		return nil
	}}
	executor, err := NewPersistent(request.HostID, streamRegistry(a), streamClock, path)
	if err != nil {
		t.Fatal(err)
	}
	response, err := executor.ExecuteStream(context.Background(), request, func(context.Context, []byte) error { t.Fatal("emitted interrupted replay"); return nil })
	if err != nil || response.ErrorCode == nil || *response.ErrorCode != "INDETERMINATE" {
		t.Fatal(response, err)
	}
}

type streamDoer func(*http.Request) (*http.Response, error)

func (d streamDoer) Do(r *http.Request) (*http.Response, error) { return d(r) }
func TestStreamAcceptedProviderCleanEOFIntegration(t *testing.T) {
	for _, mode := range []string{"valid", "trailing-delta", "missing-done", "overflow"} {
		t.Run(mode, func(t *testing.T) {
			terminal := `{"model":"synthetic-model:fixture","created_at":"2026-11-03T20:00:00Z","message":{"role":"assistant","content":"synthetic final"},"done":true,"done_reason":"stop","total_duration":1,"load_duration":1,"prompt_eval_count":1,"prompt_eval_duration":1,"eval_count":2,"eval_duration":1}`
			delta := `{"model":"synthetic-model:fixture","created_at":"2026-11-03T20:00:00Z","message":{"role":"assistant","content":"synthetic delta"},"done":false}`
			body := delta + "\n" + terminal + "\n"
			if mode == "trailing-delta" {
				body += delta + "\n"
			}
			if mode == "missing-done" {
				body = delta + "\n"
			}
			if mode == "overflow" {
				body = strings.Replace(body, `"prompt_eval_count":1`, `"prompt_eval_count":9007199254740991`, 1)
			}
			var chatCalls atomic.Int32
			client, err := ollama.NewWithDependencies(ollama.Config{ProviderID: "synthetic-provider", Endpoint: "http://127.0.0.1:11434", Timeout: time.Second}, streamDoer(func(req *http.Request) (*http.Response, error) {
				content := ""
				media := "application/json"
				switch req.URL.Path {
				case "/api/tags":
					content = `{"models":[{"name":"synthetic-model:fixture","model":"synthetic-model:fixture","modified_at":"2026-11-03T20:00:00Z","size":1,"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","details":{"parent_model":"","format":"gguf","family":"synthetic","families":["synthetic"],"parameter_size":"1B","quantization_level":"synthetic"}}]}`
				case "/api/ps":
					content = `{"models":[{"name":"synthetic-model:fixture","model":"synthetic-model:fixture","size":1,"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","details":{"parent_model":"","format":"gguf","family":"synthetic","families":["synthetic"],"parameter_size":"1B","quantization_level":"synthetic"},"expires_at":"2026-11-03T22:00:00Z","size_vram":0,"context_length":1}]}`
				case "/api/chat":
					chatCalls.Add(1)
					raw, _ := io.ReadAll(req.Body)
					var request map[string]any
					_ = json.Unmarshal(raw, &request)
					if request["stream"] != true || request["model"] != "synthetic-model:fixture" {
						t.Error("not accepted ChatStream request")
					}
					content = body
					media = "application/x-ndjson"
				default:
					t.Errorf("unexpected provider path %s", req.URL.Path)
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{media}}, Body: io.NopCloser(strings.NewReader(content))}, nil
			}), provider.SystemClock{})
			if err != nil {
				t.Fatal(err)
			}
			// Use the accepted inventory's computed identity, not a guessed model ID.
			models, err := client.ListInstalled(context.Background())
			if err != nil || len(models) != 1 {
				t.Fatal(models, err)
			}
			request, _ := streamFixture(t)
			var params StreamParams
			_ = json.Unmarshal(request.Params, &params)
			var c map[string]any
			_ = json.Unmarshal(params.Chat, &c)
			c["modelId"] = models[0].ModelID
			params.Chat, _ = json.Marshal(c)
			request.Params, _ = json.Marshal(params)
			modelID := models[0].ModelID
			request.Capability.ModelID = &modelID
			request.Capability.TargetID = modelID
			request.Capability.RequestDigest, _ = authorizationDigest(request)
			registry := NewRegistry(streamClock)
			registry.RegisterOllama("synthetic-provider", client)
			executor := New(request.HostID, registry, streamClock)
			validator, err := NewStreamValidator(request)
			if err != nil {
				t.Fatal(err)
			}
			kinds := []string{}
			response, err := executor.ExecuteStream(context.Background(), request, func(_ context.Context, raw []byte) error {
				e, err := validator.Accept(raw)
				if err == nil {
					kinds = append(kinds, e.Kind)
				}
				return err
			})
			if err != nil || chatCalls.Load() != 1 || validator.Finish() != nil {
				t.Fatal(response, err, kinds)
			}
			want := "failed"
			if mode == "valid" {
				want = "succeeded"
			}
			if response.Status != want || len(kinds) != 2 || kinds[1] != want {
				t.Fatal(response, kinds)
			}
			if _, err := registry.runDrain(context.Background(), "synthetic-provider", "synthetic-model:fixture"); err != nil {
				t.Fatal("lease after provider outcome", err)
			}
		})
	}
}

func TestStreamSharedRawRejectionVectors(t *testing.T) {
	r, events := streamFixture(t)
	raw, err := os.ReadFile("testdata/stream-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Invalid []struct {
			Name  string `json:"name"`
			Prior []int  `json:"prior"`
			Raw   string `json:"raw"`
		} `json:"invalidEvents"`
	}
	if json.Unmarshal(raw, &f) != nil || len(f.Invalid) == 0 {
		t.Fatal("vectors")
	}
	for _, c := range f.Invalid {
		t.Run(c.Name, func(t *testing.T) {
			v, _ := NewStreamValidator(r)
			for _, index := range c.Prior {
				if _, err := v.Accept(events[index]); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := v.Accept([]byte(c.Raw)); err == nil {
				t.Fatal("accepted invalid vector")
			}
			if v.Finish() == nil {
				t.Fatal("poisoned terminal")
			}
		})
	}
}

func TestStreamAdmissionRejectionIsFinalNotRequeued(t *testing.T) {
	request, _ := streamFixture(t)
	a := &streamAdapter{run: func(context.Context, ollama.ChatRequest, func(context.Context, ollama.ChatChunk) error) error {
		t.Fatal("draining provider executed")
		return nil
	}}
	registry := streamRegistry(a)
	registry.markRunning("synthetic-provider", "synthetic-model:fixture", true)
	if _, err := registry.runDrain(context.Background(), "synthetic-provider", "synthetic-model:fixture"); err != nil {
		t.Fatal(err)
	}
	executor := New(request.HostID, registry, streamClock)
	emit := func(context.Context, []byte) error { t.Fatal("unadmitted event"); return nil }
	response, err := executor.ExecuteStream(context.Background(), request, emit)
	if err != nil || response.Status != "failed" {
		t.Fatal("admission requeued", response, err)
	}
	registry.mu.Lock()
	delete(registry.draining, modelKey("synthetic-provider", "synthetic-model:fixture"))
	registry.mu.Unlock()
	response, err = executor.ExecuteStream(context.Background(), request, emit)
	if err != nil || response.Status != "failed" || a.calls.Load() != 0 {
		t.Fatal("replay restarted rejected stream", response, err)
	}
}
func TestStreamProviderCancellationTerminal(t *testing.T) {
	request, _ := streamFixture(t)
	a := &streamAdapter{run: func(context.Context, ollama.ChatRequest, func(context.Context, ollama.ChatChunk) error) error {
		return context.Canceled
	}}
	executor := New(request.HostID, streamRegistry(a), streamClock)
	kinds := []string{}
	response, err := executor.ExecuteStream(context.Background(), request, func(_ context.Context, raw []byte) error {
		var e StreamEvent
		_ = json.Unmarshal(raw, &e)
		kinds = append(kinds, e.Kind)
		return nil
	})
	if err != nil || response.Status != "cancelled" || len(kinds) != 1 || kinds[0] != "cancelled" {
		t.Fatal(response, err, kinds)
	}
}

func TestStreamProviderDeadlineUnblocksPublisher(t *testing.T) {
	request, _ := streamFixture(t)
	chunks := fixtureChunks(t)
	a := &streamAdapter{run: func(ctx context.Context, _ ollama.ChatRequest, emit func(context.Context, ollama.ChatChunk) error) error {
		providerCtx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
		defer cancel()
		return emit(providerCtx, chunks[0])
	}}
	registry := streamRegistry(a)
	done := make(chan error, 1)
	go func() {
		done <- registry.ExecuteStream(context.Background(), request, func(ctx context.Context, _ []byte) error { <-ctx.Done(); return ctx.Err() })
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("provider deadline not propagated into publisher")
	}
	if _, err := registry.runDrain(context.Background(), "synthetic-provider", "synthetic-model:fixture"); err != nil {
		t.Fatal("deadline leaked lease", err)
	}
}

func TestStreamSharedRawCommandRejectionVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/stream-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Invalid []struct {
			Name string `json:"name"`
			Raw  string `json:"raw"`
		} `json:"invalidCommands"`
	}
	if json.Unmarshal(raw, &f) != nil || len(f.Invalid) == 0 {
		t.Fatal("command vectors")
	}
	for _, c := range f.Invalid {
		t.Run(c.Name, func(t *testing.T) {
			if _, err := ParseStreamCommand([]byte(c.Raw)); err == nil {
				t.Fatal("accepted raw command")
			}
		})
	}
}
func mutateStreamRequest(r *Request) {
	for i := range r.Params {
		r.Params[i] = ' '
	}
	*r.Capability.ModelID = "foreign"
}
func TestStreamValidatorSnapshotIsolation(t *testing.T) {
	request, events := streamFixture(t)
	validator, err := NewStreamValidator(request)
	if err != nil {
		t.Fatal(err)
	}
	mutateStreamRequest(&request)
	if *validator.request.Capability.ModelID != "synthetic-model-id" || !json.Valid(validator.request.Params) {
		t.Fatal("validator retained caller references")
	}
	for _, raw := range events {
		if _, err := validator.Accept(raw); err != nil {
			t.Fatal(err)
		}
	}
	if validator.Finish() != nil {
		t.Fatal("snapshot stream invalid")
	}
}

// Runs mutations synchronously only after executor entry has taken ownership;
// no test relies on racy mutation while the entry snapshot is being copied.
type snapshotStreamAdapter struct {
	*Registry
	original *Request
}

func (a snapshotStreamAdapter) ExecuteStream(ctx context.Context, r Request, emit StreamEmitter) error {
	mutateStreamRequest(a.original)
	return a.Registry.ExecuteStream(ctx, r, emit)
}
func TestStreamExecutorSnapshotIsolation(t *testing.T) {
	request, _ := streamFixture(t)
	chunks := fixtureChunks(t)
	a := &streamAdapter{run: func(ctx context.Context, _ ollama.ChatRequest, emit func(context.Context, ollama.ChatChunk) error) error {
		for _, c := range chunks {
			if err := emit(ctx, c); err != nil {
				return err
			}
		}
		return nil
	}}
	registry := streamRegistry(a)
	executor := New(request.HostID, snapshotStreamAdapter{registry, &request}, streamClock)
	kinds := []string{}
	response, err := executor.ExecuteStream(context.Background(), request, func(_ context.Context, raw []byte) error {
		var e StreamEvent
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		kinds = append(kinds, e.Kind)
		return nil
	})
	if err != nil || response.Status != "succeeded" || len(kinds) != 2 || kinds[1] != "succeeded" {
		t.Fatal("caller mutation affected execution", response, err, kinds)
	}
}
