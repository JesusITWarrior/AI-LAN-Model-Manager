package command

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider/ollama"
)

func inferenceRequest() Request {
	model := "model-1"
	params, _ := json.Marshal(map[string]any{"providerId": "ollama-1", "modelId": model, "model": "qwen:latest", "requestId": "request-1", "maxRequestBytes": 524288, "maxResponseBytes": 262144, "messages": []any{map[string]any{"role": "user", "contentBase64": base64.StdEncoding.EncodeToString([]byte("hello"))}}, "temperatureMilli": nil, "maxTokens": nil})
	r := Request{RequestID: "request-1", JobID: "job-1", HostID: "host-1", Operation: "inference.chat", IdempotencyKey: "idem-1", Sequence: 1, Deadline: "2026-09-29T13:00:00.000Z", Capability: Capability{Operation: "model-inference", TargetKind: "model", TargetID: model, HostID: "host-1", ModelID: &model, ExpiresAt: "2026-09-29T13:01:00.000Z"}, Params: params}
	r.Capability.RequestDigest, _ = authorizationDigest(r)
	return r
}

func TestInferenceRejectsTargetMismatchBeforeChat(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			_, _ = w.Write([]byte(`{"models":[{"name":"qwen:latest","model":"qwen:latest","modified_at":"2026-09-29T10:00:00Z","size":1,"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","details":{"parent_model":"","format":"gguf","family":"qwen","families":["qwen"],"parameter_size":"1B","quantization_level":"Q4"}}]}`))
			return
		}
		calls++
		w.WriteHeader(500)
	}))
	defer server.Close()
	client, err := ollama.New(ollama.Config{ProviderID: "ollama-1", Endpoint: server.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry(time.Now)
	registry.RegisterOllama("ollama-1", client)
	params, _ := json.Marshal(map[string]any{"providerId": "ollama-1", "modelId": "wrong-model", "model": "qwen:latest", "requestId": "request-1", "maxRequestBytes": 524288, "maxResponseBytes": 262144, "messages": []any{map[string]any{"role": "user", "contentBase64": base64.StdEncoding.EncodeToString([]byte("hello"))}}, "temperatureMilli": nil, "maxTokens": nil})
	_, err = registry.Execute(context.Background(), "inference.chat", params)
	if !errors.Is(err, ErrRuntimeStateMismatch) || calls != 0 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestInferenceLeaseBlocksDrainAndCrashMarkerPreventsDuplicate(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{"name":"qwen:latest","model":"qwen:latest","modified_at":"2026-09-29T10:00:00Z","size":1,"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","details":{"parent_model":"","format":"gguf","family":"qwen","families":["qwen"],"parameter_size":"1B","quantization_level":"Q4"}}]}`))
		case "/api/ps":
			_, _ = w.Write([]byte(`{"models":[{"name":"qwen:latest","model":"qwen:latest","size":1,"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","details":{"parent_model":"","format":"gguf","family":"qwen","families":["qwen"],"parameter_size":"1B","quantization_level":"Q4"},"expires_at":"2026-09-29T13:00:00Z","size_vram":0,"context_length":8192}]}`))
		case "/api/chat":
			close(entered)
			<-release
			_, _ = w.Write([]byte(`{"model":"qwen:latest","created_at":"2026-09-29T10:00:00Z","message":{"role":"assistant","content":"ok"},"done":true,"done_reason":"stop","total_duration":1,"load_duration":1,"prompt_eval_count":1,"prompt_eval_duration":1,"eval_count":1,"eval_duration":1}`))
		}
	}))
	defer server.Close()
	client, _ := ollama.New(ollama.Config{ProviderID: "ollama-1", Endpoint: server.URL, Timeout: time.Second})
	registry := NewRegistry(time.Now)
	registry.RegisterOllama("ollama-1", client)
	params, _ := json.Marshal(map[string]any{"providerId": "ollama-1", "modelId": "ollama-b7942bc503dd509f3122012aa9ffeb24d61c6e7a981e77c59a2831f296dbb529", "model": "qwen:latest", "requestId": "request-1", "maxRequestBytes": 524288, "maxResponseBytes": 262144, "messages": []any{map[string]any{"role": "user", "contentBase64": base64.StdEncoding.EncodeToString([]byte("hello"))}}, "temperatureMilli": nil, "maxTokens": nil})
	done := make(chan error, 1)
	go func() { _, err := registry.Execute(context.Background(), "inference.chat", params); done <- err }()
	<-entered
	if _, err := registry.runDrain(context.Background(), "ollama-1", "qwen:latest"); !errors.Is(err, ErrServingActive) {
		t.Fatalf("drain err=%v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "replay.json")
	r := inferenceRequest()
	progress := uint8(1)
	running := Response{RequestID: r.RequestID, JobID: r.JobID, HostID: r.HostID, Sequence: r.Sequence, Status: "running", Progress: &progress, ObservedAt: "2026-09-29T10:00:00.000Z"}
	raw, _ := json.Marshal(map[string]entry{r.IdempotencyKey: {Digest: r.Capability.RequestDigest, Response: running}})
	if os.WriteFile(path, raw, 0o600) != nil {
		t.Fatal("write")
	}
	var calls atomic.Int32
	adapter := adapterFunc(func(context.Context, string, json.RawMessage) (any, error) { calls.Add(1); return nil, nil })
	executor, err := NewPersistent("host-1", adapter, func() time.Time { return time.Date(2026, 9, 29, 11, 0, 0, 0, time.UTC) }, path)
	if err != nil {
		t.Fatal(err)
	}
	response, err := executor.Execute(context.Background(), r)
	if err != nil || response.ErrorCode == nil || *response.ErrorCode != "INDETERMINATE" || calls.Load() != 0 {
		t.Fatalf("response=%#v err=%v calls=%d", response, err, calls.Load())
	}
}

type adapterFunc func(context.Context, string, json.RawMessage) (any, error)

func (f adapterFunc) Execute(ctx context.Context, op string, raw json.RawMessage) (any, error) {
	return f(ctx, op, raw)
}
