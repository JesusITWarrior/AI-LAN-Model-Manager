package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider/lmstudio"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider/ollama"
)

const (
	testCanonical = "acme/bert:latest"
	testDigest    = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

var nowConstant = time.Date(2026, 9, 26, 22, 1, 2, 987654321, time.FixedZone("test", -5*60*60))

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

type fakeClock struct{ value time.Time }

func (c fakeClock) Now() time.Time { return c.value }

func newOllamaClient(t *testing.T, doer provider.HTTPDoer) *ollama.Client {
	t.Helper()
	client, err := ollama.NewWithDependencies(
		ollama.Config{ProviderID: "ollama-main", Endpoint: "http://127.0.0.1:11434/"},
		doer,
		fakeClock{nowConstant},
	)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func ok200(body any) *http.Response {
	var reader io.Reader
	switch value := body.(type) {
	case string:
		reader = strings.NewReader(value)
	case io.Reader:
		reader = value
	default:
		panic("unsupported response body")
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(reader)}
}

func newLMStudioClient(t *testing.T, doer provider.HTTPDoer) *lmstudio.Client {
	t.Helper()
	client, err := lmstudio.NewWithDependencies(
		lmstudio.Config{ProviderID: "lmstudio-main", Endpoint: "http://127.0.0.1:1234/"},
		doer,
		fakeClock{nowConstant},
	)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func lmNativeState(instances ...string) *http.Response {
	loaded := make([]string, 0, len(instances))
	for _, id := range instances {
		loaded = append(loaded, fmt.Sprintf(`{"id":%q,"config":{"context_length":4096}}`, id))
	}
	body := `{"models":[{"type":"llm","publisher":"acme","key":"acme/bert","display_name":"Bert","quantization":null,"size_bytes":1,"params_string":null,"loaded_instances":[` + strings.Join(loaded, ",") + `],"max_context_length":8192,"format":"gguf"}]}`
	return ok200(strings.NewReader(body))
}

func psEmpty() string { return `{"models":[]}` }

func psLoaded() string {
	return `{"models":[{"name":"` + testCanonical + `","model":"` + testCanonical +
		`","size":456,"digest":"` + testDigest +
		`","details":{"parent_model":"","format":"gguf","family":"qwen2","families":["qwen2"],"parameter_size":"7B","quantization_level":"Q4"},"expires_at":"2026-09-27T03:01:02Z","size_vram":321,"context_length":8192}]}`
}

func successBody() string {
	return `{"model":"` + testCanonical + `","created_at":"2026-09-27T03:01:02.123Z","response":"","done":true,"done_reason":"load","context":[0,1,2147483647],"total_duration":1,"load_duration":0,"prompt_eval_count":0,"prompt_eval_duration":0,"eval_count":0,"eval_duration":0}`
}

func loadParams(providerID, name, keepAlive string) json.RawMessage {
	p, _ := json.Marshal(map[string]any{"providerId": providerID, "model": name, "keepAlive": keepAlive})
	return p
}

func modelParamsOnly(providerID, name string) json.RawMessage {
	p, _ := json.Marshal(map[string]any{"providerId": providerID, "model": name})
	return p
}

// TestLoadPostVerificationPass requires the runtime observation to reflect the
// mutation, then marks the model loaded.
func TestLoadPostVerificationPass(t *testing.T) {
	reg := NewRegistry(func() time.Time { return nowConstant })
	gets := 0
	reg.RegisterOllama("ollama-main", newOllamaClient(t, doerFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet {
			gets++
			if gets == 1 {
				return ok200(psEmpty()), nil
			}
			return ok200(psLoaded()), nil
		}
		return ok200(strings.NewReader(successBody())), nil
	})))
	result, err := reg.Execute(context.Background(), "load", loadParams("ollama-main", testCanonical, "30s"))
	if err != nil {
		t.Fatal(err)
	}
	lr, ok := result.(provider.LifecycleResult)
	if !ok {
		t.Fatalf("result is not LifecycleResult: %#v", result)
	}
	if !lr.Changed || lr.RuntimeState != provider.RuntimeLoaded || lr.Action != provider.ActionLoad {
		t.Fatalf("unexpected result: %#v", lr)
	}
	if reg.isLoaded("ollama-main", testCanonical) != true {
		t.Fatal("registry view not marked loaded")
	}
}

// TestLoadPostVerificationFailure rejects a mutation whose post-run runtime
// observation does not reflect success.
func TestLoadPostVerificationFailure(t *testing.T) {
	reg := NewRegistry(func() time.Time { return nowConstant })
	reg.RegisterOllama("ollama-main", newOllamaClient(t, doerFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet {
			return ok200(psEmpty()), nil // model not present after the mutation
		}
		return ok200(strings.NewReader(successBody())), nil
	})))
	if _, err := reg.Execute(context.Background(), "load", loadParams("ollama-main", testCanonical, "30s")); !errors.Is(err, ErrRuntimeStateMismatch) {
		t.Fatalf("error = %v, want ErrRuntimeStateMismatch", err)
	}
	if reg.isLoaded("ollama-main", testCanonical) {
		t.Fatal("registry view must not be marked loaded")
	}
}

// TestLoadIdempotentNoWhenAlreadyLoaded requires no mutation once the runtime
// already reports the model present.
func TestLoadIdempotentNoWhenAlreadyLoaded(t *testing.T) {
	reg := NewRegistry(func() time.Time { return nowConstant })
	reg.RegisterOllama("ollama-main", newOllamaClient(t, doerFunc(func(r *http.Request) (*http.Response, error) {
		return ok200(psLoaded()), nil
	})))
	first, err := reg.Execute(context.Background(), "load", loadParams("ollama-main", testCanonical, "30s"))
	if err != nil {
		t.Fatal(err)
	}
	if lr := first.(provider.LifecycleResult); lr.Changed {
		t.Fatalf("expected no-op, changed=%v", lr.Changed)
	}
	// active request is available because the model is loaded.
	if _, err := reg.Acquire(context.Background(), "ollama-main", testCanonical); err != nil {
		t.Fatalf("acquire after load = %v", err)
	}
}

// TestUnloadRefusesWhileServingActive refuses unload when requests are outstanding.
func TestUnloadRefusesWhileServingActive(t *testing.T) {
	reg := NewRegistry(func() time.Time { return nowConstant })
	reg.RegisterOllama("ollama-main", newOllamaClient(t, doerFunc(func(r *http.Request) (*http.Response, error) {
		return ok200(psLoaded()), nil
	})))
	if _, err := reg.Execute(context.Background(), "load", loadParams("ollama-main", testCanonical, "30s")); err != nil {
		t.Fatal(err)
	}
	handle, err := reg.Acquire(context.Background(), "ollama-main", testCanonical)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Complete(context.Background(), handle)
	if _, err := reg.Execute(context.Background(), "unload", modelParamsOnly("ollama-main", testCanonical)); !errors.Is(err, ErrServingActive) {
		t.Fatalf("error = %v, want ErrServingActive", err)
	}
}

// TestDrainThenUnload requires the caller to drain before unloading.
func TestDrainThenUnload(t *testing.T) {
	reg := NewRegistry(func() time.Time { return nowConstant })
	loaded := true
	reg.RegisterOllama("ollama-main", newOllamaClient(t, doerFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet {
			if loaded {
				return ok200(psLoaded()), nil
			}
			return ok200(psEmpty()), nil
		}
		loaded = false
		return ok200(strings.NewReader(successBody())), nil
	})))
	if _, err := reg.Execute(context.Background(), "load", loadParams("ollama-main", testCanonical, "30s")); err != nil {
		t.Fatal(err)
	}
	handle, err := reg.Acquire(context.Background(), "ollama-main", testCanonical)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Execute(context.Background(), "set-options", loadParams("ollama-main", testCanonical, "30s")); !errors.Is(err, ErrModelNotIdle) {
		t.Fatalf("set-options while active = %v, want ErrModelNotIdle", err)
	}
	if _, err := reg.Execute(context.Background(), "drain", modelParamsOnly("ollama-main", testCanonical)); !errors.Is(err, ErrServingActive) {
		t.Fatalf("drain with active request = %v, want ErrServingActive", err)
	}
	if _, err := reg.Acquire(context.Background(), "ollama-main", testCanonical); !errors.Is(err, ErrServingActive) {
		t.Fatalf("acquire after admission stop = %v, want ErrServingActive", err)
	}
	if err := reg.Complete(context.Background(), handle); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Execute(context.Background(), "drain", modelParamsOnly("ollama-main", testCanonical)); err != nil {
		t.Fatalf("drain after completion = %v", err)
	}
	if _, err := reg.Execute(context.Background(), "unload", modelParamsOnly("ollama-main", testCanonical)); err != nil {
		t.Fatalf("unload after drain = %v", err)
	}
	if reg.isLoaded("ollama-main", testCanonical) {
		t.Fatal("registry view must not be marked loaded after unload")
	}
}

// TestDrainRefusesWhenNotLoaded requires the model to be loaded before draining.
func TestDrainRefusesWhenNotLoaded(t *testing.T) {
	reg := NewRegistry(func() time.Time { return nowConstant })
	reg.RegisterOllama("ollama-main", newOllamaClient(t, doerFunc(func(r *http.Request) (*http.Response, error) {
		return ok200(psEmpty()), nil
	})))
	if _, err := reg.Execute(context.Background(), "drain", modelParamsOnly("ollama-main", testCanonical)); !errors.Is(err, ErrModelNotLoaded) {
		t.Fatalf("error = %v, want ErrModelNotLoaded", err)
	}
}

// TestSetOptionsRequiresIdle requires the model to be idle before changing options.
func TestSetOptionsRequiresIdle(t *testing.T) {
	reg := NewRegistry(func() time.Time { return nowConstant })
	reg.RegisterOllama("ollama-main", newOllamaClient(t, doerFunc(func(r *http.Request) (*http.Response, error) {
		return ok200(psLoaded()), nil
	})))
	if _, err := reg.Execute(context.Background(), "load", loadParams("ollama-main", testCanonical, "30s")); err != nil {
		t.Fatal(err)
	}
	handle, err := reg.Acquire(context.Background(), "ollama-main", testCanonical)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Complete(context.Background(), handle)
	if _, err := reg.Execute(context.Background(), "set-options", loadParams("ollama-main", testCanonical, "30s")); !errors.Is(err, ErrModelNotIdle) {
		t.Fatalf("error = %v, want ErrModelNotIdle", err)
	}
}

// TestInstallAndRemoveAreGuarded requires the registry to reject install/remove.
func TestInstallAndRemoveAreGuarded(t *testing.T) {
	reg := NewRegistry(func() time.Time { return nowConstant })
	reg.RegisterOllama("ollama-main", newOllamaClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return ok200(psLoaded()), nil
	})))
	if _, err := reg.Execute(context.Background(), "install", loadParams("ollama-main", testCanonical, "30s")); !errors.Is(err, ErrGuardedOperation) {
		t.Fatalf("install = %v, want ErrGuardedOperation", err)
	}
	if _, err := reg.Execute(context.Background(), "remove-managed-artifact", loadParams("ollama-main", testCanonical, "")); !errors.Is(err, ErrGuardedOperation) {
		t.Fatalf("remove = %v, want ErrGuardedOperation", err)
	}
}

// TestNoPostMutationObservationTrustedForLmStudio requires the registry to trust a
// provider convergence result when the provider exposes no running-model view.
func TestNoPostMutationObservationTrustedForLmStudio(t *testing.T) {
	reg := NewRegistry(func() time.Time { return nowConstant })
	reg.RegisterLMStudio("lmstudio-main", newLMStudioClient(t, doerFunc(func(r *http.Request) (*http.Response, error) {
		return lmNativeState("instance-1"), nil
	})))
	// no Acquire: the model has no outstanding requests.
	if _, err := reg.Execute(context.Background(), "load", loadParams("lmstudio-main", "acme/bert", "0")); err != nil {
		t.Fatalf("lmstudio load = %v", err)
	}
}

// TestSynchronousNoOpLoadRequiresStateObservation trusts convergence for LM Studio.
func TestSynchronousNoOpLoadRequiresStateObservation(t *testing.T) {
	reg := NewRegistry(func() time.Time { return nowConstant })
	reg.RegisterLMStudio("lmstudio-main", newLMStudioClient(t, doerFunc(func(r *http.Request) (*http.Response, error) {
		return lmNativeState("instance-1"), nil
	})))
	if _, err := reg.Execute(context.Background(), "load", loadParams("lmstudio-main", "acme/bert", "0")); err != nil {
		t.Fatalf("no-op load = %v", err)
	}
}

// TestCancelsBeforeIo requires cancellation to be reported without any provider call.
func TestCancelsBeforeIo(t *testing.T) {
	reg := NewRegistry(func() time.Time { return nowConstant })
	reg.RegisterOllama("ollama-main", newOllamaClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("called with canceled context")
		return nil, nil
	})))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reg.Execute(ctx, "load", loadParams("ollama-main", testCanonical, "30s")); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

// TestTransportFailureRedactsSecrets requires transport errors to reach the
// controller without leaking response bodies.
func TestTransportFailureRedactsSecrets(t *testing.T) {
	secret := "do-not-leak"
	reg := NewRegistry(func() time.Time { return nowConstant })
	reg.RegisterOllama("ollama-main", newOllamaClient(t, doerFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet {
			return ok200(psEmpty()), nil
		}
		return &http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(strings.NewReader(secret))}, nil
	})))
	_, err := reg.Execute(context.Background(), "load", loadParams("ollama-main", testCanonical, "30s"))
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("error = %v, want redacted transport error", err)
	}
}

// TestBlocksShellUrlCommandPath requires the registry to refuse the forbidden
// network/path surfaces even when a provider is registered.
func TestBlocksShellUrlCommandPath(t *testing.T) {
	reg := NewRegistry(func() time.Time { return nowConstant })
	reg.RegisterOllama("ollama-main", newOllamaClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("provider must not be called")
		return nil, nil
	})))
	forbidden := []string{
		`{"providerId":"ollama-main","model":"acme/bert:latest","url":"http://evil"}`,
		`{"providerId":"ollama-main","model":"acme/bert:latest","endpoint":"http://evil"}`,
		`{"providerId":"ollama-main","model":"acme/bert:latest","address":"10.0.0.1:8080"}`,
		`{"providerId":"ollama-main","model":"acme/bert:latest","command":"uname"}`,
		`{"providerId":"ollama-main","model":"acme/bert:latest","shell":"bash"}`,
		`{"providerId":"ollama-main","model":"acme/bert:latest","path":"/etc/passwd"}`,
	}
	for _, raw := range forbidden {
		if _, err := reg.Execute(context.Background(), "load", json.RawMessage(raw)); err == nil {
			t.Fatalf("load with %q must be rejected", raw)
		}
	}
}

// TestRejectsUnknownProvider requires NoProvider when no adapter is registered.
func TestRejectsUnknownProvider(t *testing.T) {
	reg := NewRegistry(func() time.Time { return nowConstant })
	if _, err := reg.Execute(context.Background(), "load", loadParams("other", testCanonical, "30s")); !errors.Is(err, NoProvider) {
		t.Fatalf("error = %v, want NoProvider", err)
	}
}

// TestRejectsInvalidModelName requires invalid model names to be rejected.
func TestRejectsInvalidModelName(t *testing.T) {
	reg := NewRegistry(func() time.Time { return nowConstant })
	reg.RegisterOllama("ollama-main", newOllamaClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("provider must not be called")
		return nil, nil
	})))
	if _, err := reg.Execute(context.Background(), "load", loadParams("ollama-main", "../etc/passwd", "30s")); err == nil {
		t.Fatal("invalid model name must be rejected")
	}
}

// TestContextLengthOutOfRange requires an out-of-range context length to be rejected.
func TestContextLengthOutOfRange(t *testing.T) {
	reg := NewRegistry(func() time.Time { return nowConstant })
	reg.RegisterOllama("ollama-main", newOllamaClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("provider must not be called")
		return nil, nil
	})))
	p, _ := json.Marshal(map[string]any{"providerId": "ollama-main", "model": testCanonical, "contextLength": provider.MaximumContextLength + 1})
	if _, err := reg.Execute(context.Background(), "load", p); err == nil {
		t.Fatal("out-of-range context length must be rejected")
	}
}

func TestObservationOperationsReachProviderRouting(t *testing.T) {
	reg := NewRegistry(nil)
	params, _ := json.Marshal(map[string]any{"providerId": "ollama-main"})
	for _, operation := range []string{"probe", "inventory", "estimate"} {
		if _, err := reg.Execute(context.Background(), operation, params); !errors.Is(err, NoProvider) {
			t.Fatalf("%s error = %v, want NoProvider", operation, err)
		}
	}
}

func TestUnloadStopsAdmissionBeforeProviderMutation(t *testing.T) {
	reg := NewRegistry(func() time.Time { return nowConstant })
	postStarted, release := make(chan struct{}), make(chan struct{})
	loaded := true
	reg.RegisterOllama("ollama-main", newOllamaClient(t, doerFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet {
			if loaded {
				return ok200(psLoaded()), nil
			}
			return ok200(psEmpty()), nil
		}
		close(postStarted)
		<-release
		loaded = false
		return ok200(successBody()), nil
	})))
	if _, err := reg.Execute(context.Background(), "load", loadParams("ollama-main", testCanonical, "30s")); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := reg.Execute(context.Background(), "unload", modelParamsOnly("ollama-main", testCanonical))
		done <- err
	}()
	<-postStarted
	if _, err := reg.Acquire(context.Background(), "ollama-main", testCanonical); !errors.Is(err, ErrServingActive) {
		t.Fatalf("Acquire during unload = %v, want ErrServingActive", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
