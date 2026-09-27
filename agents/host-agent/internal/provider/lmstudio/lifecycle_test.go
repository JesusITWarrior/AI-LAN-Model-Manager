package lmstudio

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
)

const lifecycleModelName = "acme/bert"

func lmNativeState(instances ...string) string {
	return lmNativeStateWithContext(4096, instances...)
}

func lmNativeStateWithContext(contextLength uint64, instances ...string) string {
	loaded := make([]string, 0, len(instances))
	for _, id := range instances {
		loaded = append(loaded, fmt.Sprintf(`{"id":%q,"config":{"context_length":%d}}`, id, contextLength))
	}
	return `{"models":[{"type":"llm","publisher":"acme","key":"acme/bert","display_name":"Bert","quantization":null,"size_bytes":1,"params_string":null,"loaded_instances":[` + strings.Join(loaded, ",") + `],"max_context_length":8192,"format":"gguf"}]}`
}

func lmLoadCommand(t *testing.T, id, providerID string, contextLength uint64, known bool) provider.LoadModelCommand {
	t.Helper()
	command, err := provider.NewLoadModelCommand(id, providerID, lifecycleModelName, 0, provider.Metadata{ContextLength: contextLength, Known: known})
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func lmUnloadCommand(t *testing.T, id, providerID string) provider.UnloadModelCommand {
	t.Helper()
	command, err := provider.NewUnloadModelCommand(id, providerID, lifecycleModelName, provider.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func lmOK(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}
}

func TestLifecycleLoadExactWireSequenceAndResult(t *testing.T) {
	step := 0
	client := testClient(t, doerFunc(func(request *http.Request) (*http.Response, error) {
		step++
		switch step {
		case 1:
			if request.Method != http.MethodGet || request.URL.Path != "/api/v1/models" {
				t.Fatalf("precheck = %s %s", request.Method, request.URL)
			}
			return lmOK(lmNativeState()), nil
		case 2:
			if request.Method != http.MethodPost || request.URL.Path != "/api/v1/models/load" {
				t.Fatalf("mutation = %s %s", request.Method, request.URL)
			}
			if !reflect.DeepEqual(request.Header.Values("Accept"), []string{"application/json"}) || !reflect.DeepEqual(request.Header.Values("Content-Type"), []string{"application/json"}) || request.Header.Get("Authorization") != "" {
				t.Fatalf("headers = %#v", request.Header)
			}
			body, _ := io.ReadAll(request.Body)
			if string(body) != `{"model":"acme/bert","context_length":4096}` {
				t.Fatalf("body = %s", body)
			}
			return lmOK(`{"type":"llm","instance_id":"instance-1","load_time_seconds":1.25,"status":"loaded"}`), nil
		case 3:
			return lmOK(lmNativeState("instance-1")), nil
		default:
			t.Fatalf("unexpected request %d", step)
			return nil, nil
		}
	}))
	result, err := client.Load(context.Background(), lmLoadCommand(t, "cmd-load", "lmstudio-main", 4096, true))
	if err != nil {
		t.Fatal(err)
	}
	if step != 3 || result.CommandID != "cmd-load" || result.ProviderID != "lmstudio-main" || result.CanonicalModelName != lifecycleModelName || result.Action != provider.ActionLoad || result.Outcome != provider.OutcomeSucceeded || !result.Changed || result.RuntimeState != provider.RuntimeLoaded || result.ObservedAt != "2026-09-27T03:01:02.987Z" {
		t.Fatalf("step/result = %d/%#v", step, result)
	}
}

func TestLifecycleLoadOmitsUnknownContextAndNoopIsIdempotent(t *testing.T) {
	requests := 0
	client := testClient(t, doerFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		return lmOK(lmNativeState("instance-1")), nil
	}))
	command := lmLoadCommand(t, "cmd-load", "lmstudio-main", 0, false)
	first, err := client.Load(context.Background(), command)
	if err != nil || first.Changed || first.RuntimeState != provider.RuntimeLoaded {
		t.Fatalf("first = %#v, %v", first, err)
	}
	second, err := client.Load(context.Background(), command)
	if err != nil || second != first || requests != 2 {
		t.Fatalf("second/requests = %#v/%d, %v", second, requests, err)
	}
}

func TestLifecycleLoadKnownContextRequiresConvergence(t *testing.T) {
	t.Run("matching loaded context is no-op", func(t *testing.T) {
		calls := 0
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return lmOK(lmNativeStateWithContext(4096, "instance-1")), nil
		}))
		result, err := client.Load(context.Background(), lmLoadCommand(t, "cmd", "lmstudio-main", 4096, true))
		if err != nil || result.Changed || calls != 1 {
			t.Fatalf("result=%#v calls=%d err=%v", result, calls, err)
		}
	})

	t.Run("mismatched loaded context blocks mutation", func(t *testing.T) {
		calls := 0
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return lmOK(lmNativeStateWithContext(2048, "instance-1")), nil
		}))
		_, err := client.Load(context.Background(), lmLoadCommand(t, "cmd", "lmstudio-main", 4096, true))
		if !errors.Is(err, ErrLifecyclePrecheckFailed) || !errors.Is(err, ErrLifecycleContextUnsupported) || calls != 1 {
			t.Fatalf("calls=%d err=%v", calls, err)
		}
	})

	t.Run("post-verification requires requested context", func(t *testing.T) {
		step := 0
		client := testClient(t, doerFunc(func(request *http.Request) (*http.Response, error) {
			step++
			switch step {
			case 1:
				return lmOK(lmNativeState()), nil
			case 2:
				return lmOK(`{"type":"llm","instance_id":"i","load_time_seconds":0,"status":"loaded"}`), nil
			default:
				return lmOK(lmNativeStateWithContext(2048, "i")), nil
			}
		}))
		_, err := client.Load(context.Background(), lmLoadCommand(t, "cmd", "lmstudio-main", 4096, true))
		if !errors.Is(err, ErrLifecycleVerificationFailed) || step != 3 {
			t.Fatalf("step=%d err=%v", step, err)
		}
	})
}

func TestLifecycleLoadOmitsUnknownContextOnWire(t *testing.T) {
	step := 0
	client := testClient(t, doerFunc(func(request *http.Request) (*http.Response, error) {
		step++
		switch step {
		case 1:
			return lmOK(lmNativeState()), nil
		case 2:
			body, _ := io.ReadAll(request.Body)
			if string(body) != `{"model":"acme/bert"}` {
				t.Fatalf("body = %s", body)
			}
			return lmOK(`{"type":"llm","instance_id":"i","load_time_seconds":0,"status":"loaded"}`), nil
		default:
			return lmOK(lmNativeState("i")), nil
		}
	}))
	if _, err := client.Load(context.Background(), lmLoadCommand(t, "cmd", "lmstudio-main", 0, false)); err != nil || step != 3 {
		t.Fatalf("load = %v, requests=%d", err, step)
	}
}

func TestLifecycleUnloadExactInstanceWireAndConvergence(t *testing.T) {
	step := 0
	client := testClient(t, doerFunc(func(request *http.Request) (*http.Response, error) {
		step++
		if step == 1 {
			return lmOK(lmNativeState("opaque-instance")), nil
		}
		if step == 2 {
			if request.Method != http.MethodPost || request.URL.Path != "/api/v1/models/unload" {
				t.Fatalf("request = %s %s", request.Method, request.URL)
			}
			body, _ := io.ReadAll(request.Body)
			if string(body) != `{"instance_id":"opaque-instance"}` {
				t.Fatalf("body = %s", body)
			}
			return lmOK(`{"instance_id":"opaque-instance"}`), nil
		}
		return lmOK(lmNativeState()), nil
	}))
	result, err := client.Unload(context.Background(), lmUnloadCommand(t, "cmd-unload", "lmstudio-main"))
	if err != nil || step != 3 || !result.Changed || result.Action != provider.ActionUnload || result.RuntimeState != provider.RuntimeUnloaded {
		t.Fatalf("result/step = %#v/%d, %v", result, step, err)
	}
}

func TestLifecycleGuardsConflictKeepAliveContextAndAmbiguity(t *testing.T) {
	called := 0
	client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) { called++; return lmOK(lmNativeState("one", "two")), nil }))
	if _, err := client.Load(context.Background(), lmLoadCommand(t, "c", "other", 0, false)); !errors.Is(err, ErrLifecycleProviderConflict) || called != 0 {
		t.Fatalf("conflict = %v, calls=%d", err, called)
	}
	withKeepAlive, err := provider.NewLoadModelCommand("c", "lmstudio-main", lifecycleModelName, time.Second, provider.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Load(context.Background(), withKeepAlive); !errors.Is(err, ErrLifecycleKeepAliveUnsupported) || called != 0 {
		t.Fatalf("keep alive = %v, calls=%d", err, called)
	}
	if _, err = client.Unload(context.Background(), lmUnloadCommand(t, "c", "lmstudio-main")); !errors.Is(err, ErrLifecycleAmbiguousInstances) || called != 1 {
		t.Fatalf("ambiguity = %v, calls=%d", err, called)
	}

	contextClient := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) { return lmOK(lmNativeState()), nil }))
	if _, err = contextClient.Load(context.Background(), lmLoadCommand(t, "c", "lmstudio-main", 8193, true)); !errors.Is(err, ErrLifecycleContextUnsupported) {
		t.Fatalf("context = %v", err)
	}
}

func TestLifecyclePhaseClassificationAndVerification(t *testing.T) {
	precheck := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(strings.NewReader("secret"))}, nil
	}))
	_, err := precheck.Load(context.Background(), lmLoadCommand(t, "cmd", "lmstudio-main", 0, false))
	if !errors.Is(err, ErrLifecyclePrecheckFailed) || !errors.Is(err, ErrNativeModelsHTTPStatus) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("precheck = %v", err)
	}

	step := 0
	verification := testClient(t, doerFunc(func(request *http.Request) (*http.Response, error) {
		step++
		if request.Method == http.MethodPost {
			return lmOK(`{"type":"llm","instance_id":"i","load_time_seconds":0,"status":"loaded"}`), nil
		}
		return lmOK(lmNativeState()), nil
	}))
	_, err = verification.Load(context.Background(), lmLoadCommand(t, "cmd", "lmstudio-main", 0, false))
	if !errors.Is(err, ErrLifecycleVerificationFailed) || step != 3 {
		t.Fatalf("verification = %v, requests=%d", err, step)
	}

	unloaded, err := verification.Unload(context.Background(), lmUnloadCommand(t, "cmd", "lmstudio-main"))
	if err != nil || unloaded.Changed || unloaded.RuntimeState != provider.RuntimeUnloaded || step != 4 {
		t.Fatalf("unloaded no-op = %#v, %v, requests=%d", unloaded, err, step)
	}
}

func TestLifecycleStrictMutationResponses(t *testing.T) {
	badLoads := []string{
		``, `{}`, `{"type":"llm","instance_id":"i","load_time_seconds":0,"status":"loaded","extra":1}`,
		`{"type":"bad","instance_id":"i","load_time_seconds":0,"status":"loaded"}`,
		`{"type":"llm","instance_id":"i","load_time_seconds":-1,"status":"loaded"}`,
		`{"type":"llm","instance_id":"i","load_time_seconds":0,"status":"loading"}`,
		`{"load_config":{"context_length":4096},"status":"loaded","load_time_seconds":0,"instance_id":"i","type":"llm"} trailing`,
	}
	for index, response := range badLoads {
		t.Run(fmt.Sprintf("load-%d", index), func(t *testing.T) {
			if err := validateLoadResponse([]byte(response)); !errors.Is(err, ErrLifecycleInvalidResponse) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if err := validateLoadResponse([]byte(`{"load_config":{"context_length":4096,"flash_attention":true},"status":"loaded","load_time_seconds":0,"instance_id":"i","type":"llm"}`)); err != nil {
		t.Fatalf("valid reordered response = %v", err)
	}
	for _, response := range []string{`{}`, `{"instance_id":"other"}`, `{"instance_id":"i","extra":1}`, `{"instance_id":"i"}[]`} {
		if err := validateUnloadResponse("i", []byte(response)); !errors.Is(err, ErrLifecycleInvalidResponse) {
			t.Fatalf("unload %q = %v", response, err)
		}
	}
}

func TestLifecycleMutationErrorPhasesBoundsCloseAndRedaction(t *testing.T) {
	secret := "do-not-leak"
	tests := []struct {
		name string
		doer HTTPDoer
		want error
	}{
		{"transport", doerFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New(secret) }), ErrLifecycleMutationFailed},
		{"wrapped deadline", doerFunc(func(*http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("%s: %w", secret, context.DeadlineExceeded)
		}), context.DeadlineExceeded},
		{"nil response", doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil }), ErrLifecycleMutationFailed},
		{"status", doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader(secret))}, nil
		}), ErrLifecycleHTTPStatus},
		{"malformed", doerFunc(func(*http.Request) (*http.Response, error) { return lmOK(secret), nil }), ErrLifecycleInvalidResponse},
		{"oversize", doerFunc(func(*http.Request) (*http.Response, error) {
			return lmOK(strings.Repeat("x", MaximumLifecycleBodySize+1)), nil
		}), ErrLifecycleResponseTooLarge},
		{"read", doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: &errorReadCloser{err: errors.New(secret)}}, nil
		}), ErrLifecycleInvalidResponse},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := testClient(t, test.doer)
			err := client.doLifecycleMutation(context.Background(), "/api/v1/models/load", []byte(`{}`), func([]byte) error { return ErrLifecycleInvalidResponse })
			if !errors.Is(err, test.want) || strings.Contains(err.Error(), secret) {
				t.Fatalf("error = %v", err)
			}
		})
	}

	body := &trackedBody{Reader: strings.NewReader(`{}`)}
	client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 500, Body: body}, errors.New(secret)
	}))
	if err := client.doLifecycleMutation(context.Background(), "/x", nil, func([]byte) error { return nil }); !errors.Is(err, ErrLifecycleMutationFailed) || !body.closed || strings.Contains(err.Error(), secret) {
		t.Fatalf("response+error = %v closed=%v", err, body.closed)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.doLifecycleMutation(ctx, "/x", nil, func([]byte) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel = %v", err)
	}
}

type errorReadCloser struct {
	err    error
	closed bool
}

func (reader *errorReadCloser) Read([]byte) (int, error) { return 0, reader.err }
func (reader *errorReadCloser) Close() error             { reader.closed = true; return nil }
