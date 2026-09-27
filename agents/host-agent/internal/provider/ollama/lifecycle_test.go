package ollama

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
)

const (
	lifecycleName     = "acme/bert:latest"
	lifecycleDigest   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	fixedLifecycleNow = "2026-09-27T03:01:02.987Z"
)

func ok200(body io.Reader) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(body)}
}

func lifecyclePS(loaded bool) string {
	if !loaded {
		return `{"models":[]}`
	}
	return `{"models":[{"name":"acme/bert:latest","model":"acme/bert:latest","size":456,"digest":"` + lifecycleDigest + `","details":{"parent_model":"","format":"gguf","family":"qwen2","families":["qwen2"],"parameter_size":"7B","quantization_level":"Q4"},"expires_at":"2026-09-27T03:01:02Z","size_vram":321,"context_length":8192}]}`
}

func lifecycleSuccess() string {
	return `{"model":"acme/bert:latest","created_at":"2026-09-27T03:01:02.123Z","response":"","done":true,"done_reason":"load","context":[0,1,2147483647],"total_duration":1,"load_duration":0,"prompt_eval_count":0,"prompt_eval_duration":0,"eval_count":0,"eval_duration":0}`
}

func lifecycleLoad(t *testing.T, id, providerID string) provider.LoadModelCommand {
	t.Helper()
	command, err := provider.NewLoadModelCommand(id, providerID, lifecycleName, 30*time.Second, provider.Metadata{ContextLength: 8192, Known: true})
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func lifecycleUnload(t *testing.T, id, providerID string) provider.UnloadModelCommand {
	t.Helper()
	command, err := provider.NewUnloadModelCommand(id, providerID, lifecycleName, provider.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func TestLoadExactRequestAndConvergence(t *testing.T) {
	gets, posts := 0, 0
	client := testClient(t, doerFunc(func(request *http.Request) (*http.Response, error) {
		switch request.Method {
		case http.MethodGet:
			gets++
			return ok200(strings.NewReader(lifecyclePS(gets > 1))), nil
		case http.MethodPost:
			posts++
			if request.URL.String() != "http://127.0.0.1:11434/api/generate" || request.Header.Get("Accept") != "application/json" || request.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("unexpected request metadata: %#v", request)
			}
			body, _ := io.ReadAll(request.Body)
			const want = `{"model":"acme/bert:latest","prompt":"","stream":false,"keep_alive":"30s"}`
			if string(body) != want {
				t.Fatalf("body = %s, want %s", body, want)
			}
			var fields map[string]any
			if err := json.Unmarshal(body, &fields); err != nil || len(fields) != 4 {
				t.Fatalf("unexpected fields: %#v, %v", fields, err)
			}
			return ok200(strings.NewReader(lifecycleSuccess())), nil
		default:
			t.Fatalf("unexpected method %s", request.Method)
			return nil, nil
		}
	}))
	result, err := client.Load(context.Background(), lifecycleLoad(t, "cmd-load", "ollama-main"))
	if err != nil {
		t.Fatal(err)
	}
	if gets != 2 || posts != 1 {
		t.Fatalf("gets/posts = %d/%d, want 2/1", gets, posts)
	}
	if result.CommandID != "cmd-load" || result.ProviderID != "ollama-main" || result.CanonicalModelName != lifecycleName || result.Action != provider.ActionLoad || result.Outcome != provider.OutcomeSucceeded || !result.Changed || result.RuntimeState != provider.RuntimeLoaded || result.ObservedAt != fixedLifecycleNow {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestUnloadExactNumericZeroAndConvergence(t *testing.T) {
	gets, posts := 0, 0
	client := testClient(t, doerFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet {
			gets++
			return ok200(strings.NewReader(lifecyclePS(gets == 1))), nil
		}
		posts++
		body, _ := io.ReadAll(request.Body)
		const want = `{"model":"acme/bert:latest","prompt":"","stream":false,"keep_alive":0}`
		if string(body) != want {
			t.Fatalf("body = %s, want numeric zero", body)
		}
		var fields map[string]any
		_ = json.Unmarshal(body, &fields)
		if value, ok := fields["keep_alive"].(float64); !ok || value != 0 {
			t.Fatalf("keep_alive type/value = %T/%v", fields["keep_alive"], fields["keep_alive"])
		}
		return ok200(strings.NewReader(lifecycleSuccess())), nil
	}))
	result, err := client.Unload(context.Background(), lifecycleUnload(t, "cmd-unload", "ollama-main"))
	if err != nil {
		t.Fatal(err)
	}
	if gets != 2 || posts != 1 || !result.Changed || result.RuntimeState != provider.RuntimeUnloaded || result.Action != provider.ActionUnload {
		t.Fatalf("gets/posts/result = %d/%d/%#v", gets, posts, result)
	}
}

func TestLifecycleNoOpsDoNotPost(t *testing.T) {
	for _, test := range []struct {
		name   string
		loaded bool
		run    func(*Client) (provider.LifecycleResult, error)
		state  provider.RuntimeState
	}{
		{"load", true, func(c *Client) (provider.LifecycleResult, error) {
			return c.Load(context.Background(), lifecycleLoad(t, "load", "ollama-main"))
		}, provider.RuntimeLoaded},
		{"unload", false, func(c *Client) (provider.LifecycleResult, error) {
			return c.Unload(context.Background(), lifecycleUnload(t, "unload", "ollama-main"))
		}, provider.RuntimeUnloaded},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := testClient(t, doerFunc(func(request *http.Request) (*http.Response, error) {
				if request.Method == http.MethodPost {
					t.Fatal("no-op posted")
				}
				return ok200(strings.NewReader(lifecyclePS(test.loaded))), nil
			}))
			result, err := test.run(client)
			if err != nil || result.Changed || result.Outcome != provider.OutcomeSucceeded || result.RuntimeState != test.state {
				t.Fatalf("result = %#v, %v", result, err)
			}
		})
	}
}

func TestLifecycleProviderMismatchRejectedBeforeIO(t *testing.T) {
	calls := 0
	client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, nil }))
	_, err := client.Load(context.Background(), lifecycleLoad(t, "cmd", "ollama-other"))
	if !errors.Is(err, ErrLifecycleProviderConflict) || calls != 0 {
		t.Fatalf("error/calls = %v/%d", err, calls)
	}
}

func TestGenerateResponseStrictDocumentedShape(t *testing.T) {
	if err := validateGenerateResponse(lifecycleName, []byte(lifecycleSuccess())); err != nil {
		t.Fatalf("valid response: %v", err)
	}
	validOptional := `{"model":"ACME/BERT:LATEST","done":true,"created_at":"2026-09-27T03:01:02Z","response":"x","done_reason":"stop","context":[],"total_duration":0,"load_duration":1,"prompt_eval_count":2,"prompt_eval_duration":3,"eval_count":4,"eval_duration":5}`
	if err := validateGenerateResponse(lifecycleName, []byte(validOptional)); err != nil {
		t.Fatalf("canonical-equal response: %v", err)
	}
	invalid := []string{
		`{}`, `{"model":"acme/bert:latest"}`, `{"done":true}`, `{"model":"acme/bert:latest","done":false}`,
		`{"model":"other:latest","done":true}`, `{"model":"acme/bert:latest","done":true,"unknown":0}`,
		`{"model":"acme/bert:latest","model":"acme/bert:latest","done":true}`,
		`{"model":"acme/bert:latest","done":true} {}`, `{"model":"acme/bert:latest","done":1}`,
		`{"model":"acme/bert:latest","done":true,"created_at":"bad"}`,
		`{"model":"acme/bert:latest","done":true,"total_duration":-1}`,
		`{"model":"acme/bert:latest","done":true,"eval_count":1.5}`,
		`{"model":"acme/bert:latest","done":true,"context":[null]}`,
		`{"model":"acme/bert:latest","done":true,"context":[2147483648]}`,
	}
	for _, body := range invalid {
		if err := validateGenerateResponse(lifecycleName, []byte(body)); !errors.Is(err, ErrLifecycleInvalidResponse) {
			t.Errorf("body %q: %v", body, err)
		}
	}
}

func TestLifecyclePhaseErrorsAndVerification(t *testing.T) {
	t.Run("precheck", func(t *testing.T) {
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader("secret"))}, nil
		}))
		_, err := client.Load(context.Background(), lifecycleLoad(t, "cmd", "ollama-main"))
		if !errors.Is(err, ErrLifecyclePrecheckFailed) || !errors.Is(err, ErrRunningHTTPStatus) || strings.Contains(err.Error(), "secret") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("verification observation", func(t *testing.T) {
		gets := 0
		client := testClient(t, doerFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method == http.MethodPost {
				return ok200(strings.NewReader(lifecycleSuccess())), nil
			}
			gets++
			if gets == 1 {
				return ok200(strings.NewReader(lifecyclePS(false))), nil
			}
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader("secret"))}, nil
		}))
		_, err := client.Load(context.Background(), lifecycleLoad(t, "cmd", "ollama-main"))
		if !errors.Is(err, ErrLifecycleVerificationFailed) || !errors.Is(err, ErrRunningHTTPStatus) || strings.Contains(err.Error(), "secret") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("state mismatch", func(t *testing.T) {
		posts := 0
		client := testClient(t, doerFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method == http.MethodPost {
				posts++
				return ok200(strings.NewReader(lifecycleSuccess())), nil
			}
			return ok200(strings.NewReader(lifecyclePS(false))), nil
		}))
		_, err := client.Load(context.Background(), lifecycleLoad(t, "cmd", "ollama-main"))
		if !errors.Is(err, ErrLifecycleVerificationFailed) || posts != 1 {
			t.Fatalf("error/posts = %v/%d", err, posts)
		}
	})
}

func TestMutationErrorsCloseAndRedact(t *testing.T) {
	tests := []struct {
		name     string
		response func() (*http.Response, error)
		want     error
	}{
		{"transport", func() (*http.Response, error) { return nil, errors.New("dial secret") }, ErrLifecycleMutationFailed},
		{"status", func() (*http.Response, error) {
			return &http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader("secret"))}, nil
		}, ErrLifecycleHTTPStatus},
		{"malformed", func() (*http.Response, error) { return ok200(strings.NewReader("secret not json")), nil }, ErrLifecycleInvalidResponse},
		{"oversize", func() (*http.Response, error) {
			return ok200(strings.NewReader(strings.Repeat("x", MaximumGenerateBodySize+1))), nil
		}, ErrLifecycleResponseTooLarge},
		{"read", func() (*http.Response, error) {
			return ok200(readerFunc(func([]byte) (int, error) { return 0, errors.New("read secret") })), nil
		}, ErrLifecycleInvalidResponse},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := testClient(t, doerFunc(func(request *http.Request) (*http.Response, error) {
				if request.Method == http.MethodGet {
					return ok200(strings.NewReader(lifecyclePS(false))), nil
				}
				return test.response()
			}))
			_, err := client.Load(context.Background(), lifecycleLoad(t, "cmd", "ollama-main"))
			if !errors.Is(err, test.want) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("error = %v", err)
			}
		})
	}

	body := &trackedBody{Reader: strings.NewReader(lifecycleSuccess())}
	client := testClient(t, doerFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet {
			return ok200(strings.NewReader(lifecyclePS(false))), nil
		}
		return &http.Response{StatusCode: 200, Body: body}, errors.New("transport secret")
	}))
	_, err := client.Load(context.Background(), lifecycleLoad(t, "cmd", "ollama-main"))
	if !errors.Is(err, ErrLifecycleMutationFailed) || !body.closed || strings.Contains(err.Error(), "secret") {
		t.Fatalf("response+error = %v, closed=%v", err, body.closed)
	}
}

func TestLifecycleCancellationEveryPhase(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) { t.Fatal("called with canceled precheck"); return nil, nil }))
	if _, err := client.Load(ctx, lifecycleLoad(t, "pre", "ollama-main")); !errors.Is(err, context.Canceled) {
		t.Fatalf("precheck = %v", err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	client = testClient(t, doerFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet {
			return ok200(strings.NewReader(lifecyclePS(false))), nil
		}
		cancel()
		return nil, request.Context().Err()
	}))
	if _, err := client.Load(ctx, lifecycleLoad(t, "mutation", "ollama-main")); !errors.Is(err, context.Canceled) {
		t.Fatalf("mutation = %v", err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	gets := 0
	client = testClient(t, doerFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet {
			gets++
			return ok200(strings.NewReader(lifecyclePS(false))), nil
		}
		cancel()
		return ok200(strings.NewReader(lifecycleSuccess())), nil
	}))
	if _, err := client.Load(ctx, lifecycleLoad(t, "verify", "ollama-main")); !errors.Is(err, context.Canceled) || gets != 1 {
		t.Fatalf("verification = %v gets=%d", err, gets)
	}
}

func TestRepeatedCallsDoNotMutateTwice(t *testing.T) {
	loaded, posts := false, 0
	client := testClient(t, doerFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet {
			return ok200(strings.NewReader(lifecyclePS(loaded))), nil
		}
		posts++
		loaded = true
		return ok200(strings.NewReader(lifecycleSuccess())), nil
	}))
	first, err := client.Load(context.Background(), lifecycleLoad(t, "same", "ollama-main"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.Load(context.Background(), lifecycleLoad(t, "same", "ollama-main"))
	if err != nil {
		t.Fatal(err)
	}
	if posts != 1 || !first.Changed || second.Changed {
		t.Fatalf("posts/results = %d %#v %#v", posts, first, second)
	}
}
