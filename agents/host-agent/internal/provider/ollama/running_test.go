package ollama

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func runningJSON(name, digest, expires string, contextLength uint64) string {
	return `{"name":"` + name + `","model":"` + name + `","size":456,"digest":"` + digest + `","details":{"parent_model":"","format":"gguf","family":"qwen2","families":["qwen2","bert"],"parameter_size":"7.6B","quantization_level":"Q4_K_M"},"expires_at":"` + expires + `","size_vram":321,"context_length":` + formatUint(contextLength) + `}`
}

func formatUint(value uint64) string {
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[index:])
}

// runningModelCustom renders one running-model object with a caller-chosen name
// and digest plus otherwise-valid fields, letting a test control the reported
// casing and content digest independently.
func runningModelCustom(name string, size, sizeVRAM uint64, digest string) string {
	return `{"name":"` + name + `","model":"` + name + `","size":` + formatUint(size) +
		`,"digest":"` + digest + `","details":{"parent_model":"","format":"gguf","family":"qwen2","families":["qwen2","bert"],"parameter_size":"7.6B","quantization_level":"Q4_K_M"},` +
		`,"expires_at":"2026-09-27T03:01:02.123456Z","size_vram":` + formatUint(sizeVRAM) +
		`,"context_length":8192}`
}

func TestListRunningNormalizesSortsAndUsesExactRequest(t *testing.T) {
	payload := `{"models":[` + runningJSON("Zoo/Model:Latest", digestB, "2026-09-26T22:31:02.987654321-05:00", 8192) + `,` + runningJSON("acme/embed@sha256:"+strings.ToLower(digestA), digestA, "2026-09-27T04:01:02Z", 1024) + `]}`
	body := &trackedBody{Reader: strings.NewReader(payload)}
	client := testClient(t, doerFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.String() != "http://127.0.0.1:11434/api/ps" || request.Header.Get("Accept") != "application/json" {
			t.Fatalf("unexpected request: %s %s %#v", request.Method, request.URL, request.Header)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
	}))
	models, err := client.ListRunning(context.Background())
	if err != nil || len(models) != 2 {
		t.Fatalf("ListRunning = %#v, %v", models, err)
	}
	if models[0].CanonicalName != "acme/embed@sha256:"+strings.ToLower(digestA) || models[0].Digest != strings.ToLower(digestA) || models[0].ContextLength != 1024 {
		t.Fatalf("first model not normalized: %#v", models[0])
	}
	if models[1].CanonicalName != "zoo/model:latest" || models[1].DisplayName != "Zoo/Model:Latest" || models[1].ExpiresAt != "2026-09-27T03:31:02.987Z" || models[1].ObservedAt != "2026-09-27T03:01:02.987Z" || models[1].SizeBytes != 456 || models[1].SizeVRAMBytes != 321 {
		t.Fatalf("second model not normalized: %#v", models[1])
	}
	if models[0].RuntimeID == models[1].RuntimeID || !strings.HasPrefix(models[0].RuntimeID, "ollama-runtime-") || models[0].Capabilities == nil || len(models[0].Capabilities) != 0 || !body.closed {
		t.Fatal("bad runtime identity/capabilities or unclosed body")
	}
	models[0].Families[0] = "mutated"
	body.Reader = strings.NewReader(payload)
	body.closed = false
	again, err := client.ListRunning(context.Background())
	if err != nil || again[0].Families[0] != "qwen2" {
		t.Fatalf("result aliases prior mutation: %#v, %v", again, err)
	}
}

func TestListRunningEmptyIsNonNil(t *testing.T) {
	client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"models":[]}`))}, nil
	}))
	models, err := client.ListRunning(context.Background())
	if err != nil || models == nil || len(models) != 0 {
		t.Fatalf("empty = %#v, %v", models, err)
	}
}

func TestListRunningStrictInvalidResponses(t *testing.T) {
	valid := runningJSON("qwen:latest", digestA, "2026-09-27T03:01:02.123456Z", 8192)
	cases := []string{
		`{}`, `[]`, `{"models":null}`, `{"models":[],"extra":1}`, `{"models":[],"models":[]}`, `{"models":[]} {}`,
		`{"models":[` + strings.Replace(valid, `"name":`, `"extra":1,"name":`, 1) + `]}`,
		`{"models":[` + strings.Replace(valid, `"name":"qwen:latest"`, `"name":"qwen:latest","name":"qwen:latest"`, 1) + `]}`,
		`{"models":[` + strings.Replace(valid, `"format":"gguf"`, `"format":"gguf","extra":1`, 1) + `]}`,
		`{"models":[` + strings.Replace(valid, `"size":456`, `"size":-1`, 1) + `]}`,
		`{"models":[` + strings.Replace(valid, `"size_vram":321`, `"size_vram":1.2`, 1) + `]}`,
		`{"models":[` + strings.Replace(valid, `"context_length":8192`, `"context_length":0`, 1) + `]}`,
		`{"models":[` + strings.Replace(valid, `"context_length":8192`, `"context_length":10000001`, 1) + `]}`,
		`{"models":[` + strings.Replace(valid, `qwen:latest`, `../bad?query`, 2) + `]}`,
		`{"models":[` + strings.Replace(valid, digestA, `bad`, 1) + `]}`,
		`{"models":[` + strings.Replace(valid, `2026-09-27T03:01:02.123456Z`, `tomorrow`, 1) + `]}`,
		`{"models":[` + strings.Replace(valid, `["qwen2","bert"]`, `["qwen2","QWEN2"]`, 1) + `]}`,
		`{"models":[` + valid + `,` + valid + `]}`,
	}
	for _, text := range cases {
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(text))}, nil
		}))
		if _, err := client.ListRunning(context.Background()); err != ErrInvalidRunningResponse {
			t.Errorf("body %.60q: %v", text, err)
		}
	}
}

func TestListRunningStableErrorsLimitsCancellationAndClose(t *testing.T) {
	t.Run("status", func(t *testing.T) {
		body := &trackedBody{Reader: strings.NewReader("secret body")}
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) { return &http.Response{StatusCode: 401, Body: body}, nil }))
		if _, err := client.ListRunning(context.Background()); err != ErrRunningHTTPStatus || strings.Contains(err.Error(), "secret") {
			t.Fatalf("error = %v", err)
		}
		if !body.closed {
			t.Fatal("body not closed")
		}
	})
	t.Run("transport", func(t *testing.T) {
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("secret.internal token") }))
		if _, err := client.ListRunning(context.Background()); err != ErrRunningFailed {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("oversize", func(t *testing.T) {
		body := &trackedBody{Reader: strings.NewReader(strings.Repeat("x", MaximumRunningBodySize+1))}
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) { return &http.Response{StatusCode: 200, Body: body}, nil }))
		if _, err := client.ListRunning(context.Background()); err != ErrRunningResponseTooLarge || !body.closed {
			t.Fatalf("error = %v, closed=%v", err, body.closed)
		}
	})
	t.Run("body cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		body := &trackedBody{Reader: readerFunc(func([]byte) (int, error) { cancel(); return 0, errors.New("secret read") })}
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) { return &http.Response{StatusCode: 200, Body: body}, nil }))
		if _, err := client.ListRunning(ctx); !errors.Is(err, context.Canceled) || !body.closed {
			t.Fatalf("error = %v, closed=%v", err, body.closed)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		client, err := NewWithDependencies(Config{ProviderID: "ollama", Endpoint: "http://localhost", Timeout: MinimumTimeout}, doerFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: &trackedBody{Reader: readerFunc(func([]byte) (int, error) { <-request.Context().Done(); return 0, errors.New("read") })}}, nil
		}), fakeClock{time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.ListRunning(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestListRunningProductionClientRejectsRedirects(t *testing.T) {
	redirected := false
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/ps" {
			http.Redirect(writer, request, "/secret", http.StatusFound)
			return
		}
		redirected = true
		_, _ = io.WriteString(writer, `{"models":[]}`)
	}))
	defer server.Close()
	client, err := New(Config{ProviderID: "ollama", Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListRunning(context.Background()); err != ErrRunningHTTPStatus || redirected {
		t.Fatalf("redirect error = %v, followed=%v", err, redirected)
	}
}

func TestDecodeRunningModelsDenseLimitAndDeterminism(t *testing.T) {
	minimal := runningJSON("a", digestA, "2026-01-01T00:00:00Z", 1)
	var dense strings.Builder
	dense.WriteString(`{"models":[`)
	for index := 0; index <= MaximumRunningModels; index++ {
		if index > 0 {
			dense.WriteByte(',')
		}
		dense.WriteString(minimal)
	}
	dense.WriteString(`]}`)
	if _, err := decodeRunningModels([]byte(dense.String()), "ollama", "2026-01-01T00:00:00.000Z"); !errors.Is(err, ErrInvalidRunningResponse) {
		t.Fatalf("dense error = %v", err)
	}

	one := `{"models":[` + runningJSON("qwen:latest", digestA, "2026-09-27T03:01:02Z", 8192) + `]}`
	a, err := decodeRunningModels([]byte(one), "provider-a", "2026-01-01T00:00:00.000Z")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := decodeRunningModels([]byte(one), "provider-a", "2026-01-02T00:00:00.000Z")
	c, _ := decodeRunningModels([]byte(one), "provider-b", "2026-01-01T00:00:00.000Z")
	if a[0].RuntimeID != b[0].RuntimeID || a[0].RuntimeID == c[0].RuntimeID {
		t.Fatal("runtime ID is not deterministic/provider-scoped")
	}
}
