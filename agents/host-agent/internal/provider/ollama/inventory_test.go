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

const digestA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
const digestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func tagJSON(name, digest, modified string) string {
	return `{"name":"` + name + `","model":"` + name + `","modified_at":"` + modified + `","size":123,"digest":"` + digest + `","details":{"parent_model":"","format":"gguf","family":"qwen2","families":["qwen2","bert"],"parameter_size":"7.6B","quantization_level":"Q4_K_M"}}`
}

func TestListInstalledNormalizesSortsAndUsesExactRequest(t *testing.T) {
	payload := `{"models":[` + tagJSON("Zoo/Model:Latest", digestB, "2026-09-26T20:01:02.987654321-05:00") + `,` + tagJSON("acme/embed@sha256:"+strings.ToLower(digestA), digestA, "2026-09-27T03:01:02Z") + `]}`
	body := &trackedBody{Reader: strings.NewReader(payload)}
	client := testClient(t, doerFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.String() != "http://127.0.0.1:11434/api/tags" || request.Header.Get("Accept") != "application/json" {
			t.Fatalf("unexpected request: %s %s %#v", request.Method, request.URL, request.Header)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
	}))
	models, err := client.ListInstalled(context.Background())
	if err != nil || len(models) != 2 {
		t.Fatalf("ListInstalled = %#v, %v", models, err)
	}
	if models[0].CanonicalName != "acme/embed@sha256:"+strings.ToLower(digestA) || models[0].Digest != strings.ToLower(digestA) || models[0].ModifiedAt != "2026-09-27T03:01:02.000Z" {
		t.Fatalf("first model not normalized: %#v", models[0])
	}
	if models[1].CanonicalName != "zoo/model:latest" || models[1].DisplayName != "Zoo/Model:Latest" || models[1].ModifiedAt != "2026-09-27T01:01:02.987Z" || models[1].SizeBytes != 123 {
		t.Fatalf("second model not normalized: %#v", models[1])
	}
	if models[0].ModelID == models[1].ModelID || !strings.HasPrefix(models[0].ModelID, "ollama-") || !body.closed {
		t.Fatal("unstable identity or unclosed body")
	}
	models[0].Families[0] = "mutated"
	body.Reader = strings.NewReader(payload)
	body.closed = false
	again, err := client.ListInstalled(context.Background())
	if err != nil || again[0].Families[0] != "qwen2" {
		t.Fatalf("result aliases prior mutation: %#v, %v", again, err)
	}
}

func TestListInstalledEmptyIsNonNil(t *testing.T) {
	client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"models":[]}`))}, nil
	}))
	models, err := client.ListInstalled(context.Background())
	if err != nil || models == nil || len(models) != 0 {
		t.Fatalf("empty = %#v, %v", models, err)
	}
}

func TestListInstalledStrictInvalidResponses(t *testing.T) {
	valid := tagJSON("qwen:latest", digestA, "2026-09-27T03:01:02.123456Z")
	cases := []string{
		`{}`, `[]`, `{"models":null}`, `{"models":[],"extra":1}`, `{"models":[],"models":[]}`, `{"models":[]} {}`,
		`{"models":[` + strings.Replace(valid, `"name":`, `"extra":1,"name":`, 1) + `]}`,
		`{"models":[` + strings.Replace(valid, `"name":"qwen:latest"`, `"name":"qwen:latest","name":"qwen:latest"`, 1) + `]}`,
		`{"models":[` + strings.Replace(valid, `"format":"gguf"`, `"format":"gguf","extra":1`, 1) + `]}`,
		`{"models":[` + strings.Replace(valid, `"size":123`, `"size":-1`, 1) + `]}`,
		`{"models":[` + strings.Replace(valid, `"size":123`, `"size":1.2`, 1) + `]}`,
		`{"models":[` + strings.Replace(valid, `qwen:latest`, `../bad?query`, 2) + `]}`,
		`{"models":[` + strings.Replace(valid, digestA, `bad`, 1) + `]}`,
		`{"models":[` + strings.Replace(valid, `2026-09-27T03:01:02.123456Z`, `yesterday`, 1) + `]}`,
		`{"models":[` + strings.Replace(valid, `["qwen2","bert"]`, `["qwen2","QWEN2"]`, 1) + `]}`,
		`{"models":[` + valid + `,` + valid + `]}`,
	}
	for _, text := range cases {
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(text))}, nil
		}))
		if _, err := client.ListInstalled(context.Background()); err != ErrInvalidListResponse {
			t.Errorf("body %.60q: %v", text, err)
		}
	}
}

func TestListInstalledStableErrorsLimitsCancellationAndClose(t *testing.T) {
	t.Run("status", func(t *testing.T) {
		body := &trackedBody{Reader: strings.NewReader("secret body")}
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) { return &http.Response{StatusCode: 401, Body: body}, nil }))
		if _, err := client.ListInstalled(context.Background()); err != ErrListHTTPStatus || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "127.0.0.1") {
			t.Fatalf("error = %v", err)
		}
		if !body.closed {
			t.Fatal("body not closed")
		}
	})
	t.Run("transport", func(t *testing.T) {
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("secret.internal token") }))
		if _, err := client.ListInstalled(context.Background()); err != ErrListFailed {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("oversize", func(t *testing.T) {
		body := &trackedBody{Reader: strings.NewReader(strings.Repeat("x", MaximumListBodySize+1))}
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) { return &http.Response{StatusCode: 200, Body: body}, nil }))
		if _, err := client.ListInstalled(context.Background()); err != ErrListResponseTooLarge {
			t.Fatalf("error = %v", err)
		}
		if !body.closed {
			t.Fatal("body not closed")
		}
	})
	t.Run("body cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		body := &trackedBody{Reader: readerFunc(func([]byte) (int, error) { cancel(); return 0, errors.New("secret read") })}
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) { return &http.Response{StatusCode: 200, Body: body}, nil }))
		if _, err := client.ListInstalled(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
		if !body.closed {
			t.Fatal("body not closed")
		}
	})
	t.Run("deadline", func(t *testing.T) {
		client, err := NewWithDependencies(Config{ProviderID: "ollama", Endpoint: "http://localhost", Timeout: MinimumTimeout}, doerFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: &trackedBody{Reader: readerFunc(func([]byte) (int, error) { <-request.Context().Done(); return 0, errors.New("read") })}}, nil
		}), fakeClock{time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.ListInstalled(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestListInstalledProductionClientRejectsRedirects(t *testing.T) {
	redirected := false
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/tags" {
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
	if _, err := client.ListInstalled(context.Background()); err != ErrListHTTPStatus {
		t.Fatalf("redirect error = %v", err)
	}
	if redirected {
		t.Fatal("redirect followed")
	}
}

func TestDecodeInstalledModelsDenseLimitAndDeterminism(t *testing.T) {
	minimal := `{"name":"a","model":"a","modified_at":"2026-01-01T00:00:00Z","size":0,"digest":"` + digestA + `","details":{"parent_model":"","format":"g","family":"f","families":null,"parameter_size":"1B","quantization_level":"Q4"}}`
	var dense strings.Builder
	dense.WriteString(`{"models":[`)
	for index := 0; index <= MaximumInstalledModels; index++ {
		if index > 0 {
			dense.WriteByte(',')
		}
		dense.WriteString(minimal)
	}
	dense.WriteString(`]}`)
	if _, err := decodeInstalledModels([]byte(dense.String()), "ollama"); !errors.Is(err, ErrInvalidListResponse) {
		t.Fatalf("dense error = %v", err)
	}

	one := `{"models":[` + tagJSON("qwen:latest", digestA, "2026-09-27T03:01:02Z") + `]}`
	a, err := decodeInstalledModels([]byte(one), "provider-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := decodeInstalledModels([]byte(one), "provider-a")
	if err != nil {
		t.Fatal(err)
	}
	c, err := decodeInstalledModels([]byte(one), "provider-b")
	if err != nil {
		t.Fatal(err)
	}
	if a[0].ModelID != b[0].ModelID || a[0].ModelID == c[0].ModelID {
		t.Fatal("model ID is not deterministic/provider-scoped")
	}
}
