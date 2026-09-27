package ollama

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
)

type fakeClock struct{ value time.Time }

func (c fakeClock) Now() time.Time { return c.value }

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

type trackedBody struct {
	io.Reader
	closed bool
}

func (b *trackedBody) Close() error { b.closed = true; return nil }

func testClient(t *testing.T, doer HTTPDoer) *Client {
	t.Helper()
	c, err := NewWithDependencies(Config{ProviderID: "ollama-main", Endpoint: "http://127.0.0.1:11434/"}, doer,
		fakeClock{time.Date(2026, 9, 26, 22, 1, 2, 987654321, time.FixedZone("test", -5*60*60))})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNormalizeEndpoint(t *testing.T) {
	for input, want := range map[string]string{
		"http://localhost:1":      "http://localhost:1",
		"http://localhost:11434":  "http://localhost:11434",
		"http://localhost:11434/": "http://localhost:11434",
		"http://localhost:65535":  "http://localhost:65535",
		"https://[::1]:1":         "https://[::1]:1",
		"https://[::1]:11434":     "https://[::1]:11434",
		"https://[::1]:65535":     "https://[::1]:65535",
	} {
		got, err := NormalizeEndpoint(input)
		if err != nil || got != want {
			t.Errorf("NormalizeEndpoint(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"", " http://localhost", "ftp://localhost", "http://", "http://user@localhost",
		"http://user:secret@localhost", "http://localhost?token=secret", "http://localhost?", "http://localhost/#x",
		"http://localhost#", "http://localhost/#", "http://localhost/api", "http://localhost/%2F", "//localhost:11434",
		"http://localhost:", "http://localhost:0", "http://localhost:65536", "http://localhost:not-a-port",
		"http://[::1]:", "http://[::1]:0", "http://[::1]:65536", "http://[::1]:not-a-port"} {
		if _, err := NormalizeEndpoint(input); !errors.Is(err, ErrInvalidEndpoint) {
			t.Errorf("NormalizeEndpoint(%q) error = %v", input, err)
		}
	}
}

func TestConfigValidationAndDefaults(t *testing.T) {
	doer := doerFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("unused") })
	for _, id := range []string{"UPPER", "contains:colon", strings.Repeat("a", 128)} {
		if _, err := NewWithDependencies(Config{ProviderID: id, Endpoint: "http://localhost"}, doer, fakeClock{}); err != nil {
			t.Errorf("valid id %q rejected: %v", id, err)
		}
	}
	for _, id := range []string{"", "-leading", strings.Repeat("a", 129), "has/slash", "has space", "has\x00control", "nonascii-é"} {
		_, err := NewWithDependencies(Config{ProviderID: id, Endpoint: "http://localhost"}, doer, fakeClock{})
		if !errors.Is(err, ErrInvalidID) {
			t.Errorf("id %q error = %v", id, err)
		}
	}
	for _, timeout := range []time.Duration{time.Nanosecond, 99 * time.Millisecond, MaximumTimeout + 1, -time.Second} {
		_, err := NewWithDependencies(Config{ProviderID: "ollama", Endpoint: "http://localhost", Timeout: timeout}, doer, fakeClock{})
		if !errors.Is(err, ErrInvalidTimeout) {
			t.Errorf("timeout %s error = %v", timeout, err)
		}
	}
	for _, timeout := range []time.Duration{0, MinimumTimeout, MaximumTimeout} {
		client, err := NewWithDependencies(Config{ProviderID: "ollama", Endpoint: "http://localhost", Timeout: timeout}, doer, fakeClock{})
		if err != nil {
			t.Errorf("timeout %s rejected: %v", timeout, err)
		} else if timeout == 0 && client.timeout != DefaultTimeout {
			t.Errorf("default = %s", client.timeout)
		}
	}
	if _, err := NewWithDependencies(Config{ProviderID: "ollama", Endpoint: "http://localhost"}, nil, fakeClock{}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("nil doer: %v", err)
	}
	if _, err := NewWithDependencies(Config{ProviderID: "ollama", Endpoint: "http://localhost"}, doer, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("nil clock: %v", err)
	}
}

func TestParseVersion(t *testing.T) {
	boundaryPrerelease := strings.Repeat("a", 122)
	valid := map[string]provider.VersionInfo{
		"0.5.7": {Raw: "0.5.7", Minor: 5, Patch: 7}, "v0.5.7": {Raw: "0.5.7", Minor: 5, Patch: 7},
		"12.34.56-rc.1":               {Raw: "12.34.56-rc.1", Major: 12, Minor: 34, Patch: 56, Prerelease: "rc.1"},
		"1.2.3-" + boundaryPrerelease: {Raw: "1.2.3-" + boundaryPrerelease, Major: 1, Minor: 2, Patch: 3, Prerelease: boundaryPrerelease},
	}
	for input, want := range valid {
		if got, err := ParseVersion(input); err != nil || got != want {
			t.Errorf("ParseVersion(%q) = %#v, %v", input, got, err)
		}
	}
	for _, input := range []string{"", "v", "1", "1.2", "1.2.3.4", "1.2.3+build", "1.2.3-", "1.2.3-01", "65536.1.1", " 1.2.3", "1.2.3 secret", "V1.2.3", "1.2.3-" + strings.Repeat("a", 123)} {
		if _, err := ParseVersion(input); !errors.Is(err, ErrInvalidVersion) {
			t.Errorf("ParseVersion(%q) error = %v", input, err)
		}
	}
}

func TestProbeSuccess(t *testing.T) {
	body := &trackedBody{Reader: strings.NewReader(`{"version":"v0.5.7-rc.1"}`)}
	client := testClient(t, doerFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || r.URL.String() != "http://127.0.0.1:11434/api/version" {
			t.Errorf("request = %s %s", r.Method, r.URL)
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("Accept = %q", r.Header.Get("Accept"))
		}
		return &http.Response{StatusCode: 200, Body: body}, nil
	}))
	got, err := client.Probe(context.Background())
	want := provider.ProviderProbe{
		ProviderID:   "ollama-main",
		Kind:         provider.KindOllama,
		Endpoint:     "http://127.0.0.1:11434",
		Health:       provider.HealthReady,
		Version:      provider.VersionInfo{Raw: "0.5.7-rc.1", Minor: 5, Patch: 7, Prerelease: "rc.1"},
		VersionKnown: true,
		ObservedAt:   "2026-09-27T03:01:02.987Z",
	}
	if err != nil || got != want {
		t.Fatalf("Probe() = %#v, %v; want %#v", got, err, want)
	}
	wire, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wire), `"version":"0.5.7-rc.1"`) || strings.Contains(string(wire), `"Major"`) {
		t.Fatalf("probe JSON version is not a scalar string: %s", wire)
	}
	if !body.closed {
		t.Fatal("body not closed")
	}
}

func TestProbeRejectsInvalidResponsesAndCloses(t *testing.T) {
	cases := []string{"", `{}`, `[]`, `{"version":1}`, `{"other":"0.5.7"}`, `{"version":"0.5.7","extra":true}`,
		`{"version":"0.5.7","version":"0.5.8"}`, `{"version":"0.5.7"} {}`, `{"version":"bad"}`, strings.Repeat(" ", MaximumBodySize+1)}
	for _, text := range cases {
		body := &trackedBody{Reader: strings.NewReader(text)}
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) { return &http.Response{StatusCode: 200, Body: body}, nil }))
		if _, err := client.Probe(context.Background()); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("body %q: %v", text[:min(len(text), 40)], err)
		}
		if !body.closed {
			t.Error("body not closed")
		}
	}
}

func TestProbePropagatesContextErrorsFromBodyReadsAndCloses(t *testing.T) {
	t.Run("canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		body := &trackedBody{Reader: readerFunc(func([]byte) (int, error) {
			cancel()
			return 0, errors.New("read failed")
		})}
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
		}))
		if _, err := client.Probe(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("body read error = %v", err)
		}
		if !body.closed {
			t.Fatal("body not closed")
		}
	})

	t.Run("deadline", func(t *testing.T) {
		var body *trackedBody
		client, err := NewWithDependencies(
			Config{ProviderID: "ollama", Endpoint: "http://localhost", Timeout: MinimumTimeout},
			doerFunc(func(r *http.Request) (*http.Response, error) {
				body = &trackedBody{Reader: readerFunc(func([]byte) (int, error) {
					<-r.Context().Done()
					return 0, errors.New("read failed")
				})}
				return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
			}),
			fakeClock{},
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Probe(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("body read error = %v", err)
		}
		if body == nil || !body.closed {
			t.Fatal("body not closed")
		}
	})
}

func TestProbeStableErrorsCancellationAndClosing(t *testing.T) {
	body := &trackedBody{Reader: strings.NewReader("super-secret-body")}
	client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) { return &http.Response{StatusCode: 401, Body: body}, nil }))
	_, err := client.Probe(context.Background())
	if err != ErrHTTPStatus || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("unsafe status error: %q", err)
	}
	if !body.closed {
		t.Fatal("status body not closed")
	}
	client = testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial secret.internal token=secret")
	}))
	if _, err = client.Probe(context.Background()); err != ErrProbeFailed {
		t.Fatalf("network error = %q", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	body = &trackedBody{Reader: strings.NewReader(`{"version":"0.5.7"}`)}
	client = testClient(t, doerFunc(func(r *http.Request) (*http.Response, error) {
		cancel()
		<-r.Context().Done()
		return &http.Response{Body: body}, errors.New("cancel")
	}))
	if _, err = client.Probe(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error = %v", err)
	}
	if !body.closed {
		t.Fatal("cancel body not closed")
	}
}

func TestProbeTimeoutAndPreCancellation(t *testing.T) {
	client, err := NewWithDependencies(Config{ProviderID: "ollama", Endpoint: "http://localhost", Timeout: MinimumTimeout},
		doerFunc(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() }), fakeClock{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Probe(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	client = testClient(t, doerFunc(func(*http.Request) (*http.Response, error) { called = true; return nil, nil }))
	if _, err := client.Probe(ctx); !errors.Is(err, context.Canceled) || called {
		t.Fatalf("pre-cancel = %v, called=%v", err, called)
	}
}

func TestProductionClientRejectsRedirects(t *testing.T) {
	redirected := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/version" {
			http.Redirect(w, r, "/redirected", http.StatusFound)
			return
		}
		redirected = true
		_, _ = io.WriteString(w, `{"version":"0.5.7"}`)
	}))
	defer server.Close()
	client, err := New(Config{ProviderID: "ollama", Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Probe(context.Background()); err != ErrHTTPStatus {
		t.Fatalf("redirect error = %v", err)
	}
	if redirected {
		t.Fatal("redirect followed")
	}
}
