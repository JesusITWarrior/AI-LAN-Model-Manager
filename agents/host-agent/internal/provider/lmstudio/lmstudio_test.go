package lmstudio

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
)

type fakeClock struct{ value time.Time }

func (clock fakeClock) Now() time.Time { return clock.value }

type doerFunc func(*http.Request) (*http.Response, error)

func (doer doerFunc) Do(request *http.Request) (*http.Response, error) { return doer(request) }

type readerFunc func([]byte) (int, error)

func (reader readerFunc) Read(buffer []byte) (int, error) { return reader(buffer) }

type trackedBody struct {
	io.Reader
	closed bool
}

func (body *trackedBody) Close() error {
	body.closed = true
	return nil
}

func testClient(t *testing.T, doer HTTPDoer) *Client {
	t.Helper()
	client, err := NewWithDependencies(
		Config{ProviderID: "lmstudio-main", Endpoint: "http://127.0.0.1:1234/"},
		doer,
		fakeClock{time.Date(2026, 9, 26, 22, 1, 2, 987654321, time.FixedZone("test", -5*60*60))},
	)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func listJSON(entries ...string) string {
	return `{"object":"list","data":[` + strings.Join(entries, ",") + `]}`
}

func TestNormalizeEndpoint(t *testing.T) {
	valid := map[string]string{
		"http://localhost":          "http://localhost",
		"http://localhost:1/":       "http://localhost:1",
		"https://host-name:65535":   "https://host-name:65535",
		"http://127.0.0.1:1234":     "http://127.0.0.1:1234",
		"https://[::1]":             "https://[::1]",
		"https://[2001:db8::1]:443": "https://[2001:db8::1]:443",
	}
	for input, want := range valid {
		got, err := NormalizeEndpoint(input)
		if err != nil || got != want {
			t.Errorf("NormalizeEndpoint(%q) = %q, %v; want %q", input, got, err, want)
		}
	}

	invalid := []string{
		"", " http://localhost", "http://localhost ", "ftp://localhost", "//localhost",
		"http://user@localhost", "http://user:secret@localhost", "http://localhost?x=1",
		"http://localhost?", "http://localhost#fragment", "http://localhost/api",
		"http://localhost/%2F", "http://localhost:", "http://localhost:0",
		"http://localhost:65536", "http://localhost:not-a-port", "http://bad_host",
		"http://-bad", "http://bad-", "http://999.999.999.999", "http://[::1]:0",
		"http://[::1]:65536", "http://[::1]:bad", "http://[fe80::1%25eth0]:1234",
	}
	for _, input := range invalid {
		if _, err := NormalizeEndpoint(input); !errors.Is(err, provider.ErrInvalidEndpoint) {
			t.Errorf("NormalizeEndpoint(%q) error = %v; want ErrInvalidEndpoint", input, err)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	doer := doerFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("unused") })
	for _, id := range []string{"a", "UPPER", "a:b.c_d-e", strings.Repeat("a", 128)} {
		if _, err := NewWithDependencies(Config{ProviderID: id, Endpoint: "http://localhost:1234"}, doer, fakeClock{}); err != nil {
			t.Errorf("valid id %q rejected: %v", id, err)
		}
	}
	for _, id := range []string{"", "-lead", strings.Repeat("a", 129), "has/slash", "has space", "é"} {
		if _, err := NewWithDependencies(Config{ProviderID: id, Endpoint: "http://localhost:1234"}, doer, fakeClock{}); !errors.Is(err, provider.ErrInvalidProviderID) {
			t.Errorf("id %q error = %v; want ErrInvalidProviderID", id, err)
		}
	}
	for _, timeout := range []time.Duration{-time.Second, time.Nanosecond, 99 * time.Millisecond, MaximumTimeout + 1} {
		if _, err := NewWithDependencies(Config{ProviderID: "x", Endpoint: "http://localhost", Timeout: timeout}, doer, fakeClock{}); !errors.Is(err, ErrInvalidTimeout) {
			t.Errorf("timeout %s error = %v; want ErrInvalidTimeout", timeout, err)
		}
	}
	for _, timeout := range []time.Duration{0, MinimumTimeout, MaximumTimeout} {
		client, err := NewWithDependencies(Config{ProviderID: "x", Endpoint: "http://localhost", Timeout: timeout}, doer, fakeClock{})
		if err != nil {
			t.Errorf("timeout %s rejected: %v", timeout, err)
		} else if timeout == 0 && client.timeout != DefaultTimeout {
			t.Errorf("default timeout = %s; want %s", client.timeout, DefaultTimeout)
		}
	}
	if _, err := NewWithDependencies(Config{ProviderID: "x", Endpoint: "http://localhost"}, nil, fakeClock{}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("nil doer error = %v", err)
	}
	if _, err := NewWithDependencies(Config{ProviderID: "x", Endpoint: "http://localhost"}, doer, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("nil clock error = %v", err)
	}
}

func TestProbeSuccessExactRequestUnknownVersionAndClock(t *testing.T) {
	body := &trackedBody{Reader: strings.NewReader(listJSON(
		`{"id":"qwen/qwen3-4b","object":"model","created":0,"owned_by":"lmstudio-community"}`,
		`{"id":"local:latest"}`,
	))}
	client := testClient(t, doerFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.String() != "http://127.0.0.1:1234/v1/models" || request.Body != nil {
			t.Errorf("request = %s %s body=%v", request.Method, request.URL, request.Body)
		}
		if got := request.Header.Values("Accept"); !reflect.DeepEqual(got, []string{"application/json"}) {
			t.Errorf("Accept = %#v", got)
		}
		if request.Header.Get("Authorization") != "" {
			t.Error("unexpected Authorization header")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       body,
			Header: http.Header{
				"X-LMStudio-Version": []string{"9.9.9"},
				"X-LS-Version":       []string{"8.8.8"},
			},
		}, nil
	}))

	got, err := client.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe error = %v", err)
	}
	want := provider.ProviderProbe{
		ProviderID:   "lmstudio-main",
		Kind:         provider.KindLMStudio,
		Endpoint:     "http://127.0.0.1:1234",
		Health:       provider.HealthReady,
		Version:      provider.UnknownVersion(),
		VersionKnown: false,
		ObservedAt:   "2026-09-27T03:01:02.987Z",
	}
	if got != want {
		t.Fatalf("Probe = %#v; want %#v", got, want)
	}
	if got.Version != (provider.VersionInfo{}) {
		t.Fatalf("unknown Version = %#v; want zero", got.Version)
	}
	wire, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), "models") || strings.Contains(string(wire), "qwen") {
		t.Fatalf("probe leaked inventory: %s", wire)
	}
	if !body.closed {
		t.Fatal("success body not closed")
	}
}

func TestValidateModelsAcceptedShapes(t *testing.T) {
	for _, body := range []string{
		listJSON(),
		listJSON(`{"id":"a"}`),
		listJSON(`{"id":"a","object":"model"}`),
		listJSON(`{"id":"org/model-name:latest","object":"model","created":123,"owned_by":"lm studio"}`),
		`{"data":[],"object":"list"}`,
	} {
		if err := validateModels([]byte(body)); err != nil {
			t.Errorf("validateModels(%q) = %v; want nil", body, err)
		}
	}
}

func TestValidateModelsRejectsMalformedShapes(t *testing.T) {
	cases := []string{
		"", " ", "null", `[]`, `{}`, `{"object":"list"}`, `{"data":[]}`,
		`{"object":"garbage","data":[]}`, `{"object":null,"data":[]}`,
		`{"object":"list","data":null}`, `{"object":"list","data":{}}`,
		`{"object":"list","data":[],"extra":1}`,
		`{"object":"list","object":"list","data":[]}`,
		`{"object":"list","data":[],"data":[]}`,
		`{"object":"list","data":[]} {}`,
		listJSON(`{}`), listJSON(`{"object":"model"}`), listJSON(`{"id":""}`),
		listJSON(`{"id":" has-space"}`), listJSON(`{"id":"../unsafe"}`),
		listJSON(`{"id":"a?token=secret"}`), listJSON(`{"id":1}`), listJSON(`{"id":null}`),
		listJSON(`{"id":"a","object":"garbage"}`), listJSON(`{"id":"a","object":null}`),
		listJSON(`{"id":"a","created":-1}`), listJSON(`{"id":"a","created":1.5}`),
		listJSON(`{"id":"a","created":"1"}`), listJSON(`{"id":"a","owned_by":""}`),
		listJSON(`{"id":"a","owned_by":1}`), listJSON(`{"id":"a","extra":true}`),
		listJSON(`{"id":"a","id":"b"}`), listJSON(`{"id":"a","object":"model","object":"model"}`),
		listJSON(`{"id":"a"}`, `{"id":"a"}`),
		listJSON(`{"id":"` + strings.Repeat("a", 257) + `"}`),
	}
	for _, body := range cases {
		if err := validateModels([]byte(body)); !errors.Is(err, ErrResponseInvalid) {
			t.Errorf("validateModels(%.100q) = %v; want ErrResponseInvalid", body, err)
		}
	}
}

func TestValidateModelsCountCapIndependentOfBodyLimit(t *testing.T) {
	build := func(count int) []byte {
		var builder strings.Builder
		builder.WriteString(`{"object":"list","data":[`)
		for index := 0; index < count; index++ {
			if index > 0 {
				builder.WriteByte(',')
			}
			fmt.Fprintf(&builder, `{"id":"m%d"}`, index)
		}
		builder.WriteString(`]}`)
		return []byte(builder.String())
	}
	if err := validateModels(build(MaximumModels)); err != nil {
		t.Fatalf("MaximumModels rejected: %v", err)
	}
	if err := validateModels(build(MaximumModels + 1)); !errors.Is(err, ErrResponseInvalid) {
		t.Fatalf("MaximumModels+1 error = %v; want ErrResponseInvalid", err)
	}
}

func TestProbeProtocolErrorsAreStableAndBodiesClose(t *testing.T) {
	tests := []struct {
		name string
		doer HTTPDoer
		want error
		body *trackedBody
	}{
		{
			name: "non-200",
			body: &trackedBody{Reader: strings.NewReader("secret status body")},
			want: ErrResponseStatus,
		},
		{
			name: "malformed",
			body: &trackedBody{Reader: strings.NewReader(`{"object":"list","data":null}`)},
			want: ErrResponseInvalid,
		},
		{
			name: "oversize",
			body: &trackedBody{Reader: strings.NewReader(strings.Repeat("x", MaximumBodySize+1))},
			want: ErrResponseTooLarge,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status := http.StatusOK
			if test.name == "non-200" {
				status = http.StatusUnauthorized
			}
			client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Body: test.body}, nil
			}))
			_, err := client.Probe(context.Background())
			if err != test.want {
				t.Fatalf("error = %v; want exact %v", err, test.want)
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "127.0.0.1") {
				t.Fatalf("error leaked details: %v", err)
			}
			if !test.body.closed {
				t.Fatal("body not closed")
			}
		})
	}
	if ErrResponseTooLarge == ErrResponseInvalid || ErrResponseTooLarge == ErrResponseFailed {
		t.Fatal("oversize error must be distinct")
	}
}

func TestProbeTransportNilAndResponseError(t *testing.T) {
	t.Run("transport redacted", func(t *testing.T) {
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial secret.internal token=secret")
		}))
		if _, err := client.Probe(context.Background()); err != ErrResponseFailed {
			t.Fatalf("error = %v; want exact ErrResponseFailed", err)
		}
	})
	t.Run("nil response", func(t *testing.T) {
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil }))
		if _, err := client.Probe(context.Background()); err != ErrResponseFailed {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("nil body", func(t *testing.T) {
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK}, nil
		}))
		if _, err := client.Probe(context.Background()); err != ErrResponseFailed {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("response and error closes body", func(t *testing.T) {
		body := &trackedBody{Reader: strings.NewReader("secret")}
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: body}, errors.New("transport secret")
		}))
		if _, err := client.Probe(context.Background()); err != ErrResponseFailed {
			t.Fatalf("error = %v", err)
		}
		if !body.closed {
			t.Fatal("response+error body not closed")
		}
	})
}

func TestProbeCancellationAndReadFailures(t *testing.T) {
	t.Run("pre-canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		called := false
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			called = true
			return nil, nil
		}))
		if _, err := client.Probe(ctx); !errors.Is(err, context.Canceled) || called {
			t.Fatalf("error = %v, transport called = %v", err, called)
		}
	})
	t.Run("do canceled with response", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		body := &trackedBody{Reader: strings.NewReader("secret")}
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			cancel()
			return &http.Response{Body: body}, context.Canceled
		}))
		if _, err := client.Probe(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
		if !body.closed {
			t.Fatal("body not closed")
		}
	})
	t.Run("read canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		body := &trackedBody{Reader: readerFunc(func([]byte) (int, error) {
			cancel()
			return 0, errors.New("secret read failure")
		})}
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
		}))
		if _, err := client.Probe(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
		if !body.closed {
			t.Fatal("body not closed")
		}
	})
	t.Run("ordinary read failure redacted", func(t *testing.T) {
		body := &trackedBody{Reader: readerFunc(func([]byte) (int, error) {
			return 0, errors.New("secret read failure")
		})}
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
		}))
		if _, err := client.Probe(context.Background()); err != ErrResponseFailed {
			t.Fatalf("error = %v; want exact ErrResponseFailed", err)
		}
		if !body.closed {
			t.Fatal("body not closed")
		}
	})
	t.Run("deadline during read", func(t *testing.T) {
		var body *trackedBody
		client, err := NewWithDependencies(
			Config{ProviderID: "x", Endpoint: "http://localhost", Timeout: MinimumTimeout},
			doerFunc(func(request *http.Request) (*http.Response, error) {
				body = &trackedBody{Reader: readerFunc(func([]byte) (int, error) {
					<-request.Context().Done()
					return 0, errors.New("read stopped")
				})}
				return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
			}),
			fakeClock{},
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Probe(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v; want DeadlineExceeded", err)
		}
		if body == nil || !body.closed {
			t.Fatal("body not closed")
		}
	})
}

func TestProductionClientRejectsRedirects(t *testing.T) {
	redirected := false
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/models" {
			http.Redirect(writer, request, "/secret", http.StatusFound)
			return
		}
		redirected = true
		_, _ = io.WriteString(writer, listJSON())
	}))
	defer server.Close()

	client, err := New(Config{ProviderID: "x", Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Probe(context.Background()); err != ErrResponseStatus {
		t.Fatalf("redirect error = %v; want ErrResponseStatus", err)
	}
	if redirected {
		t.Fatal("redirect was followed")
	}
}
