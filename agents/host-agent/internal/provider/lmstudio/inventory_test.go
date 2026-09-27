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

func TestListAvailableModelsNormalizesSortsAndUsesExactRequest(t *testing.T) {
	payload := listJSON(
		`{"id":"Zoo/Model:Latest","object":"model","created":1,"owned_by":"lm studio"}`,
		`{"id":"acme/embed","object":"model"}`,
	)
	body := &trackedBody{Reader: strings.NewReader(payload)}
	client := testClient(t, doerFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.String() != "http://127.0.0.1:1234/v1/models" || request.Body != nil {
			t.Fatalf("request = %s %s body=%v", request.Method, request.URL, request.Body)
		}
		if got := request.Header.Values("Accept"); !reflect.DeepEqual(got, []string{"application/json"}) {
			t.Fatalf("Accept = %#v", got)
		}
		if request.Header.Get("Authorization") != "" {
			t.Fatal("unexpected Authorization header")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
	}))

	models, err := client.ListAvailableModels(context.Background())
	if err != nil {
		t.Fatalf("ListAvailableModels error = %v", err)
	}
	want := []provider.AvailableModel{
		{
			ModelID:       "lmstudio-9dc13cce2cf10c8a9a82d6fa0ef22a1237cea16002ba0806306e397ac901c37c",
			ProviderID:    "lmstudio-main",
			CanonicalName: "acme/embed",
			DisplayName:   "acme/embed",
			State:         provider.AvailableModelStateAvailable,
			Capabilities:  []string{},
			Modalities:    []string{},
		},
		{
			ModelID:        "lmstudio-6627266378f3054ec629e4701b5c1a543e2bb564a7e5831303444b5e1c0122c8",
			ProviderID:     "lmstudio-main",
			CanonicalName:  "Zoo/Model:Latest",
			DisplayName:    "Zoo/Model:Latest",
			State:          provider.AvailableModelStateAvailable,
			Owner:          "lm studio",
			OwnerKnown:     true,
			CreatedAt:      "1970-01-01T00:00:01.000Z",
			CreatedAtKnown: true,
			Capabilities:   []string{},
			Modalities:     []string{},
		},
	}
	if !reflect.DeepEqual(models, want) {
		t.Fatalf("ListAvailableModels = %#v; want %#v", models, want)
	}
	if models[0].Owner != "" || models[0].OwnerKnown || models[0].Capabilities == nil || models[0].Modalities == nil {
		t.Fatalf("absent optional fields or empty claims normalized incorrectly: %#v", models[0])
	}
	wire, err := json.Marshal(models)
	if err != nil {
		t.Fatal(err)
	}
	wantWire := `[{"modelId":"lmstudio-9dc13cce2cf10c8a9a82d6fa0ef22a1237cea16002ba0806306e397ac901c37c","providerId":"lmstudio-main","canonicalName":"acme/embed","displayName":"acme/embed","state":"available","owner":"","ownerKnown":false,"createdAt":"","createdAtKnown":false,"capabilities":[],"modalities":[]},{"modelId":"lmstudio-6627266378f3054ec629e4701b5c1a543e2bb564a7e5831303444b5e1c0122c8","providerId":"lmstudio-main","canonicalName":"Zoo/Model:Latest","displayName":"Zoo/Model:Latest","state":"available","owner":"lm studio","ownerKnown":true,"createdAt":"1970-01-01T00:00:01.000Z","createdAtKnown":true,"capabilities":[],"modalities":[]}]`
	if string(wire) != wantWire {
		t.Fatalf("wire = %s; want %s", wire, wantWire)
	}
	if !body.closed {
		t.Fatal("success body not closed")
	}

	models[0].CanonicalName = "mutated"
	models[0].Capabilities = append(models[0].Capabilities, "mutated")
	models[0].Modalities = append(models[0].Modalities, "mutated")
	body.Reader = strings.NewReader(payload)
	body.closed = false
	again, err := client.ListAvailableModels(context.Background())
	if err != nil || !reflect.DeepEqual(again, want) || !body.closed {
		t.Fatalf("result aliases prior mutation: %#v, %v", again, err)
	}
}

func TestListAvailableModelsEmptyIsNonNil(t *testing.T) {
	client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(listJSON()))}, nil
	}))
	models, err := client.ListAvailableModels(context.Background())
	if err != nil || models == nil || len(models) != 0 {
		t.Fatalf("empty = %#v, %v", models, err)
	}
}

func TestDecodeAvailableModelsStrictShapesAndCanonicalIDs(t *testing.T) {
	invalid := []string{
		"", "null", `[]`, `{}`, `{"object":"list"}`, `{"data":[]}`,
		`{"object":"other","data":[]}`, `{"object":"list","data":null}`,
		`{"object":"list","data":[],"extra":1}`,
		`{"object":"list","object":"list","data":[]}`,
		`{"object":"list","data":[],"data":[]}`,
		`{"object":"list","data":[]} {}`,
		listJSON(`{}`), listJSON(`{"id":null}`), listJSON(`{"id":""}`),
		listJSON(`{"id":"a","extra":1}`), listJSON(`{"id":"a","id":"b"}`),
		listJSON(`{"id":"a","object":"other"}`), listJSON(`{"id":"a","object":"model","object":"model"}`),
		listJSON(`{"id":"a","created":null}`), listJSON(`{"id":"a","created":"1"}`),
		listJSON(`{"id":"a","created":1.1}`), listJSON(`{"id":"a","created":-1}`),
		listJSON(`{"id":"a","created":253402300800}`),
		listJSON(`{"id":"a","owned_by":""}`), listJSON(`{"id":"a","owned_by":1}`),
		listJSON(`{"id":"a","owned_by":null}`), listJSON(`{"id":"a","owned_by":" owner"}`),
		listJSON(`{"id":"a","owned_by":"owner","owned_by":"owner"}`),
		listJSON(`{"id":"a","owned_by":"` + strings.Repeat("a", 257) + `"}`),
		listJSON(`{"id":"a"}`, `{"id":"a"}`),
		listJSON(`{"id":"a//b"}`), listJSON(`{"id":"a/../b"}`),
		listJSON(`{"id":"a?secret=token"}`), listJSON(`{"id":"` + strings.Repeat("a", 257) + `"}`),
	}
	for _, body := range invalid {
		if _, err := decodeAvailableModels([]byte(body), "provider-a"); !errors.Is(err, ErrInvalidListResponse) {
			t.Errorf("decodeAvailableModels(%.100q) = %v; want ErrInvalidListResponse", body, err)
		}
	}

	payload := listJSON(`{"id":"Case/Sensitive","created":0}`)
	a, err := decodeAvailableModels([]byte(payload), "provider-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := decodeAvailableModels([]byte(payload), "provider-a")
	if err != nil {
		t.Fatal(err)
	}
	c, err := decodeAvailableModels([]byte(payload), "provider-b")
	if err != nil {
		t.Fatal(err)
	}
	if a[0].CanonicalName != "Case/Sensitive" || a[0].ModelID != b[0].ModelID || a[0].ModelID == c[0].ModelID {
		t.Fatalf("canonical identity not conservative/deterministic: %#v %#v %#v", a, b, c)
	}
}

func TestDecodeAvailableModelsCountCap(t *testing.T) {
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
	if models, err := decodeAvailableModels(build(MaximumAvailableModels), "x"); err != nil || len(models) != MaximumAvailableModels {
		t.Fatalf("cap result len=%d err=%v", len(models), err)
	}
	if _, err := decodeAvailableModels(build(MaximumAvailableModels+1), "x"); !errors.Is(err, ErrInvalidListResponse) {
		t.Fatalf("cap+1 error = %v", err)
	}
}

func TestListAvailableModelsStableErrorsRedactionAndClose(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   *trackedBody
		want   error
	}{
		{"status", http.StatusUnauthorized, &trackedBody{Reader: strings.NewReader("secret token")}, ErrListHTTPStatus},
		{"malformed", http.StatusOK, &trackedBody{Reader: strings.NewReader(`{"object":"list","data":null}`)}, ErrInvalidListResponse},
		{"oversize", http.StatusOK, &trackedBody{Reader: strings.NewReader(strings.Repeat("x", MaximumListBodySize+1))}, ErrListResponseTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: test.status, Body: test.body}, nil
			}))
			_, err := client.ListAvailableModels(context.Background())
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
	if ErrListFailed == ErrResponseFailed || ErrListHTTPStatus == ErrResponseStatus || ErrListResponseTooLarge == ErrResponseTooLarge || ErrInvalidListResponse == ErrResponseInvalid {
		t.Fatal("inventory sentinels must be distinct from probe sentinels")
	}
}

func TestListAvailableModelsTransportReadAndCancellation(t *testing.T) {
	t.Run("transport", func(t *testing.T) {
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial secret.internal token=secret")
		}))
		if _, err := client.ListAvailableModels(context.Background()); err != ErrListFailed {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("nil response", func(t *testing.T) {
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil }))
		if _, err := client.ListAvailableModels(context.Background()); err != ErrListFailed {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("nil body", func(t *testing.T) {
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK}, nil
		}))
		if _, err := client.ListAvailableModels(context.Background()); err != ErrListFailed {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("response and error closes body", func(t *testing.T) {
		body := &trackedBody{Reader: strings.NewReader("secret")}
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: body}, errors.New("transport secret")
		}))
		if _, err := client.ListAvailableModels(context.Background()); err != ErrListFailed || !body.closed {
			t.Fatalf("error=%v closed=%v", err, body.closed)
		}
	})
	t.Run("transport cancellation closes body", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		body := &trackedBody{Reader: strings.NewReader("secret")}
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			cancel()
			return &http.Response{StatusCode: http.StatusOK, Body: body}, context.Canceled
		}))
		if _, err := client.ListAvailableModels(ctx); !errors.Is(err, context.Canceled) || !body.closed {
			t.Fatalf("error=%v closed=%v", err, body.closed)
		}
	})
	t.Run("read failure", func(t *testing.T) {
		body := &trackedBody{Reader: readerFunc(func([]byte) (int, error) { return 0, errors.New("secret read") })}
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
		}))
		if _, err := client.ListAvailableModels(context.Background()); err != ErrListFailed || !body.closed {
			t.Fatalf("error=%v closed=%v", err, body.closed)
		}
	})
	t.Run("pre-canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		called := false
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) { called = true; return nil, nil }))
		if _, err := client.ListAvailableModels(ctx); !errors.Is(err, context.Canceled) || called {
			t.Fatalf("error=%v called=%v", err, called)
		}
	})
	t.Run("read canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		body := &trackedBody{Reader: readerFunc(func([]byte) (int, error) { cancel(); return 0, errors.New("secret") })}
		client := testClient(t, doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
		}))
		if _, err := client.ListAvailableModels(ctx); !errors.Is(err, context.Canceled) || !body.closed {
			t.Fatalf("error=%v closed=%v", err, body.closed)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		var body *trackedBody
		client, err := NewWithDependencies(Config{ProviderID: "x", Endpoint: "http://localhost", Timeout: MinimumTimeout}, doerFunc(func(request *http.Request) (*http.Response, error) {
			body = &trackedBody{Reader: readerFunc(func([]byte) (int, error) { <-request.Context().Done(); return 0, errors.New("read") })}
			return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
		}), fakeClock{time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.ListAvailableModels(context.Background()); !errors.Is(err, context.DeadlineExceeded) || body == nil || !body.closed {
			t.Fatalf("error=%v body=%#v", err, body)
		}
	})
}

func TestListAvailableModelsProductionClientRejectsRedirects(t *testing.T) {
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
	if _, err := client.ListAvailableModels(context.Background()); err != ErrListHTTPStatus {
		t.Fatalf("redirect error = %v", err)
	}
	if redirected {
		t.Fatal("redirect followed")
	}
}
