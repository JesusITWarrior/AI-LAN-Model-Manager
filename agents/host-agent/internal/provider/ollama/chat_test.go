package ollama

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func chatInput() ChatRequest {
	return ChatRequest{RequestID: "request-1", Model: "qwen:latest", Messages: []ChatMessage{{Role: "user", Content: "hello"}}, MaxRequestBytes: MaximumChatRequestSize, MaxResponseBytes: MaximumChatResponseSize}
}
func TestChatUsesOnlyConfiguredLoopbackAndSanitizesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" || r.Method != http.MethodPost {
			t.Fatalf("request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "" {
			t.Fatal("unexpected authorization")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"qwen:latest","created_at":"2026-09-29T10:00:00Z","message":{"role":"assistant","content":"world"},"done":true,"done_reason":"stop","total_duration":1,"load_duration":1,"prompt_eval_count":2,"prompt_eval_duration":1,"eval_count":3,"eval_duration":1}`))
	}))
	defer server.Close()
	client, err := New(Config{ProviderID: "ollama-1", Endpoint: server.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	value, err := client.Chat(context.Background(), chatInput())
	if err != nil || value.ID != "request-1" || value.Choices[0].Message.Content != "world" || value.Usage.TotalTokens != 5 {
		t.Fatalf("value=%#v err=%v", value, err)
	}
}
func TestChatBoundsMalformedOversizedTimeoutAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		delay      time.Duration
		max        uint64
		want       error
	}{{"malformed", `{"model":"qwen:latest","message":{"role":"assistant","content":"x"},"done":true,"extra":1}`, 0, 1024, ErrInvalidChatResponse}, {"oversized", `{"model":"qwen:latest","created_at":"x","message":{"role":"assistant","content":"` + strings.Repeat("x", 256) + `"},"done":true}`, 0, 64, ErrChatResponseTooLarge}, {"timeout", `{}`, 300 * time.Millisecond, 1024, context.DeadlineExceeded}} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(tc.delay)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			client, err := New(Config{ProviderID: "ollama-1", Endpoint: server.URL, Timeout: 100 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			input := chatInput()
			input.MaxResponseBytes = tc.max
			_, err = client.Chat(context.Background(), input)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err=%v want=%v", err, tc.want)
			}
		})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer server.Close()
	client, _ := New(Config{ProviderID: "ollama-1", Endpoint: server.URL, Timeout: time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := client.Chat(ctx, chatInput()); done <- err }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel err=%v", err)
	}
}
