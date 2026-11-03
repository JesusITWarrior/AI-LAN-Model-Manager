package ollama

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
)

const streamDelta = `{"model":"fixture:latest","created_at":"2026-01-01T00:00:00Z","message":{"role":"assistant","content":"世界🙂"},"done":false}`
const streamTerminal = `{"model":"fixture:latest","created_at":"2026-01-01T00:00:00Z","message":{"role":"assistant","content":""},"done":true,"done_reason":"stop","total_duration":1,"load_duration":1,"prompt_eval_count":2,"prompt_eval_duration":1,"eval_count":3,"eval_duration":1}`

func streamInput() ChatRequest {
	return ChatRequest{RequestID: "stream-1", Model: "fixture:latest", Messages: []ChatMessage{{Role: "user", Content: "synthetic input"}}, MaxRequestBytes: MaximumChatRequestSize, MaxResponseBytes: MaximumChatResponseSize}
}
func streamClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := New(Config{ProviderID: "fixture-provider", Endpoint: server.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return client
}
func TestChatStreamFragmentedUTF8AllowlistedChunks(t *testing.T) {
	client := streamClient(t, func(w http.ResponseWriter, r *http.Request) {
		var request map[string]json.RawMessage
		if r.Method != "POST" || r.URL.Path != "/api/chat" || r.Header.Get("Authorization") != "" || r.Header.Get("Accept") != "application/x-ndjson" || json.NewDecoder(r.Body).Decode(&request) != nil || string(request["stream"]) != "true" || len(request) != 3 {
			t.Error("unexpected request")
		}
		w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		for _, b := range []byte(streamDelta + "\r\n" + streamTerminal) {
			_, _ = w.Write([]byte{b})
			w.(http.Flusher).Flush()
		}
	})
	var chunks []ChatChunk
	err := client.ChatStream(context.Background(), streamInput(), func(ctx context.Context, chunk ChatChunk) error { chunks = append(chunks, chunk); return nil })
	if err != nil || len(chunks) != 2 || chunks[0].Choices[0].Delta.Content != "世界🙂" || chunks[0].Usage != nil || chunks[0].Choices[0].FinishReason != nil || chunks[1].Usage.TotalTokens != 5 || *chunks[1].Choices[0].FinishReason != "stop" {
		t.Fatalf("chunks=%#v err=%v", chunks, err)
	}
	raw, _ := json.Marshal(chunks)
	for _, private := range []string{"created_at", "duration", "done", "error", "thinking"} {
		if strings.Contains(string(raw), private) {
			t.Fatalf("provider field leaked: %s", raw)
		}
	}
}

func TestChatStreamRejectsInvalidFramesAndMissingTerminal(t *testing.T) {
	cases := []struct {
		name, body string
		want       error
		count      int
	}{
		{"empty", "", ErrInvalidChatResponse, 0},
		{"no-terminal", streamDelta + "\n", ErrInvalidChatResponse, 1},
		{"malformed", "{\n", ErrInvalidChatResponse, 0},
		{"blank", "\n", ErrInvalidChatResponse, 0},
		{"unknown", strings.Replace(streamDelta, `"done":false`, `"done":false,"private":"secret"`, 1), ErrInvalidChatResponse, 0},
		{"error", `{"error":"private diagnostic /secret"}`, ErrInvalidChatResponse, 0},
		{"duplicate", strings.Replace(streamDelta, `"done":false`, `"done":false,"done":false`, 1), ErrInvalidChatResponse, 0},
		{"escaped-duplicate", strings.Replace(streamDelta, `"done":false`, `"done":false,"\u0064one":false`, 1), ErrInvalidChatResponse, 0},
		{"message-duplicate", strings.Replace(streamDelta, `"role":"assistant"`, `"role":"assistant","role":"assistant"`, 1), ErrInvalidChatResponse, 0},
		{"message-extra", strings.Replace(streamDelta, `"role":"assistant"`, `"role":"assistant","thinking":"secret"`, 1), ErrInvalidChatResponse, 0},
		{"wrong-model", strings.Replace(streamDelta, "fixture:latest", "other:latest", 1), ErrInvalidChatResponse, 0},
		{"null-done", strings.Replace(streamDelta, `"done":false`, `"done":null`, 1), ErrInvalidChatResponse, 0},
		{"null-content", strings.Replace(streamDelta, `"content":"世界🙂"`, `"content":null`, 1), ErrInvalidChatResponse, 0},
		{"invalid-utf8", strings.Replace(streamDelta, "世界🙂", string([]byte{0xff}), 1), ErrInvalidChatResponse, 0},
		{"two-json", streamDelta + streamDelta, ErrInvalidChatResponse, 0},
		{"terminal-missing-fields", strings.Replace(streamDelta, `"done":false`, `"done":true`, 1), ErrInvalidChatResponse, 0},
		{"terminal-bad-reason", strings.Replace(streamTerminal, `"stop"`, `"error"`, 1), ErrInvalidChatResponse, 0},
		{"terminal-bad-count", strings.Replace(streamTerminal, `"eval_count":3`, `"eval_count":-1`, 1), ErrInvalidChatResponse, 0},
		{"terminal-overflow", strings.Replace(streamTerminal, `"eval_count":3`, `"eval_count":18446744073709551615`, 1), ErrInvalidChatResponse, 0},
		{"duplicate-terminal", streamTerminal + "\n" + streamTerminal + "\n", ErrInvalidChatResponse, 0},
		{"post-terminal-delta", streamTerminal + "\n" + streamDelta + "\n", ErrInvalidChatResponse, 0},
		{"post-terminal-junk", streamTerminal + "\nprivate", ErrInvalidChatResponse, 0},
		{"frame-overflow", strings.Repeat("x", MaximumChatStreamFrameSize+1), ErrChatStreamFrameTooLarge, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := streamClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/x-ndjson")
				_, _ = io.WriteString(w, tc.body)
			})
			count := 0
			err := client.ChatStream(context.Background(), streamInput(), func(context.Context, ChatChunk) error { count++; return nil })
			if !errors.Is(err, tc.want) || count != tc.count || strings.Contains(err.Error(), "private") {
				t.Fatalf("count=%d err=%v", count, err)
			}
		})
	}
}

func TestChatStreamExactFrameAndTotalLimits(t *testing.T) {
	frame := strings.Replace(streamDelta, "世界🙂", strings.Repeat("x", MaximumChatStreamFrameSize-len(streamDelta)+len("世界🙂")), 1)
	body := frame + "\n" + streamTerminal + "\n"
	for _, tc := range []struct {
		name  string
		body  string
		limit uint64
		want  error
	}{
		{"exact", body, uint64(len(body)), nil},
		{"total-over", body, uint64(len(body) - 1), ErrChatResponseTooLarge},
		{"frame-over", strings.Replace(frame, `"content":"`, `"content":"x`, 1) + "\n", MaximumChatResponseSize, ErrChatStreamFrameTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := streamClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/x-ndjson")
				_, _ = io.WriteString(w, tc.body)
			})
			input := streamInput()
			input.MaxResponseBytes = tc.limit
			err := client.ChatStream(context.Background(), input, func(context.Context, ChatChunk) error { return nil })
			if !errors.Is(err, tc.want) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestChatStreamCancellationBlockedReadAndEmitter(t *testing.T) {
	for _, mode := range []string{"read", "emitter", "deadline", "terminal-awaits-eof"} {
		t.Run(mode, func(t *testing.T) {
			ready := make(chan struct{})
			client := streamClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/x-ndjson")
				if mode == "emitter" {
					_, _ = io.WriteString(w, streamDelta+"\n")
				} else if mode == "terminal-awaits-eof" {
					_, _ = io.WriteString(w, streamTerminal+"\n")
				}
				w.(http.Flusher).Flush()
				close(ready)
				<-r.Context().Done()
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "deadline" {
				client.timeout = 100 * time.Millisecond
			}
			entered := make(chan struct{})
			done := make(chan error, 1)
			var count atomic.Int32
			go func() {
				done <- client.ChatStream(ctx, streamInput(), func(ctx context.Context, chunk ChatChunk) error {
					count.Add(1)
					close(entered)
					<-ctx.Done()
					return ctx.Err()
				})
			}()
			<-ready
			if mode == "emitter" {
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("emitter not entered")
				}
			}
			if mode != "deadline" {
				cancel()
			}
			select {
			case err := <-done:
				want := context.Canceled
				if mode == "deadline" {
					want = context.DeadlineExceeded
				}
				if !errors.Is(err, want) {
					t.Fatalf("err=%v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("cancellation stalled")
			}
			if mode == "terminal-awaits-eof" && count.Load() != 0 {
				t.Fatal("premature terminal")
			}
		})
	}
}

type streamDoer func(*http.Request) (*http.Response, error)

func (f streamDoer) Do(r *http.Request) (*http.Response, error) { return f(r) }

type streamTrackedBody struct {
	reader        io.Reader
	reads, closes atomic.Int32
}

func (b *streamTrackedBody) Read(p []byte) (int, error) { b.reads.Add(1); return b.reader.Read(p) }
func (b *streamTrackedBody) Close() error               { b.closes.Add(1); return nil }

func TestChatStreamBackpressureCallbackErrorAndBodyClose(t *testing.T) {
	body := &streamTrackedBody{reader: strings.NewReader(streamDelta + "\n" + strings.Repeat(streamDelta+"\n", 100))}
	client, err := NewWithDependencies(Config{ProviderID: "fixture-provider", Endpoint: "http://127.0.0.1:12345", Timeout: time.Second}, streamDoer(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/x-ndjson"}}, Body: body}, nil
	}), provider.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("consumer stopped")
	err = client.ChatStream(context.Background(), streamInput(), func(context.Context, ChatChunk) error {
		reads := body.reads.Load()
		time.Sleep(20 * time.Millisecond)
		if body.reads.Load() != reads || reads != 1 {
			t.Error("read ahead beyond fixed buffer")
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) || body.closes.Load() != 1 {
		t.Fatalf("err=%v closes=%d", err, body.closes.Load())
	}
}

func TestChatStreamStrictRequestValidation(t *testing.T) {
	client := streamClient(t, func(http.ResponseWriter, *http.Request) { t.Error("invalid request reached provider") })
	nan := math.NaN()
	inf := math.Inf(1)
	zero := uint64(0)
	for _, mutate := range []func(*ChatRequest){
		func(r *ChatRequest) { r.RequestID = "bad\nidentity" }, func(r *ChatRequest) { r.Model = "bad model" },
		func(r *ChatRequest) { r.Messages = nil }, func(r *ChatRequest) { r.Messages[0].Role = "invalid" },
		func(r *ChatRequest) { r.Messages[0].Content = "\x00" }, func(r *ChatRequest) { r.Messages[0].Content = string([]byte{0xff}) },
		func(r *ChatRequest) { r.Temperature = &nan }, func(r *ChatRequest) { r.Temperature = &inf }, func(r *ChatRequest) { r.MaxTokens = &zero },
		func(r *ChatRequest) { r.MaxRequestBytes = 1 }, func(r *ChatRequest) { r.MaxResponseBytes = 0 },
	} {
		input := streamInput()
		mutate(&input)
		if err := client.ChatStream(context.Background(), input, func(context.Context, ChatChunk) error { return nil }); !errors.Is(err, ErrChatFailed) {
			t.Fatalf("err=%v", err)
		}
	}
	if err := client.ChatStream(context.Background(), streamInput(), nil); !errors.Is(err, ErrChatFailed) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.ChatStream(ctx, streamInput(), func(context.Context, ChatChunk) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestChatStreamHTTPFailuresRedacted(t *testing.T) {
	for _, tc := range []struct {
		name, media string
		status      int
		want        error
	}{{"status", "application/x-ndjson", 500, ErrChatHTTPStatus}, {"media", "application/json", 200, ErrInvalidChatResponse}, {"redirect", "application/x-ndjson", 302, ErrChatHTTPStatus}} {
		t.Run(tc.name, func(t *testing.T) {
			client := streamClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.media)
				w.Header().Set("Location", "http://example.invalid/private")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, `{"error":"private details"}`)
			})
			if err := client.ChatStream(context.Background(), streamInput(), func(context.Context, ChatChunk) error { return nil }); !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
		})
	}
}

type streamFailingReader struct{}

func (streamFailingReader) Read([]byte) (int, error) {
	return 0, errors.New("private provider body diagnostic")
}

func TestChatStreamTransportAndBodyErrorsAreRedactedAndClosed(t *testing.T) {
	for _, mode := range []string{"transport", "body", "after-terminal"} {
		t.Run(mode, func(t *testing.T) {
			var reader io.Reader = streamFailingReader{}
			if mode == "after-terminal" {
				reader = io.MultiReader(strings.NewReader(streamTerminal+"\n"), reader)
			}
			body := &streamTrackedBody{reader: reader}
			client, err := NewWithDependencies(Config{ProviderID: "fixture-provider", Endpoint: "http://127.0.0.1:12345", Timeout: time.Second}, streamDoer(func(*http.Request) (*http.Response, error) {
				response := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/x-ndjson"}}, Body: body}
				if mode == "transport" {
					return response, errors.New("private transport diagnostic")
				}
				return response, nil
			}), provider.SystemClock{})
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			err = client.ChatStream(context.Background(), streamInput(), func(context.Context, ChatChunk) error { count++; return nil })
			want := ErrInvalidChatResponse
			if mode == "transport" {
				want = ErrChatFailed
			}
			if !errors.Is(err, want) || strings.Contains(err.Error(), "private") || count != 0 || body.closes.Load() != 1 {
				t.Fatalf("err=%v count=%d closes=%d", err, count, body.closes.Load())
			}
		})
	}
}

func TestChatStreamTerminalExactlyOnceAndCallbackError(t *testing.T) {
	sentinel := errors.New("terminal consumer failure")
	for _, ending := range []string{"", "\n"} {
		for _, fail := range []bool{false, true} {
			client := streamClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/x-ndjson")
				_, _ = io.WriteString(w, streamTerminal+ending)
			})
			count := 0
			err := client.ChatStream(context.Background(), streamInput(), func(context.Context, ChatChunk) error {
				count++
				if fail {
					return sentinel
				}
				return nil
			})
			var want error
			if fail {
				want = sentinel
			}
			if !errors.Is(err, want) || count != 1 {
				t.Fatalf("err=%v count=%d", err, count)
			}
		}
	}
}

func TestChatStreamRejectsNonlocalOrInvalidClient(t *testing.T) {
	doer := streamDoer(func(*http.Request) (*http.Response, error) {
		t.Error("invalid client contacted provider")
		return nil, nil
	})
	client, err := NewWithDependencies(Config{ProviderID: "fixture-provider", Endpoint: "http://192.0.2.1:12345", Timeout: time.Second}, doer, provider.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*Client{nil, {}, client} {
		if err := c.ChatStream(context.Background(), streamInput(), func(context.Context, ChatChunk) error { return nil }); !errors.Is(err, ErrChatFailed) {
			t.Fatalf("err=%v", err)
		}
	}
}

func TestChatStreamRequestOptionsAndCanonicalModel(t *testing.T) {
	temperature := 0.5
	maxTokens := uint64(7)
	client := streamClient(t, func(w http.ResponseWriter, r *http.Request) {
		var raw map[string]json.RawMessage
		if json.NewDecoder(r.Body).Decode(&raw) != nil || len(raw) != 4 || string(raw["model"]) != `"fixture:latest"` || string(raw["options"]) != `{"num_predict":7,"temperature":0.5}` {
			t.Error("unexpected request options")
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		_, _ = io.WriteString(w, streamTerminal+"\n")
	})
	input := streamInput()
	input.Model = "FIXTURE:latest"
	input.Temperature = &temperature
	input.MaxTokens = &maxTokens
	if err := client.ChatStream(context.Background(), input, func(context.Context, ChatChunk) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestChatStreamStrictRFC3339Timestamps(t *testing.T) {
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{"2026-01-01T00:00:00Z", true},
		{"2024-02-29T23:59:59.123456789Z", true},
		{"2026-01-01T12:34:56.1+05:30", true},
		{"2026-01-01T12:34:56-23:59", true},
		{"2026-01-01T0:00:00Z", false},
		{"2026-01-01T00:00:00,123Z", false},
		{"2026-01-01T00:00:00+24:00", false},
		{"2026-01-01T00:00:00-24:00", false},
		{"2026-01-01T00:00:00+00:60", false},
		{"2026-01-01T00:00:00-00:60", false},
		{"2026-02-29T00:00:00Z", false},
		{"2026-04-31T00:00:00Z", false},
		{"2026-00-01T00:00:00Z", false},
		{"2026-01-00T00:00:00Z", false},
		{"2026-01-01T24:00:00Z", false},
		{"2026-01-01T00:60:00Z", false},
		{"2026-01-01T00:00:60Z", false},
		{"2026-01-01T00:00:00.Z", false},
		{"2026-01-01t00:00:00z", false},
		{"2026-01-01T00:00:00Z\n", false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			for _, record := range []string{streamDelta, streamTerminal} {
				raw := strings.Replace(record, "2026-01-01T00:00:00Z", tc.value, 1)
				_, _, err := parseChatStreamFrame([]byte(raw), "stream-1", "fixture:latest")
				if (err == nil) != tc.valid {
					t.Fatalf("valid=%v err=%v", tc.valid, err)
				}
			}
		})
	}
}

func TestChatStreamCanceledDoerResponsePrecedesStatusAndMedia(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		media  string
	}{
		{"bad-status", http.StatusInternalServerError, "application/x-ndjson"},
		{"bad-media", http.StatusOK, "application/json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			body := &streamTrackedBody{reader: strings.NewReader("private provider diagnostic")}
			client, err := NewWithDependencies(Config{ProviderID: "fixture-provider", Endpoint: "http://127.0.0.1:12345", Timeout: time.Second}, streamDoer(func(r *http.Request) (*http.Response, error) {
				cancel()
				if !errors.Is(r.Context().Err(), context.Canceled) {
					t.Error("request context not canceled")
				}
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": []string{tc.media}}, Body: body}, nil
			}), provider.SystemClock{})
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			err = client.ChatStream(ctx, streamInput(), func(context.Context, ChatChunk) error { count++; return nil })
			if !errors.Is(err, context.Canceled) || count != 0 || body.reads.Load() != 0 || body.closes.Load() != 1 {
				t.Fatalf("err=%v count=%d reads=%d closes=%d", err, count, body.reads.Load(), body.closes.Load())
			}
		})
	}
}
