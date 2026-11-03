package ollama

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
)

// MaximumChatStreamFrameSize bounds a single NDJSON record, excluding LF.
// ChatRequest.MaxResponseBytes bounds the entire upstream body, including LFs.
const MaximumChatStreamFrameSize = 64 * 1024

var ErrChatStreamFrameTooLarge = errors.New("ollama chat stream frame too large")

// ChatChunk contains only public completion fields, never provider metadata.
// A nonterminal delta has no finish reason or usage; the sole terminal chunk
// carries usage and a finish reason. No full response is accumulated.
type ChatChunk struct {
	ID      string            `json:"id"`
	Object  string            `json:"object"`
	Model   string            `json:"model"`
	Choices []ChatChunkChoice `json:"choices"`
	Usage   *ChatUsage        `json:"usage,omitempty"`
}
type ChatChunkChoice struct {
	Index        uint64      `json:"index"`
	Delta        ChatMessage `json:"delta"`
	FinishReason *string     `json:"finish_reason"`
}

// ChatStream is an agent-local provider primitive, not a command/transport API.
// Emit runs synchronously: it must honor its context when blocking, must not
// retain unbounded chunks, and must not launch detached work. An arbitrary
// callback cannot be forcibly interrupted safely. No reader goroutine or
// unbounded queue is created; read-ahead is limited to one 4 KiB reader buffer.
// A terminal record is held until clean EOF so trailing/duplicate records cannot
// produce a successful terminal event. EOF without a terminal record fails.
func (client *Client) ChatStream(ctx context.Context, input ChatRequest, emit func(context.Context, ChatChunk) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, canonical, err := client.streamRequest(input)
	if err != nil || emit == nil {
		return ErrChatFailed
	}
	requestContext, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, client.endpoint+"/api/chat", bytes.NewReader(raw))
	if err != nil {
		return ErrChatFailed
	}
	request.Header.Set("Accept", "application/x-ndjson")
	request.Header.Set("Content-Type", "application/json")
	response, err := client.doer.Do(request)
	var closeOnce sync.Once
	closeBody := func() {
		if response != nil && response.Body != nil {
			closeOnce.Do(func() { _ = response.Body.Close() })
		}
	}
	defer closeBody()
	// Cancellation wins even when a doer returns a response with nil error.
	if contextErr := requestContext.Err(); contextErr != nil {
		return contextErr
	}
	if err != nil {
		return ErrChatFailed
	}
	if response == nil || response.Body == nil {
		return ErrChatFailed
	}
	// Close also unblocks a read when the context expires. HTTP transports honor
	// request cancellation already; this covers injected context-aware doers too.
	stopClose := context.AfterFunc(requestContext, closeBody)
	defer stopClose()
	if response.StatusCode != http.StatusOK {
		return ErrChatHTTPStatus
	}
	if strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0])) != "application/x-ndjson" {
		return ErrInvalidChatResponse
	}
	reader := bufio.NewReaderSize(io.LimitReader(response.Body, int64(input.MaxResponseBytes)+1), 4096)
	var total uint64
	var terminal *ChatChunk
	send := func(chunk ChatChunk) error {
		if err := requestContext.Err(); err != nil {
			return err
		}
		err := emit(requestContext, chunk)
		if requestContext.Err() != nil {
			return requestContext.Err()
		}
		return err
	}
	for {
		if err := requestContext.Err(); err != nil {
			return err
		}
		frame, readErr := readChatStreamFrame(reader, &total, input.MaxResponseBytes)
		if requestContext.Err() != nil {
			return requestContext.Err()
		}
		if readErr != nil && readErr != io.EOF {
			return readErr
		}
		if len(frame) == 0 && readErr == io.EOF {
			if terminal == nil {
				return ErrInvalidChatResponse
			}
			return send(*terminal)
		}
		if terminal != nil {
			return ErrInvalidChatResponse
		}
		chunk, done, err := parseChatStreamFrame(frame, input.RequestID, canonical)
		if err != nil {
			return err
		}
		if done {
			terminal = &chunk
		} else if err := send(chunk); err != nil {
			return err
		}
		if readErr == io.EOF {
			if terminal == nil {
				return ErrInvalidChatResponse
			}
			return send(*terminal)
		}
	}
}

// Keep nonstreaming Chat unchanged; this validator uses the same fixed request
// schema and limits, with additional finite-number and public identity checks.
func (client *Client) streamRequest(input ChatRequest) ([]byte, string, error) {
	if client == nil || client.doer == nil || !provider.ValidateProviderID(client.providerID) || !loopbackOrigin(client.endpoint) || !provider.ValidateProviderID(input.RequestID) || input.MaxRequestBytes < 1 || input.MaxRequestBytes > MaximumChatRequestSize || input.MaxResponseBytes < 1 || input.MaxResponseBytes > MaximumChatResponseSize || len(input.Messages) < 1 || len(input.Messages) > 64 {
		return nil, "", ErrChatFailed
	}
	endpoint, err := NormalizeEndpoint(client.endpoint)
	if err != nil || endpoint != client.endpoint || client.timeout < MinimumTimeout || client.timeout > MaximumTimeout {
		return nil, "", ErrChatFailed
	}
	canonical, ok := providerCanonical(input.Model)
	if !ok {
		return nil, "", ErrChatFailed
	}
	total := 0
	for _, message := range input.Messages {
		if (message.Role != "system" && message.Role != "user" && message.Role != "assistant" && message.Role != "tool") || message.Content == "" || !utf8.ValidString(message.Content) || len(message.Content) > 65536 || strings.ContainsRune(message.Content, 0) {
			return nil, "", ErrChatFailed
		}
		total += len(message.Content)
	}
	if total > 262144 {
		return nil, "", ErrChatFailed
	}
	options := map[string]any{}
	if input.Temperature != nil {
		if math.IsNaN(*input.Temperature) || math.IsInf(*input.Temperature, 0) || *input.Temperature < 0 || *input.Temperature > 2 {
			return nil, "", ErrChatFailed
		}
		options["temperature"] = *input.Temperature
	}
	if input.MaxTokens != nil {
		if *input.MaxTokens < 1 || *input.MaxTokens > 131072 {
			return nil, "", ErrChatFailed
		}
		options["num_predict"] = *input.MaxTokens
	}
	body := map[string]any{"model": canonical, "messages": input.Messages, "stream": true}
	if len(options) > 0 {
		body["options"] = options
	}
	raw, err := json.Marshal(body)
	if err != nil || uint64(len(raw)) > input.MaxRequestBytes {
		return nil, "", ErrChatFailed
	}
	return raw, canonical, nil
}

func readChatStreamFrame(reader *bufio.Reader, total *uint64, limit uint64) ([]byte, error) {
	var frame []byte
	for {
		part, err := reader.ReadSlice('\n')
		*total += uint64(len(part))
		if *total > limit {
			return nil, ErrChatResponseTooLarge
		}
		payload := part
		if len(payload) > 0 && payload[len(payload)-1] == '\n' {
			payload = payload[:len(payload)-1]
		}
		if len(frame)+len(payload) > MaximumChatStreamFrameSize {
			return nil, ErrChatStreamFrameTooLarge
		}
		frame = append(frame, payload...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil && err != io.EOF {
			return nil, ErrInvalidChatResponse
		}
		return frame, err
	}
}

// exactChatObject rejects duplicate (including escaped) keys, nulls, unknown
// fields, and trailing JSON. It is also applied to the nested message object.
func exactChatObject(raw []byte, keys ...string) (map[string]json.RawMessage, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, false
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, false
		}
		if _, exists := fields[key]; exists {
			return nil, false
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, false
		}
		fields[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') || decoder.Decode(&struct{}{}) != io.EOF || len(fields) != len(keys) {
		return nil, false
	}
	for _, key := range keys {
		if _, ok := fields[key]; !ok {
			return nil, false
		}
	}
	return fields, true
}

func parseChatStreamFrame(raw []byte, id, model string) (ChatChunk, bool, error) {
	invalid := func() (ChatChunk, bool, error) { return ChatChunk{}, false, ErrInvalidChatResponse }
	if !utf8.Valid(raw) {
		return invalid()
	}
	var probe struct {
		Done bool `json:"done"`
	}
	if json.Unmarshal(raw, &probe) != nil {
		return invalid()
	}
	keys := []string{"model", "created_at", "message", "done"}
	if probe.Done {
		keys = append(keys, "done_reason", "total_duration", "load_duration", "prompt_eval_count", "prompt_eval_duration", "eval_count", "eval_duration")
	}
	shape, ok := exactChatObject(raw, keys...)
	if !ok {
		return invalid()
	}
	if _, ok := exactChatObject(shape["message"], "role", "content"); !ok {
		return invalid()
	}
	var upstream struct {
		Model              string      `json:"model"`
		CreatedAt          string      `json:"created_at"`
		Message            ChatMessage `json:"message"`
		Done               bool        `json:"done"`
		DoneReason         string      `json:"done_reason"`
		TotalDuration      uint64      `json:"total_duration"`
		LoadDuration       uint64      `json:"load_duration"`
		PromptEvalCount    uint64      `json:"prompt_eval_count"`
		PromptEvalDuration uint64      `json:"prompt_eval_duration"`
		EvalCount          uint64      `json:"eval_count"`
		EvalDuration       uint64      `json:"eval_duration"`
	}
	if json.Unmarshal(raw, &upstream) != nil || upstream.Model != model || upstream.Message.Role != "assistant" {
		return invalid()
	}
	if !strictChatTimestamp(upstream.CreatedAt) {
		return invalid()
	}
	chunk := ChatChunk{ID: id, Object: "chat.completion.chunk", Model: model, Choices: []ChatChunkChoice{{Index: 0, Delta: upstream.Message}}}
	if upstream.Done {
		if (upstream.DoneReason != "stop" && upstream.DoneReason != "length") || upstream.PromptEvalCount > ^uint64(0)-upstream.EvalCount {
			return invalid()
		}
		chunk.Choices[0].FinishReason = &upstream.DoneReason
		chunk.Usage = &ChatUsage{PromptTokens: upstream.PromptEvalCount, CompletionTokens: upstream.EvalCount, TotalTokens: upstream.PromptEvalCount + upstream.EvalCount}
	}
	return chunk, upstream.Done, nil
}

// time.Parse alone also accepts single-digit hours, comma fractions and
// out-of-range zone offsets. Check RFC3339 lexical bounds before calendar
// validation. Fractions use a dot and one or more digits; zone hours/minutes
// must be 00..23/00..59. Keep the existing uppercase T/Z provider profile.
var chatTimestampPattern = regexp.MustCompile(`^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]+)?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`)

func strictChatTimestamp(value string) bool {
	if !chatTimestampPattern.MatchString(value) {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, value)
	return err == nil
}
