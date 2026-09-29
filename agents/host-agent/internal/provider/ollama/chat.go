package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
)

const MaximumChatRequestSize = 512 * 1024
const MaximumChatResponseSize = 256 * 1024

var ErrChatFailed = errors.New("ollama chat failed")
var ErrChatHTTPStatus = errors.New("ollama chat returned unexpected status")
var ErrChatResponseTooLarge = errors.New("ollama chat response too large")
var ErrInvalidChatResponse = errors.New("invalid ollama chat response")

type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatRequest struct {
	RequestID        string
	Model            string
	Messages         []ChatMessage
	Temperature      *float64
	MaxTokens        *uint64
	MaxRequestBytes  uint64
	MaxResponseBytes uint64
}

type ChatCompletion struct {
	ID      string       `json:"id"`
	Object  string       `json:"object"`
	Model   string       `json:"model"`
	Choices []ChatChoice `json:"choices"`
	Usage   ChatUsage    `json:"usage"`
}
type ChatChoice struct {
	Index        uint64      `json:"index"`
	Message      ChatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}
type ChatUsage struct {
	PromptTokens     uint64 `json:"prompt_tokens"`
	CompletionTokens uint64 `json:"completion_tokens"`
	TotalTokens      uint64 `json:"total_tokens"`
}

// Chat invokes only the configured Ollama origin. The caller supplies no URL,
// header, transport option, or streaming switch.
func (client *Client) Chat(ctx context.Context, input ChatRequest) (ChatCompletion, error) {
	if err := ctx.Err(); err != nil {
		return ChatCompletion{}, err
	}
	if client == nil || !loopbackOrigin(client.endpoint) || input.RequestID == "" || input.MaxRequestBytes < 1 || input.MaxRequestBytes > MaximumChatRequestSize || input.MaxResponseBytes < 1 || input.MaxResponseBytes > MaximumChatResponseSize || len(input.Messages) < 1 || len(input.Messages) > 64 {
		return ChatCompletion{}, ErrChatFailed
	}
	canonical, ok := providerCanonical(input.Model)
	if !ok {
		return ChatCompletion{}, ErrChatFailed
	}
	total := 0
	for _, message := range input.Messages {
		if (message.Role != "system" && message.Role != "user" && message.Role != "assistant" && message.Role != "tool") || message.Content == "" || !utf8.ValidString(message.Content) || len(message.Content) > 65536 {
			return ChatCompletion{}, ErrChatFailed
		}
		total += len(message.Content)
	}
	if total > 262144 {
		return ChatCompletion{}, ErrChatFailed
	}
	options := map[string]any{}
	if input.Temperature != nil {
		if *input.Temperature < 0 || *input.Temperature > 2 {
			return ChatCompletion{}, ErrChatFailed
		}
		options["temperature"] = *input.Temperature
	}
	if input.MaxTokens != nil {
		if *input.MaxTokens < 1 || *input.MaxTokens > 131072 {
			return ChatCompletion{}, ErrChatFailed
		}
		options["num_predict"] = *input.MaxTokens
	}
	body := map[string]any{"model": canonical, "messages": input.Messages, "stream": false}
	if len(options) > 0 {
		body["options"] = options
	}
	raw, err := json.Marshal(body)
	if err != nil || uint64(len(raw)) > input.MaxRequestBytes {
		return ChatCompletion{}, ErrChatFailed
	}
	requestContext, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, client.endpoint+"/api/chat", bytes.NewReader(raw))
	if err != nil {
		return ChatCompletion{}, ErrChatFailed
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	response, err := client.doer.Do(request)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil {
		if requestContext.Err() != nil {
			return ChatCompletion{}, requestContext.Err()
		}
		return ChatCompletion{}, ErrChatFailed
	}
	if response == nil || response.Body == nil {
		return ChatCompletion{}, ErrChatFailed
	}
	if response.StatusCode != http.StatusOK {
		return ChatCompletion{}, ErrChatHTTPStatus
	}
	if strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0])) != "application/json" {
		return ChatCompletion{}, ErrInvalidChatResponse
	}
	responseRaw, err := io.ReadAll(io.LimitReader(response.Body, int64(input.MaxResponseBytes)+1))
	if err != nil {
		if requestContext.Err() != nil {
			return ChatCompletion{}, requestContext.Err()
		}
		return ChatCompletion{}, ErrInvalidChatResponse
	}
	if uint64(len(responseRaw)) > input.MaxResponseBytes {
		return ChatCompletion{}, ErrChatResponseTooLarge
	}
	var shape map[string]json.RawMessage
	if json.Unmarshal(responseRaw, &shape) != nil || len(shape) != 11 {
		return ChatCompletion{}, ErrInvalidChatResponse
	}
	for _, key := range []string{"model", "created_at", "message", "done", "done_reason", "total_duration", "load_duration", "prompt_eval_count", "prompt_eval_duration", "eval_count", "eval_duration"} {
		if _, ok := shape[key]; !ok {
			return ChatCompletion{}, ErrInvalidChatResponse
		}
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
	decoder := json.NewDecoder(bytes.NewReader(responseRaw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&upstream) != nil || decoder.Decode(&struct{}{}) != io.EOF || upstream.Model != canonical || upstream.CreatedAt == "" || !upstream.Done || (upstream.DoneReason != "stop" && upstream.DoneReason != "length") || upstream.Message.Role != "assistant" || !utf8.ValidString(upstream.Message.Content) {
		return ChatCompletion{}, ErrInvalidChatResponse
	}
	if upstream.PromptEvalCount > ^uint64(0)-upstream.EvalCount {
		return ChatCompletion{}, ErrInvalidChatResponse
	}
	return ChatCompletion{ID: input.RequestID, Object: "chat.completion", Model: canonical, Choices: []ChatChoice{{Index: 0, Message: upstream.Message, FinishReason: upstream.DoneReason}}, Usage: ChatUsage{PromptTokens: upstream.PromptEvalCount, CompletionTokens: upstream.EvalCount, TotalTokens: upstream.PromptEvalCount + upstream.EvalCount}}, nil
}

func loopbackOrigin(origin string) bool {
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "localhost" {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func providerCanonical(value string) (string, bool) {
	// Keep chat validation identical to lifecycle/inventory normalization.
	return provider.CanonicalOllamaModelName(value)
}
