package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
)

const MaximumGenerateBodySize = 1024 * 1024

var (
	ErrLifecycleProviderConflict   = errors.New("ollama lifecycle provider conflict")
	ErrLifecyclePrecheckFailed     = errors.New("ollama lifecycle precheck failed")
	ErrLifecycleMutationFailed     = errors.New("ollama lifecycle mutation failed")
	ErrLifecycleHTTPStatus         = errors.New("ollama lifecycle mutation returned unexpected status")
	ErrLifecycleInvalidResponse    = errors.New("invalid ollama lifecycle response")
	ErrLifecycleResponseTooLarge   = ErrLifecycleInvalidResponse
	ErrLifecycleVerificationFailed = errors.New("ollama lifecycle verification failed")

	// Compatibility names retained for callers of the draft API.
	ErrGenerateFailed            = ErrLifecycleMutationFailed
	ErrGenerateHTTPStatus        = ErrLifecycleHTTPStatus
	ErrGenerateResponseTooLarge  = ErrLifecycleResponseTooLarge
	ErrGenerateInvalidResponse   = ErrLifecycleInvalidResponse
	ErrCommandConflict           = ErrLifecycleProviderConflict
	ErrCommandInvalid            = provider.ErrInvalidCommand
	ErrCommandVerificationFailed = ErrLifecycleVerificationFailed
)

type loadGenerateRequest struct {
	Model     string `json:"model"`
	Prompt    string `json:"prompt"`
	Stream    bool   `json:"stream"`
	KeepAlive string `json:"keep_alive"`
}

type unloadGenerateRequest struct {
	Model     string `json:"model"`
	Prompt    string `json:"prompt"`
	Stream    bool   `json:"stream"`
	KeepAlive int    `json:"keep_alive"`
}

// newGenerateRequest is deliberately private and fixes the method, endpoint,
// headers, and JSON shape. Callers cannot turn a lifecycle command into an
// arbitrary HTTP request or add provider options.
func newGenerateRequest(ctx context.Context, endpoint, model string, keepAlive time.Duration, load bool) (*http.Request, error) {
	canonical, ok := provider.CanonicalOllamaModelName(model)
	if !ok || canonical != model {
		return nil, provider.ErrInvalidCommand
	}
	var payload []byte
	var err error
	if load {
		value, formatErr := formatKeepAlive(keepAlive)
		if formatErr != nil || value == "0" {
			return nil, provider.ErrInvalidCommand
		}
		payload, err = json.Marshal(loadGenerateRequest{Model: model, Prompt: "", Stream: false, KeepAlive: value})
	} else {
		if keepAlive != 0 {
			return nil, provider.ErrInvalidCommand
		}
		payload, err = json.Marshal(unloadGenerateRequest{Model: model, Prompt: "", Stream: false, KeepAlive: 0})
	}
	if err != nil {
		return nil, ErrLifecycleMutationFailed
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/api/generate", bytes.NewReader(payload))
	if err != nil {
		return nil, ErrLifecycleMutationFailed
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	return request, nil
}

type lifecycleCommand interface {
	CommandID() string
	ProviderID() string
	CanonicalName() string
	Action() provider.Action
}

func (client *Client) Load(ctx context.Context, command provider.LoadModelCommand) (provider.LifecycleResult, error) {
	if err := command.Validate(); err != nil {
		return provider.LifecycleResult{}, err
	}
	if command.KeepAlive() == 0 {
		return provider.LifecycleResult{}, provider.ErrInvalidCommand
	}
	if command.ProviderID() != client.providerID {
		return provider.LifecycleResult{}, ErrLifecycleProviderConflict
	}
	return client.converge(ctx, command, true, command.KeepAlive())
}

func (client *Client) Unload(ctx context.Context, command provider.UnloadModelCommand) (provider.LifecycleResult, error) {
	if err := command.Validate(); err != nil {
		return provider.LifecycleResult{}, err
	}
	if command.ProviderID() != client.providerID {
		return provider.LifecycleResult{}, ErrLifecycleProviderConflict
	}
	return client.converge(ctx, command, false, 0)
}

func (client *Client) converge(ctx context.Context, command lifecycleCommand, wantPresent bool, keepAlive time.Duration) (provider.LifecycleResult, error) {
	if err := ctx.Err(); err != nil {
		return provider.LifecycleResult{}, err
	}
	present, err := client.runningPresent(ctx, command.CanonicalName())
	if err != nil {
		return provider.LifecycleResult{}, classifyPhase(ErrLifecyclePrecheckFailed, err)
	}
	if present == wantPresent {
		return client.lifecycleResult(command, false), nil
	}

	if err := client.serveGenerate(ctx, command.CanonicalName(), keepAlive, wantPresent); err != nil {
		return provider.LifecycleResult{}, err
	}
	present, err = client.runningPresent(ctx, command.CanonicalName())
	if err != nil {
		return provider.LifecycleResult{}, classifyPhase(ErrLifecycleVerificationFailed, err)
	}
	if present != wantPresent {
		return provider.LifecycleResult{}, ErrLifecycleVerificationFailed
	}
	return client.lifecycleResult(command, true), nil
}

func classifyPhase(phase, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return errors.Join(phase, err)
}

func (client *Client) serveGenerate(ctx context.Context, requested string, keepAlive time.Duration, load bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	requestContext, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()
	request, err := newGenerateRequest(requestContext, client.endpoint, requested, keepAlive, load)
	if err != nil {
		return err
	}

	response, err := client.doer.Do(request)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil {
		if contextErr := requestContext.Err(); contextErr != nil {
			return contextErr
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return ErrLifecycleMutationFailed
	}
	if response == nil || response.Body == nil {
		return ErrLifecycleMutationFailed
	}
	if response.StatusCode != http.StatusOK {
		return ErrLifecycleHTTPStatus
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaximumGenerateBodySize+1))
	if err != nil {
		if contextErr := requestContext.Err(); contextErr != nil {
			return contextErr
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return ErrLifecycleInvalidResponse
	}
	if len(body) > MaximumGenerateBodySize {
		return ErrLifecycleResponseTooLarge
	}
	return validateGenerateResponse(requested, body)
}

func validateGenerateResponse(requested string, body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return ErrLifecycleInvalidResponse
	}
	seen := make(map[string]bool, 12)
	var model string
	var done bool
	for decoder.More() {
		key, err := generateStringToken(decoder)
		if err != nil || seen[key] {
			return ErrLifecycleInvalidResponse
		}
		seen[key] = true
		switch key {
		case "model":
			err = decoder.Decode(&model)
		case "done":
			err = decoder.Decode(&done)
		case "created_at":
			var value string
			if err = decoder.Decode(&value); err == nil {
				_, err = time.Parse(time.RFC3339Nano, value)
			}
		case "response", "done_reason":
			var value string
			err = decoder.Decode(&value)
		case "context":
			err = decodeGenerateContext(decoder)
		case "total_duration", "load_duration", "prompt_eval_count", "prompt_eval_duration", "eval_count", "eval_duration":
			_, err = decodeGenerateUint(decoder)
		default:
			return ErrLifecycleInvalidResponse
		}
		if err != nil {
			return ErrLifecycleInvalidResponse
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || !seen["model"] || !seen["done"] {
		return ErrLifecycleInvalidResponse
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrLifecycleInvalidResponse
	}
	canonical, ok := provider.CanonicalOllamaModelName(model)
	if !ok || canonical != requested || !done {
		return ErrLifecycleInvalidResponse
	}
	return nil
}

func decodeGenerateUint(decoder *json.Decoder) (uint64, error) {
	var number json.Number
	if err := decoder.Decode(&number); err != nil {
		return 0, err
	}
	return strconv.ParseUint(number.String(), 10, 64)
}

func decodeGenerateContext(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil || token != json.Delim('[') {
		return ErrLifecycleInvalidResponse
	}
	count := 0
	for decoder.More() {
		count++
		if count > provider.MaximumContextLength {
			return ErrLifecycleInvalidResponse
		}
		value, err := decodeGenerateUint(decoder)
		if err != nil || value > uint64(^uint32(0)>>1) {
			return ErrLifecycleInvalidResponse
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim(']') {
		return ErrLifecycleInvalidResponse
	}
	return nil
}

func generateStringToken(decoder *json.Decoder) (string, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", err
	}
	value, ok := token.(string)
	if !ok {
		return "", ErrLifecycleInvalidResponse
	}
	return value, nil
}

func (client *Client) runningPresent(ctx context.Context, canonicalName string) (bool, error) {
	running, err := client.ListRunning(ctx)
	if err != nil {
		return false, err
	}
	for _, model := range running {
		if model.ProviderID == client.providerID && model.CanonicalName == canonicalName {
			return true, nil
		}
	}
	return false, nil
}

func (client *Client) lifecycleResult(command lifecycleCommand, changed bool) provider.LifecycleResult {
	state := provider.RuntimeUnloaded
	if command.Action() == provider.ActionLoad {
		state = provider.RuntimeLoaded
	}
	return provider.LifecycleResult{
		CommandID: command.CommandID(), ProviderID: command.ProviderID(), CanonicalModelName: command.CanonicalName(),
		Action: command.Action(), Outcome: provider.OutcomeSucceeded, Changed: changed, RuntimeState: state,
		ObservedAt: client.clock.Now().UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z"),
	}
}

func formatKeepAlive(duration time.Duration) (string, error) {
	if duration == 0 {
		return "0", nil
	}
	if duration < provider.KeepAliveMinimum || duration > provider.KeepAliveMaximum || duration%time.Second != 0 {
		return "", provider.ErrInvalidCommand
	}
	return strconv.FormatInt(int64(duration/time.Second), 10) + "s", nil
}
