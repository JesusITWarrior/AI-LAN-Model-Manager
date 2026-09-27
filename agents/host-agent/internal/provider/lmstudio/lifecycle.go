package lmstudio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
)

const MaximumLifecycleBodySize = 1024 * 1024

var (
	ErrLifecycleProviderConflict     = errors.New("lmstudio lifecycle provider conflict")
	ErrLifecycleKeepAliveUnsupported = errors.New("lmstudio lifecycle keep-alive unsupported")
	ErrLifecycleModelNotFound        = errors.New("lmstudio lifecycle model not found")
	ErrLifecycleContextUnsupported   = errors.New("lmstudio lifecycle context length unsupported")
	ErrLifecycleAmbiguousInstances   = errors.New("lmstudio lifecycle model has multiple loaded instances")
	ErrLifecyclePrecheckFailed       = errors.New("lmstudio lifecycle precheck failed")
	ErrLifecycleMutationFailed       = errors.New("lmstudio lifecycle mutation failed")
	ErrLifecycleHTTPStatus           = errors.New("lmstudio lifecycle mutation returned unexpected status")
	ErrLifecycleInvalidResponse      = errors.New("invalid lmstudio lifecycle response")
	ErrLifecycleResponseTooLarge     = errors.New("lmstudio lifecycle response too large")
	ErrLifecycleVerificationFailed   = errors.New("lmstudio lifecycle verification failed")
)

type nativeLoadRequest struct {
	Model         string  `json:"model"`
	ContextLength *uint64 `json:"context_length,omitempty"`
}

type nativeUnloadRequest struct {
	InstanceID string `json:"instance_id"`
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
	if command.ProviderID() != client.providerID {
		return provider.LifecycleResult{}, ErrLifecycleProviderConflict
	}
	if command.KeepAlive() != 0 {
		return provider.LifecycleResult{}, ErrLifecycleKeepAliveUnsupported
	}
	return client.convergeLoad(ctx, command)
}

func (client *Client) Unload(ctx context.Context, command provider.UnloadModelCommand) (provider.LifecycleResult, error) {
	if err := command.Validate(); err != nil {
		return provider.LifecycleResult{}, err
	}
	if command.ProviderID() != client.providerID {
		return provider.LifecycleResult{}, ErrLifecycleProviderConflict
	}
	return client.convergeUnload(ctx, command)
}

func (client *Client) convergeLoad(ctx context.Context, command provider.LoadModelCommand) (provider.LifecycleResult, error) {
	if err := ctx.Err(); err != nil {
		return provider.LifecycleResult{}, err
	}
	model, found, err := client.nativeModel(ctx, command.CanonicalName())
	if err != nil {
		return provider.LifecycleResult{}, lifecyclePhase(ErrLifecyclePrecheckFailed, err)
	}
	if !found {
		return provider.LifecycleResult{}, errors.Join(ErrLifecyclePrecheckFailed, ErrLifecycleModelNotFound)
	}
	if command.ContextLengthKnown() && command.ContextLength() > model.MaximumContextLength {
		return provider.LifecycleResult{}, errors.Join(ErrLifecyclePrecheckFailed, ErrLifecycleContextUnsupported)
	}
	if len(model.LoadedInstances) != 0 {
		if command.ContextLengthKnown() && !loadedContextMatches(model.LoadedInstances, command.ContextLength()) {
			return provider.LifecycleResult{}, errors.Join(ErrLifecyclePrecheckFailed, ErrLifecycleContextUnsupported)
		}
		return client.lifecycleResult(command, false), nil
	}
	if err := client.mutateLoad(ctx, command, model.CanonicalName); err != nil {
		return provider.LifecycleResult{}, err
	}
	model, found, err = client.nativeModel(ctx, command.CanonicalName())
	if err != nil {
		return provider.LifecycleResult{}, lifecyclePhase(ErrLifecycleVerificationFailed, err)
	}
	if !found || len(model.LoadedInstances) == 0 || command.ContextLengthKnown() && !loadedContextMatches(model.LoadedInstances, command.ContextLength()) {
		return provider.LifecycleResult{}, ErrLifecycleVerificationFailed
	}
	return client.lifecycleResult(command, true), nil
}

func (client *Client) convergeUnload(ctx context.Context, command provider.UnloadModelCommand) (provider.LifecycleResult, error) {
	if err := ctx.Err(); err != nil {
		return provider.LifecycleResult{}, err
	}
	model, found, err := client.nativeModel(ctx, command.CanonicalName())
	if err != nil {
		return provider.LifecycleResult{}, lifecyclePhase(ErrLifecyclePrecheckFailed, err)
	}
	if !found || len(model.LoadedInstances) == 0 {
		return client.lifecycleResult(command, false), nil
	}
	if len(model.LoadedInstances) != 1 {
		return provider.LifecycleResult{}, errors.Join(ErrLifecyclePrecheckFailed, ErrLifecycleAmbiguousInstances)
	}
	instanceID := model.LoadedInstances[0].ProviderInstanceID
	if err := client.mutateUnload(ctx, instanceID); err != nil {
		return provider.LifecycleResult{}, err
	}
	model, found, err = client.nativeModel(ctx, command.CanonicalName())
	if err != nil {
		return provider.LifecycleResult{}, lifecyclePhase(ErrLifecycleVerificationFailed, err)
	}
	if found && len(model.LoadedInstances) != 0 {
		return provider.LifecycleResult{}, ErrLifecycleVerificationFailed
	}
	return client.lifecycleResult(command, true), nil
}

func loadedContextMatches(instances []provider.LoadedModelInstance, requested uint64) bool {
	for _, instance := range instances {
		if instance.ContextLength == requested {
			return true
		}
	}
	return false
}

func lifecyclePhase(phase, err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return errors.Join(phase, err)
}

func (client *Client) nativeModel(ctx context.Context, canonicalName string) (provider.ModelCatalogEntry, bool, error) {
	models, err := client.ListNativeModels(ctx)
	if err != nil {
		return provider.ModelCatalogEntry{}, false, err
	}
	for _, model := range models {
		if model.ProviderID == client.providerID && asciiLower(model.CanonicalName) == canonicalName {
			return model, true, nil
		}
	}
	return provider.ModelCatalogEntry{}, false, nil
}

func (client *Client) mutateLoad(ctx context.Context, command provider.LoadModelCommand, nativeModelKey string) error {
	requestBody := nativeLoadRequest{Model: nativeModelKey}
	if command.ContextLengthKnown() {
		value := command.ContextLength()
		requestBody.ContextLength = &value
	}
	body, err := json.Marshal(requestBody)
	if err != nil {
		return ErrLifecycleMutationFailed
	}
	return client.doLifecycleMutation(ctx, "/api/v1/models/load", body, validateLoadResponse)
}

func (client *Client) mutateUnload(ctx context.Context, instanceID string) error {
	body, err := json.Marshal(nativeUnloadRequest{InstanceID: instanceID})
	if err != nil {
		return ErrLifecycleMutationFailed
	}
	return client.doLifecycleMutation(ctx, "/api/v1/models/unload", body, func(response []byte) error {
		return validateUnloadResponse(instanceID, response)
	})
}

func (client *Client) doLifecycleMutation(ctx context.Context, path string, body []byte, validate func([]byte) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	requestContext, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, client.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return ErrLifecycleMutationFailed
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	response, err := client.doer.Do(request)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil {
		if contextErr := requestContext.Err(); contextErr != nil {
			return contextErr
		}
		if errors.Is(err, context.Canceled) {
			return context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return context.DeadlineExceeded
		}
		return ErrLifecycleMutationFailed
	}
	if response == nil || response.Body == nil {
		return ErrLifecycleMutationFailed
	}
	if response.StatusCode != http.StatusOK {
		return ErrLifecycleHTTPStatus
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, MaximumLifecycleBodySize+1))
	if err != nil {
		if contextErr := requestContext.Err(); contextErr != nil {
			return contextErr
		}
		if errors.Is(err, context.Canceled) {
			return context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return context.DeadlineExceeded
		}
		return ErrLifecycleInvalidResponse
	}
	if len(responseBody) > MaximumLifecycleBodySize {
		return ErrLifecycleResponseTooLarge
	}
	return validate(responseBody)
}

func validateLoadResponse(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return ErrLifecycleInvalidResponse
	}
	seen := make(map[string]bool, 5)
	var modelType, instanceID, status string
	var loadConfig json.RawMessage
	for decoder.More() {
		key, err := lifecycleStringToken(decoder)
		if err != nil || seen[key] {
			return ErrLifecycleInvalidResponse
		}
		seen[key] = true
		switch key {
		case "type":
			err = decoder.Decode(&modelType)
		case "instance_id":
			err = decoder.Decode(&instanceID)
		case "load_time_seconds":
			err = decodeNonnegativeFinite(decoder)
		case "status":
			err = decoder.Decode(&status)
		case "load_config":
			err = decoder.Decode(&loadConfig)
		default:
			return ErrLifecycleInvalidResponse
		}
		if err != nil {
			return ErrLifecycleInvalidResponse
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || !seen["type"] || !seen["instance_id"] || !seen["load_time_seconds"] || !seen["status"] {
		return ErrLifecycleInvalidResponse
	}
	if err := requireJSONEOF(decoder); err != nil || (modelType != "llm" && modelType != "embedding") || !validNativeIdentifier(instanceID) || status != "loaded" {
		return ErrLifecycleInvalidResponse
	}
	if seen["load_config"] {
		configDecoder := json.NewDecoder(bytes.NewReader(loadConfig))
		configDecoder.UseNumber()
		if err := decodeLoadConfig(configDecoder, modelType); err != nil || requireJSONEOF(configDecoder) != nil {
			return ErrLifecycleInvalidResponse
		}
	}
	return nil
}

func decodeLoadConfig(decoder *json.Decoder, modelType string) error {
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return ErrLifecycleInvalidResponse
	}
	seen := make(map[string]bool, 5)
	if modelType != "llm" && modelType != "embedding" {
		return ErrLifecycleInvalidResponse
	}
	for decoder.More() {
		key, err := lifecycleStringToken(decoder)
		if err != nil || seen[key] {
			return ErrLifecycleInvalidResponse
		}
		seen[key] = true
		switch key {
		case "context_length":
			_, err = lifecycleBoundedUint(decoder, maximumNativeContextLength)
		case "eval_batch_size":
			if modelType != "llm" {
				return ErrLifecycleInvalidResponse
			}
			_, err = lifecycleBoundedUint(decoder, maximumNativeBatchSize)
		case "flash_attention", "offload_kv_cache_to_gpu":
			if modelType != "llm" {
				return ErrLifecycleInvalidResponse
			}
			_, err = lifecycleBool(decoder)
		case "num_experts":
			if modelType != "llm" {
				return ErrLifecycleInvalidResponse
			}
			_, err = lifecycleBoundedUint(decoder, maximumNativeExperts)
		default:
			return ErrLifecycleInvalidResponse
		}
		if err != nil {
			return ErrLifecycleInvalidResponse
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || !seen["context_length"] {
		return ErrLifecycleInvalidResponse
	}
	return nil
}

func validateUnloadResponse(requestedInstanceID string, body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return ErrLifecycleInvalidResponse
	}
	key, err := lifecycleStringToken(decoder)
	if err != nil || key != "instance_id" {
		return ErrLifecycleInvalidResponse
	}
	var instanceID string
	if err := decoder.Decode(&instanceID); err != nil || instanceID != requestedInstanceID {
		return ErrLifecycleInvalidResponse
	}
	if decoder.More() {
		return ErrLifecycleInvalidResponse
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return ErrLifecycleInvalidResponse
	}
	if err := requireJSONEOF(decoder); err != nil {
		return ErrLifecycleInvalidResponse
	}
	return nil
}

func decodeNonnegativeFinite(decoder *json.Decoder) error {
	var number json.Number
	if err := decoder.Decode(&number); err != nil {
		return err
	}
	value, err := strconv.ParseFloat(number.String(), 64)
	if err != nil || value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return ErrLifecycleInvalidResponse
	}
	return nil
}

func lifecycleBoundedUint(decoder *json.Decoder, maximum uint64) (uint64, error) {
	var number json.Number
	if err := decoder.Decode(&number); err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(number.String(), 10, 64)
	if err != nil || value < 1 || value > maximum {
		return 0, ErrLifecycleInvalidResponse
	}
	return value, nil
}

func lifecycleBool(decoder *json.Decoder) (bool, error) {
	var value bool
	err := decoder.Decode(&value)
	return value, err
}

func lifecycleStringToken(decoder *json.Decoder) (string, error) {
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

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrLifecycleInvalidResponse
	}
	return nil
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
