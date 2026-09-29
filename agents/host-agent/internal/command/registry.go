// Package command adapts the controller's fixed agent lifecycle operations onto
// existing provider adapters (Ollama, LM Studio). The registry knows no shell,
// URL, or path surface: every call is bound to one validated operation, dispatched
// through a provider-specific converger, then post-verified against the runtime
// observation the provider exposes. Provider-specific error and state redaction
// lives here so the controller only ever sees provider-neutral results.
package command

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider/lmstudio"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider/ollama"
)

// NoProvider indicates the registry has no adapter bound to the requested provider.
var NoProvider = errors.New("provider adapter not registered")

// ErrUnsupported indicates the registry cannot map the operation to any provider.
var ErrUnsupported = errors.New("operation unsupported by registry")

// ErrRuntimeStateMismatch indicates the post-mutation runtime observation does not
// reflect the claimed mutation, so the operation may not be marked successful.
var ErrRuntimeStateMismatch = errors.New("post-mutation runtime observation mismatch")

// ErrModelNotLoaded indicates the model is not currently loaded.
var ErrModelNotLoaded = errors.New("model not loaded")

// ErrServingActive indicates the model has active requests and must be drained
// before it can be unloaded.
var ErrServingActive = errors.New("model has active requests; drain before unload")

// ErrModelNotIdle indicates the model has active requests and must be idle before
// its options can be changed.
var ErrModelNotIdle = errors.New("model has active requests; set-options requires idle")

// ErrGuardedOperation indicates the operation is not permitted by the registry.
var ErrGuardedOperation = errors.New("operation not permitted by registry")

// ErrOperationUnavailable indicates the operation is valid but no provider adapter
// registered supports the required observation.
var ErrOperationUnavailable = errors.New("operation unavailable for provider")

// DrainResult proves admission is stopped and no requests remain before unload.
type DrainResult struct {
	Action             string                `json:"action"`
	ProviderID         string                `json:"providerId"`
	CanonicalModelName string                `json:"canonicalModelName"`
	Outcome            provider.Outcome      `json:"outcome"`
	RuntimeState       provider.RuntimeState `json:"runtimeState"`
	ActiveRequests     uint64                `json:"activeRequests"`
	ObservedAt         string                `json:"observedAt"`
}

// adapter is the minimal surface every provider client must expose. Only the
// subset required by the fixed lifecycle operations is requested, so no provider
// client can be asked to do anything beyond probe, load, and unload.
type providerAdapter interface {
	Load(context.Context, provider.LoadModelCommand) (provider.LifecycleResult, error)
	Unload(context.Context, provider.UnloadModelCommand) (provider.LifecycleResult, error)
	Probe(context.Context) (provider.ProviderProbe, error)
}

// runtimeObserver observes the currently running (loaded) models. Only adapters
// that expose a running-model observation (Ollama) implement it.
type runtimeObserver interface {
	ListRunning(context.Context) ([]provider.RunningModel, error)
}

// installedObserver observes the locally installed models. Only adapters that
// expose an installed-model observation (Ollama) implement it.
type installedObserver interface {
	ListInstalled(context.Context) ([]provider.InstalledModel, error)
}
type inferenceAdapter interface {
	Chat(context.Context, ollama.ChatRequest) (ollama.ChatCompletion, error)
}

// ArtifactInstaller is deliberately injected. A registry without one rejects
// artifact installation, so merely enabling the command plane cannot enable
// remote acquisition.
type ArtifactInstaller interface {
	Install(context.Context, ArtifactInstallParams) (ArtifactInstallResult, error)
}

// Registry binds each fixed lifecycle operation to exactly one provider client.
// No adapter may be added through any other path.
type Registry struct {
	now       func() time.Time
	mu        sync.Mutex
	clients   map[string]providerAdapter     // providerId -> adapter
	running   map[string]struct{}            // modelKey -> currently loaded
	draining  map[string]struct{}            // modelKey -> admission stopped
	active    map[string]map[string]struct{} // modelKey -> outstanding request handles
	installer ArtifactInstaller
}

// NewRegistry creates an empty registry using the supplied clock (or time.Now
// when nil).
func NewRegistry(now func() time.Time) *Registry {
	if now == nil {
		now = time.Now
	}
	return &Registry{now: now, clients: map[string]providerAdapter{}, running: map[string]struct{}{}, draining: map[string]struct{}{}, active: map[string]map[string]struct{}{}}
}

// RegisterOllama binds one normalized Ollama adapter to the registry under its
// providerId, mapping every lifecycle operation it supports.
func (r *Registry) RegisterOllama(providerID string, client *ollama.Client) {
	if r == nil || client == nil || providerID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clients[providerID] = client
}

// RegisterLMStudio binds one normalized LM Studio adapter to the registry under
// its providerId. LM Studio exposes no running/installed observation, so runtime
// verification for it relies on the provider's own convergence result.
// ConfigureArtifactInstaller explicitly enables the otherwise guarded install
// operation. Passing nil restores the guard.
func (r *Registry) ConfigureArtifactInstaller(installer ArtifactInstaller) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.installer = installer
}

func (r *Registry) RegisterLMStudio(providerID string, client *lmstudio.Client) {
	if r == nil || client == nil || providerID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clients[providerID] = client
}

// Execute adapts a single fixed operation for the executor. It accepts no shell,
// URL, address, command, or arbitrary-path parameter: the parameter envelope is
// validated against the fixed lifecycle grammar before any provider client runs.
func (r *Registry) Execute(ctx context.Context, operation string, params json.RawMessage) (any, error) {
	if r == nil {
		return nil, ErrUnsupported
	}
	if operation == "remove-managed-artifact" {
		return nil, ErrGuardedOperation
	}
	if operation == "install" {
		r.mu.Lock()
		installer := r.installer
		r.mu.Unlock()
		if installer == nil {
			return nil, ErrGuardedOperation
		}
		parsed, err := ParseArtifactInstallParams(params)
		if err != nil {
			return nil, err
		}
		return installer.Install(ctx, parsed)
	}
	if operation == "inference.chat" {
		return r.runInference(ctx, params)
	}
	params2, err := parseLifecycle(operation, params)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	adapter := r.clients[params2.providerID]
	r.mu.Unlock()
	if adapter == nil {
		return nil, NoProvider
	}
	switch operation {
	case "probe":
		return adapter.Probe(ctx)
	case "inventory":
		return r.observeInstalled(ctx, adapter)
	case "estimate":
		return r.observeRunning(ctx, adapter)
	case "load":
		return r.runLoad(ctx, adapter, params2.providerID, params2.model, params2.keepAlive, params2.contextLength, params2.contextLengthKnown)
	case "set-options":
		return r.runSetOptions(ctx, adapter, params2.providerID, params2.model, params2.keepAlive, params2.contextLength, params2.contextLengthKnown)
	case "drain":
		return r.runDrain(ctx, params2.providerID, params2.model)
	case "unload":
		return r.runUnload(ctx, adapter, params2.providerID, params2.model, params2.contextLength, params2.contextLengthKnown)
	default:
		return nil, ErrUnsupported
	}
}

func (r *Registry) runInference(ctx context.Context, raw json.RawMessage) (any, error) {
	params, err := parseInferenceChat(raw)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	adapter := r.clients[params.ProviderID]
	r.mu.Unlock()
	chat, ok := adapter.(inferenceAdapter)
	if !ok {
		return nil, NoProvider
	}
	inventory, ok := adapter.(installedObserver)
	if !ok {
		return nil, ErrOperationUnavailable
	}
	models, err := inventory.ListInstalled(ctx)
	if err != nil {
		return nil, err
	}
	matched := false
	for _, model := range models {
		if model.ProviderID == params.ProviderID && model.ModelID == params.ModelID && model.CanonicalName == params.Model {
			matched = true
			break
		}
	}
	if !matched {
		return nil, ErrRuntimeStateMismatch
	}
	running, ok := adapter.(runtimeObserver)
	if !ok {
		return nil, ErrOperationUnavailable
	}
	loaded, err := running.ListRunning(ctx)
	if err != nil {
		return nil, err
	}
	r.syncRunning(loaded)
	handle, err := r.Acquire(ctx, params.ProviderID, params.Model)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Complete(context.Background(), handle) }()
	messages := make([]ollama.ChatMessage, len(params.Messages))
	for i, message := range params.Messages {
		messages[i] = ollama.ChatMessage{Role: message.Role, Content: message.Content}
	}
	var temperature *float64
	if params.TemperatureMilli != nil {
		value := float64(*params.TemperatureMilli) / 1000
		temperature = &value
	}
	var maxTokens *uint64
	if params.MaxTokens != nil {
		value := uint64(*params.MaxTokens)
		maxTokens = &value
	}
	return chat.Chat(ctx, ollama.ChatRequest{RequestID: params.RequestID, Model: params.Model, Messages: messages, Temperature: temperature, MaxTokens: maxTokens, MaxRequestBytes: uint64(params.MaxRequestBytes), MaxResponseBytes: uint64(params.MaxResponseBytes)})
}

type inferenceChatMessage struct {
	Role    string
	Content string
}
type inferenceChatParams struct {
	ProviderID       string
	ModelID          string
	Model            string
	RequestID        string
	MaxRequestBytes  int64
	MaxResponseBytes int64
	Messages         []inferenceChatMessage
	TemperatureMilli *int64
	MaxTokens        *int64
}

func parseInferenceChat(raw json.RawMessage) (inferenceChatParams, error) {
	var input struct {
		ProviderID       string `json:"providerId"`
		ModelID          string `json:"modelId"`
		Model            string `json:"model"`
		RequestID        string `json:"requestId"`
		MaxRequestBytes  int64  `json:"maxRequestBytes"`
		MaxResponseBytes int64  `json:"maxResponseBytes"`
		Messages         []struct {
			Role          string `json:"role"`
			ContentBase64 string `json:"contentBase64"`
		} `json:"messages"`
		TemperatureMilli *int64 `json:"temperatureMilli"`
		MaxTokens        *int64 `json:"maxTokens"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF || !provider.ValidateProviderID(input.ProviderID) || !identifier.MatchString(input.ModelID) || !identifier.MatchString(input.RequestID) || input.MaxRequestBytes < 1 || input.MaxRequestBytes > ollama.MaximumChatRequestSize || input.MaxResponseBytes < 1 || input.MaxResponseBytes > ollama.MaximumChatResponseSize || len(input.Messages) < 1 || len(input.Messages) > 64 {
		return inferenceChatParams{}, provider.ErrInvalidCommand
	}
	model, ok := provider.CanonicalOllamaModelName(input.Model)
	if !ok {
		return inferenceChatParams{}, provider.ErrInvalidCommand
	}
	if input.TemperatureMilli != nil && (*input.TemperatureMilli < 0 || *input.TemperatureMilli > 2000) || input.MaxTokens != nil && (*input.MaxTokens < 1 || *input.MaxTokens > 131072) {
		return inferenceChatParams{}, provider.ErrInvalidCommand
	}
	out := inferenceChatParams{ProviderID: input.ProviderID, ModelID: input.ModelID, Model: model, RequestID: input.RequestID, MaxRequestBytes: input.MaxRequestBytes, MaxResponseBytes: input.MaxResponseBytes, TemperatureMilli: input.TemperatureMilli, MaxTokens: input.MaxTokens, Messages: make([]inferenceChatMessage, len(input.Messages))}
	total := 0
	for i, message := range input.Messages {
		if message.Role != "system" && message.Role != "user" && message.Role != "assistant" && message.Role != "tool" {
			return inferenceChatParams{}, provider.ErrInvalidCommand
		}
		content, e := base64.StdEncoding.Strict().DecodeString(message.ContentBase64)
		if e != nil || len(content) < 1 || len(content) > 65536 || !utf8.Valid(content) {
			return inferenceChatParams{}, provider.ErrInvalidCommand
		}
		total += len(content)
		if total > 262144 {
			return inferenceChatParams{}, provider.ErrInvalidCommand
		}
		out.Messages[i] = inferenceChatMessage{Role: message.Role, Content: string(content)}
	}
	if int64(len(raw)) > input.MaxRequestBytes {
		return inferenceChatParams{}, provider.ErrInvalidCommand
	}
	return out, nil
}

// observeInstalled records the installed-model inventory against which install/remove
// safeguards later assert. Only adapters that expose an installed-model observation
// (Ollama) implement it; LM Studio reports it as unsupported.
func (r *Registry) observeInstalled(ctx context.Context, adapter providerAdapter) (any, error) {
	obs, ok := adapter.(installedObserver)
	if !ok {
		return nil, ErrOperationUnavailable
	}
	return obs.ListInstalled(ctx)
}

// observeRunning records the running-model observation and requires the registry's
// internal view of loaded models to agree with it before the controller trusts a
// subsequent runtime query.
func (r *Registry) observeRunning(ctx context.Context, adapter providerAdapter) (any, error) {
	obs, ok := adapter.(runtimeObserver)
	if !ok {
		return nil, ErrOperationUnavailable
	}
	models, err := obs.ListRunning(ctx)
	if err != nil {
		return nil, err
	}
	r.syncRunning(models)
	return models, nil
}

// runLoad loads (or no-ops on an already-loaded model) and then requires a fresh
// runtime observation to confirm the mutation landed. A stale post-mutation
// observation is rejected so the controller never marks success from a claim the
// runtime does not back.
func (r *Registry) runLoad(ctx context.Context, adapter providerAdapter, providerID, canonical string, keepAlive time.Duration, contextLength uint64, contextLengthKnown bool) (provider.LifecycleResult, error) {
	command, err := provider.NewLoadModelCommand(r.newToken("cmd-"), providerID, canonical, keepAlive, provider.Metadata{ContextLength: contextLength, Known: contextLengthKnown})
	if err != nil {
		return provider.LifecycleResult{}, err
	}
	if command.KeepAlive() == 0 {
		if _, ok := adapter.(*lmstudio.Client); !ok {
			return provider.LifecycleResult{}, provider.ErrInvalidCommand
		}
	}
	result, err := adapter.Load(ctx, command)
	if err != nil {
		if errors.Is(err, ollama.ErrLifecycleVerificationFailed) || errors.Is(err, lmstudio.ErrLifecycleVerificationFailed) {
			return provider.LifecycleResult{}, ErrRuntimeStateMismatch
		}
		return provider.LifecycleResult{}, err
	}
	if err := r.verifyPresent(ctx, adapter, providerID, canonical); err != nil {
		return provider.LifecycleResult{}, err
	}
	r.markRunning(providerID, canonical, true)
	return result, nil
}

// runSetOptions changes a loaded model's options and requires the model to be idle
// (no outstanding requests) first. It reuses the load converger, which reconfigures
// and re-verifies the model in place.
func (r *Registry) runSetOptions(ctx context.Context, adapter providerAdapter, providerID, canonical string, keepAlive time.Duration, contextLength uint64, contextLengthKnown bool) (provider.LifecycleResult, error) {
	key := modelKey(providerID, canonical)
	r.mu.Lock()
	if len(r.active[key]) != 0 {
		r.mu.Unlock()
		return provider.LifecycleResult{}, ErrModelNotIdle
	}
	r.draining[key] = struct{}{}
	r.mu.Unlock()
	result, err := r.runLoad(ctx, adapter, providerID, canonical, keepAlive, contextLength, contextLengthKnown)
	if err == nil {
		r.mu.Lock()
		delete(r.draining, key)
		r.mu.Unlock()
	}
	return result, err
}

// runUnload refuses to run while requests are outstanding (the caller must drain
// first), then requires the runtime to report the model absent.
func (r *Registry) runUnload(ctx context.Context, adapter providerAdapter, providerID, canonical string, contextLength uint64, contextLengthKnown bool) (provider.LifecycleResult, error) {
	key := modelKey(providerID, canonical)
	if err := ctx.Err(); err != nil {
		return provider.LifecycleResult{}, err
	}
	r.mu.Lock()
	if len(r.active[key]) != 0 {
		r.mu.Unlock()
		return provider.LifecycleResult{}, ErrServingActive
	}
	r.draining[key] = struct{}{}
	r.mu.Unlock()
	command, err := provider.NewUnloadModelCommand(r.newToken("cmd-"), providerID, canonical, provider.Metadata{ContextLength: contextLength, Known: contextLengthKnown})
	if err != nil {
		return provider.LifecycleResult{}, err
	}
	result, err := adapter.Unload(ctx, command)
	if err != nil {
		if errors.Is(err, ollama.ErrLifecycleVerificationFailed) || errors.Is(err, lmstudio.ErrLifecycleVerificationFailed) {
			return provider.LifecycleResult{}, ErrRuntimeStateMismatch
		}
		return provider.LifecycleResult{}, err
	}
	if err := r.verifyAbsent(ctx, adapter, providerID, canonical); err != nil {
		return provider.LifecycleResult{}, err
	}
	r.markRunning(providerID, canonical, false)
	return result, nil
}

// runDrain completes every outstanding request on the model so it becomes unloadable
// and idle. It leaves the model itself loaded.
func (r *Registry) runDrain(ctx context.Context, providerID, canonical string) (any, error) {
	if err := ctx.Err(); err != nil {
		return provider.LifecycleResult{}, err
	}
	key := modelKey(providerID, canonical)
	r.mu.Lock()
	if _, ok := r.running[key]; !ok {
		r.mu.Unlock()
		return provider.LifecycleResult{}, ErrModelNotLoaded
	}
	r.draining[key] = struct{}{}
	outstanding := len(r.active[key])
	r.mu.Unlock()
	if outstanding != 0 {
		return provider.LifecycleResult{}, ErrServingActive
	}
	return DrainResult{
		Action:             "drain",
		ProviderID:         providerID,
		CanonicalModelName: canonical,
		Outcome:            provider.OutcomeSucceeded,
		RuntimeState:       provider.RuntimeLoaded,
		ActiveRequests:     0,
		ObservedAt:         r.now().UTC().Format("2006-01-02T15:04:05.000Z"),
	}, nil
}

// Acquire reserves one outstanding request handle against a loaded model. It fails
// if the model is not currently loaded. Handles are released with Complete.
func (r *Registry) Acquire(ctx context.Context, providerID, canonical string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	key := modelKey(providerID, canonical)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.running[key]; !ok {
		return "", ErrModelNotLoaded
	}
	if _, stopped := r.draining[key]; stopped {
		return "", ErrServingActive
	}
	handle := r.newToken("req-")
	if r.active[key] == nil {
		r.active[key] = map[string]struct{}{}
	}
	r.active[key][handle] = struct{}{}
	return handle, nil
}

// Complete releases a single outstanding request handle.
func (r *Registry) Complete(ctx context.Context, handle string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, outstanding := range r.active {
		delete(outstanding, handle)
	}
	return nil
}

// verifyPresent requires a runtime observer to report the model loaded. It is
// skipped (the provider's own convergence result stands) for adapters that expose
// no running-model observation (LM Studio).
func (r *Registry) verifyPresent(ctx context.Context, adapter providerAdapter, providerID, canonical string) error {
	return r.verify(ctx, adapter, providerID, canonical, true)
}

// verifyAbsent requires a runtime observer to report the model absent. It is
// skipped (the provider's own convergence result stands) for adapters that expose
// no running-model observation (LM Studio).
func (r *Registry) verifyAbsent(ctx context.Context, adapter providerAdapter, providerID, canonical string) error {
	return r.verify(ctx, adapter, providerID, canonical, false)
}

func (r *Registry) verify(ctx context.Context, adapter providerAdapter, providerID, canonical string, wantPresent bool) error {
	obs, ok := adapter.(runtimeObserver)
	if !ok {
		return nil // no running-model observation available; trust the converger.
	}
	models, err := obs.ListRunning(ctx)
	if err != nil {
		return err
	}
	for _, model := range models {
		if model.ProviderID == providerID && model.CanonicalName == canonical {
			if !wantPresent {
				return ErrRuntimeStateMismatch
			}
			return nil
		}
	}
	if wantPresent {
		return ErrRuntimeStateMismatch
	}
	return nil
}

// syncRunning updates the registry's view of loaded models from a running-model
// observation.
func (r *Registry) syncRunning(models []provider.RunningModel) {
	r.mu.Lock()
	defer r.mu.Unlock()
	present := map[string]struct{}{}
	for _, model := range models {
		present[modelKey(model.ProviderID, model.CanonicalName)] = struct{}{}
	}
	for key := range r.running {
		if _, ok := present[key]; !ok {
			delete(r.running, key)
			delete(r.draining, key)
			delete(r.active, key)
		}
	}
	for key := range present {
		if _, ok := r.running[key]; !ok {
			r.running[key] = struct{}{}
		}
	}
}

func (r *Registry) isLoaded(providerID, canonical string) bool {
	key := modelKey(providerID, canonical)
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.running[key]
	return ok
}

func (r *Registry) markRunning(providerID, canonical string, present bool) {
	key := modelKey(providerID, canonical)
	r.mu.Lock()
	defer r.mu.Unlock()
	if present {
		r.running[key] = struct{}{}
	} else {
		delete(r.running, key)
		delete(r.draining, key)
		delete(r.active, key)
	}
}

func modelKey(providerID, canonical string) string {
	return providerID + "\x00" + canonical
}

// newToken returns a unique, opaque identifier for a command or request handle.
func (r *Registry) newToken(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

type lifecycleParams struct {
	providerID         string
	model              string
	keepAlive          time.Duration
	contextLength      uint64
	contextLengthKnown bool
}

// parseLifecycle decodes and validates the fixed lifecycle parameter envelope. The
// envelope accepts only providerId, model, and optional keepAlive/contextLength.
// Any shell, url, address, command, or parameter field named after a network or
// path primitive is rejected outright.
func parseLifecycle(operation string, params json.RawMessage) (lifecycleParams, error) {
	switch {
	case operation == "probe" || operation == "inventory" || operation == "estimate":
		var raw struct {
			ProviderID string `json:"providerId"`
		}
		if e := decodeLifecycle(params, &raw); e != nil || !provider.ValidateProviderID(raw.ProviderID) {
			return lifecycleParams{}, provider.ErrInvalidCommand
		}
		return lifecycleParams{providerID: raw.ProviderID}, nil
	case operation == "load" || operation == "set-options":
		var raw struct {
			ProviderID    string          `json:"providerId"`
			Model         string          `json:"model"`
			KeepAlive     json.RawMessage `json:"keepAlive"`
			ContextLength json.RawMessage `json:"contextLength"`
		}
		if e := decodeLifecycle(params, &raw); e != nil {
			return lifecycleParams{}, e
		}
		return buildLoad(raw)
	case operation == "unload":
		var raw struct {
			ProviderID    string          `json:"providerId"`
			Model         string          `json:"model"`
			KeepAlive     json.RawMessage `json:"keepAlive"`
			ContextLength json.RawMessage `json:"contextLength"`
		}
		if e := decodeLifecycle(params, &raw); e != nil {
			return lifecycleParams{}, e
		}
		keepAlive, contextLength, contextLengthKnown, err := complete(raw)
		if err != nil {
			return lifecycleParams{}, err
		}
		_ = keepAlive
		return lifecycleParams{providerID: raw.ProviderID, model: raw.Model, contextLength: contextLength, contextLengthKnown: contextLengthKnown}, nil
	case operation == "drain":
		var raw struct {
			ProviderID string `json:"providerId"`
			Model      string `json:"model"`
		}
		if e := decodeLifecycle(params, &raw); e != nil {
			return lifecycleParams{}, e
		}
		if !provider.ValidateProviderID(raw.ProviderID) {
			return lifecycleParams{}, provider.ErrInvalidCommand
		}
		canonical, ok := provider.CanonicalOllamaModelName(raw.Model)
		if !ok {
			return lifecycleParams{}, provider.ErrInvalidCommand
		}
		return lifecycleParams{providerID: raw.ProviderID, model: canonical}, nil
	default:
		return lifecycleParams{}, ErrUnsupported
	}
}

// modelParams is the decoded lifecycle parameter envelope shared by load,
// set-options, and unload. KeepAlive is only meaningful for load/set-options.
type modelParams struct {
	ProviderID    string          `json:"providerId"`
	Model         string          `json:"model"`
	KeepAlive     json.RawMessage `json:"keepAlive"`
	ContextLength json.RawMessage `json:"contextLength"`
}

func buildLoad(raw modelParams) (lifecycleParams, error) {
	if !provider.ValidateProviderID(raw.ProviderID) {
		return lifecycleParams{}, provider.ErrInvalidCommand
	}
	canonical, ok := provider.CanonicalOllamaModelName(raw.Model)
	if !ok {
		return lifecycleParams{}, provider.ErrInvalidCommand
	}
	keepAlive, contextLength, contextLengthKnown, err := complete(raw)
	if err != nil {
		return lifecycleParams{}, err
	}
	return lifecycleParams{providerID: raw.ProviderID, model: canonical, keepAlive: keepAlive, contextLength: contextLength, contextLengthKnown: contextLengthKnown}, nil
}

// complete resolves keepAlive and contextLength defaults, validating both.
func complete(raw modelParams) (time.Duration, uint64, bool, error) {
	var keepAlive time.Duration
	if raw.KeepAlive != nil {
		d, e := parseKeepAlive(raw.KeepAlive)
		if e != nil {
			return 0, 0, false, e
		}
		keepAlive = d
	}
	var contextLength uint64
	var contextLengthKnown bool
	if raw.ContextLength != nil {
		if value, e := parseContextLength(raw.ContextLength); e != nil {
			return 0, 0, false, e
		} else {
			contextLength = value
			contextLengthKnown = true
		}
	}
	return keepAlive, contextLength, contextLengthKnown, nil
}

func decodeLifecycle(params json.RawMessage, target any) error {
	if len(params) == 0 {
		return provider.ErrInvalidCommand
	}
	// A structurally blind envelope: unknown keys (shell, url, address,
	// command, path, endpoint, ...) are rejected, so the registry never
	// accepts a network or path surface to dispatch to a provider client.
	dec := json.NewDecoder(bytes.NewReader(params))
	dec.DisallowUnknownFields()
	if e := dec.Decode(target); e != nil {
		return provider.ErrInvalidCommand
	}
	return nil
}

func parseKeepAlive(raw json.RawMessage) (time.Duration, error) {
	if len(raw) == 0 {
		return 0, nil
	}
	var scalar any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&scalar); err != nil {
		return 0, provider.ErrInvalidCommand
	}
	switch value := scalar.(type) {
	case string:
		if value == "" {
			return 0, nil
		}
		d, e := time.ParseDuration(value)
		if e != nil {
			return 0, provider.ErrInvalidCommand
		}
		if d != 0 && !validKeepAlive(d) {
			return 0, provider.ErrInvalidCommand
		}
		return d, nil
	case json.Number:
		seconds, err := value.Int64()
		if err != nil {
			return 0, provider.ErrInvalidCommand
		}
		if seconds < 0 {
			return 0, provider.ErrInvalidCommand
		}
		return time.Duration(seconds) * time.Second, nil
	default:
		return 0, provider.ErrInvalidCommand
	}
}

func parseContextLength(raw json.RawMessage) (uint64, error) {
	if len(raw) == 0 {
		return 0, nil
	}
	var scalar any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&scalar); err != nil {
		return 0, provider.ErrInvalidCommand
	}
	number, ok := scalar.(json.Number)
	if !ok {
		return 0, provider.ErrInvalidCommand
	}
	value, err := strconv.ParseUint(number.String(), 10, 64)
	if err != nil {
		return 0, provider.ErrInvalidCommand
	}
	if value < 1 || value > provider.MaximumContextLength {
		return 0, provider.ErrInvalidCommand
	}
	return value, nil
}

func validKeepAlive(d time.Duration) bool {
	return d > 0 && d <= provider.KeepAliveMaximum && d%time.Second == 0
}
