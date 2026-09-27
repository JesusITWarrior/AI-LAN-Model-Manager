package lmstudio

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
)

const (
	MaximumNativeModelsBodySize = 2 * 1024 * 1024
	MaximumNativeModels         = 10000
	MaximumLoadedInstances      = 32
	MaximumModelVariants        = 64

	maximumNativeDisplayLength     = 512
	maximumNativeMetadataLength    = 256
	maximumNativeDescriptionLength = 8192
	maximumNativeContextLength     = 10_000_000
	maximumNativeBatchSize         = 10_000_000
	maximumNativeParallel          = 1_000_000
	maximumNativeExperts           = 1_000_000
)

var (
	ErrNativeModelsFailed           = errors.New("lmstudio native-model request failed")
	ErrNativeModelsHTTPStatus       = errors.New("lmstudio native-model request returned unexpected status")
	ErrNativeModelsResponseTooLarge = errors.New("lmstudio native-model response too large")
	ErrInvalidNativeModelsResponse  = errors.New("invalid lmstudio native-model response")

	nativeReasoningOptions = map[string]struct{}{
		"off": {}, "on": {}, "low": {}, "medium": {}, "high": {},
	}
	nativeIdentifierPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,511}$`)
	nativeSimpleMetadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+:/() -]*$`)
)

// ListNativeModels fetches LM Studio's native v1 catalog. In contrast to the
// OpenAI-compatible inventory, this endpoint includes source-backed artifact,
// capability, variant, and loaded-instance details.
func (client *Client) ListNativeModels(ctx context.Context) ([]provider.ModelCatalogEntry, error) {
	body, err := client.doJSON(ctx, "/api/v1/models", MaximumNativeModelsBodySize, jsonResponseErrors{
		failed: ErrNativeModelsFailed,
		status: ErrNativeModelsHTTPStatus,
		large:  ErrNativeModelsResponseTooLarge,
	})
	if err != nil {
		return nil, err
	}
	observedAt := client.clock.Now().UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
	models, err := decodeNativeModels(body, client.providerID, observedAt)
	if err != nil {
		return nil, ErrInvalidNativeModelsResponse
	}
	return models, nil
}

type nativeModel struct {
	modelType            provider.ModelType
	publisher            string
	key                  string
	displayName          string
	architecture         string
	architectureKnown    bool
	quantization         nativeQuantization
	quantizationKnown    bool
	sizeBytes            uint64
	parameterSize        string
	parameterSizeKnown   bool
	loadedInstances      []nativeInstance
	maximumContextLength uint64
	format               string
	formatKnown          bool
	capabilities         nativeCapabilities
	capabilitiesKnown    bool
	description          string
	descriptionKnown     bool
	variants             []string
	variantsKnown        bool
	selectedVariant      string
	selectedVariantKnown bool
}

type nativeQuantization struct {
	name               string
	nameKnown          bool
	bitsPerWeight      float64
	bitsPerWeightKnown bool
}

type nativeCapabilities struct {
	vision            bool
	trainedForToolUse bool
	reasoning         nativeReasoning
	reasoningKnown    bool
}

type nativeReasoning struct {
	allowedOptions []string
	defaultOption  string
}

type nativeInstance struct {
	id                       string
	contextLength            uint64
	evaluationBatchSize      uint64
	evaluationBatchSizeKnown bool
	parallel                 uint64
	parallelKnown            bool
	flashAttention           bool
	flashAttentionKnown      bool
	numberOfExperts          uint64
	numberOfExpertsKnown     bool
	offloadKVCacheToGPU      bool
	offloadKVCacheToGPUKnown bool
}

func decodeNativeModels(body []byte, providerID, observedAt string) ([]provider.ModelCatalogEntry, error) {
	if !utf8.Valid(body) {
		return nil, ErrInvalidNativeModelsResponse
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, ErrInvalidNativeModelsResponse
	}
	seenModels := false
	rawModels := make([]nativeModel, 0)
	for decoder.More() {
		key, err := nativeStringToken(decoder)
		if err != nil || key != "models" || seenModels {
			return nil, ErrInvalidNativeModelsResponse
		}
		seenModels = true
		if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
			return nil, ErrInvalidNativeModelsResponse
		}
		for decoder.More() {
			if len(rawModels) == MaximumNativeModels {
				return nil, ErrInvalidNativeModelsResponse
			}
			model, err := decodeNativeModel(decoder)
			if err != nil {
				return nil, err
			}
			rawModels = append(rawModels, model)
		}
		if token, err := decoder.Token(); err != nil || token != json.Delim(']') {
			return nil, ErrInvalidNativeModelsResponse
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || !seenModels {
		return nil, ErrInvalidNativeModelsResponse
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidNativeModelsResponse
	}

	models := make([]provider.ModelCatalogEntry, 0, len(rawModels))
	modelKeys := make(map[string]struct{}, len(rawModels))
	instanceIDs := make(map[string]struct{})
	for _, raw := range rawModels {
		normalizedKey := asciiLower(raw.key)
		if _, duplicate := modelKeys[normalizedKey]; duplicate {
			return nil, ErrInvalidNativeModelsResponse
		}
		modelKeys[normalizedKey] = struct{}{}
		model, err := normalizeNativeModel(raw, providerID, observedAt, instanceIDs)
		if err != nil {
			return nil, err
		}
		models = append(models, model)
	}
	sort.Slice(models, func(i, j int) bool {
		left, right := asciiLower(models[i].CanonicalName), asciiLower(models[j].CanonicalName)
		if left != right {
			return left < right
		}
		return models[i].CanonicalName < models[j].CanonicalName
	})
	return models, nil
}

func decodeNativeModel(decoder *json.Decoder) (nativeModel, error) {
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nativeModel{}, ErrInvalidNativeModelsResponse
	}
	var model nativeModel
	seen := make(map[string]bool, 16)
	for decoder.More() {
		key, err := nativeStringToken(decoder)
		if err != nil || seen[key] {
			return nativeModel{}, ErrInvalidNativeModelsResponse
		}
		seen[key] = true
		switch key {
		case "type":
			var value string
			if err = decoder.Decode(&value); err == nil {
				model.modelType = provider.ModelType(value)
			}
		case "publisher":
			err = decoder.Decode(&model.publisher)
		case "key":
			err = decoder.Decode(&model.key)
		case "display_name":
			err = decoder.Decode(&model.displayName)
		case "architecture":
			model.architecture, model.architectureKnown, err = decodeNullableString(decoder)
		case "quantization":
			model.quantization, model.quantizationKnown, err = decodeNativeQuantization(decoder)
		case "size_bytes":
			model.sizeBytes, err = nativeUint64(decoder)
		case "params_string":
			model.parameterSize, model.parameterSizeKnown, err = decodeNullableString(decoder)
		case "loaded_instances":
			model.loadedInstances, err = decodeNativeInstances(decoder)
		case "max_context_length":
			model.maximumContextLength, err = nativeUint64(decoder)
		case "format":
			model.format, model.formatKnown, err = decodeNullableString(decoder)
		case "capabilities":
			model.capabilities, err = decodeNativeCapabilities(decoder)
			model.capabilitiesKnown = err == nil
		case "description":
			model.description, model.descriptionKnown, err = decodeNullableString(decoder)
		case "variants":
			model.variants, err = decodeNativeVariants(decoder)
			model.variantsKnown = err == nil
		case "selected_variant":
			err = decoder.Decode(&model.selectedVariant)
			model.selectedVariantKnown = err == nil
		default:
			return nativeModel{}, ErrInvalidNativeModelsResponse
		}
		if err != nil {
			return nativeModel{}, ErrInvalidNativeModelsResponse
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nativeModel{}, ErrInvalidNativeModelsResponse
	}
	for _, required := range []string{"type", "publisher", "key", "display_name", "quantization", "size_bytes", "params_string", "loaded_instances", "max_context_length", "format"} {
		if !seen[required] {
			return nativeModel{}, ErrInvalidNativeModelsResponse
		}
	}
	return model, nil
}

func decodeNativeQuantization(decoder *json.Decoder) (nativeQuantization, bool, error) {
	token, err := decoder.Token()
	if err != nil {
		return nativeQuantization{}, false, err
	}
	if token == nil {
		return nativeQuantization{}, false, nil
	}
	if token != json.Delim('{') {
		return nativeQuantization{}, false, ErrInvalidNativeModelsResponse
	}
	var value nativeQuantization
	seen := make(map[string]bool, 2)
	for decoder.More() {
		key, err := nativeStringToken(decoder)
		if err != nil || seen[key] {
			return nativeQuantization{}, false, ErrInvalidNativeModelsResponse
		}
		seen[key] = true
		switch key {
		case "name":
			value.name, value.nameKnown, err = decodeNullableString(decoder)
		case "bits_per_weight":
			value.bitsPerWeight, value.bitsPerWeightKnown, err = decodeNullableFloat(decoder)
		default:
			return nativeQuantization{}, false, ErrInvalidNativeModelsResponse
		}
		if err != nil {
			return nativeQuantization{}, false, err
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || !seen["name"] || !seen["bits_per_weight"] {
		return nativeQuantization{}, false, ErrInvalidNativeModelsResponse
	}
	return value, true, nil
}

func decodeNativeCapabilities(decoder *json.Decoder) (nativeCapabilities, error) {
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nativeCapabilities{}, ErrInvalidNativeModelsResponse
	}
	var value nativeCapabilities
	seen := make(map[string]bool, 3)
	for decoder.More() {
		key, err := nativeStringToken(decoder)
		if err != nil || seen[key] {
			return nativeCapabilities{}, ErrInvalidNativeModelsResponse
		}
		seen[key] = true
		switch key {
		case "vision":
			value.vision, err = nativeBool(decoder)
		case "trained_for_tool_use":
			value.trainedForToolUse, err = nativeBool(decoder)
		case "reasoning":
			value.reasoning, err = decodeNativeReasoning(decoder)
			value.reasoningKnown = err == nil
		default:
			return nativeCapabilities{}, ErrInvalidNativeModelsResponse
		}
		if err != nil {
			return nativeCapabilities{}, ErrInvalidNativeModelsResponse
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || !seen["vision"] || !seen["trained_for_tool_use"] {
		return nativeCapabilities{}, ErrInvalidNativeModelsResponse
	}
	return value, nil
}

func decodeNativeReasoning(decoder *json.Decoder) (nativeReasoning, error) {
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nativeReasoning{}, ErrInvalidNativeModelsResponse
	}
	var value nativeReasoning
	seen := make(map[string]bool, 2)
	for decoder.More() {
		key, err := nativeStringToken(decoder)
		if err != nil || seen[key] {
			return nativeReasoning{}, ErrInvalidNativeModelsResponse
		}
		seen[key] = true
		switch key {
		case "allowed_options":
			value.allowedOptions, err = decodeReasoningOptions(decoder)
		case "default":
			err = decoder.Decode(&value.defaultOption)
			if err == nil {
				_, valid := nativeReasoningOptions[value.defaultOption]
				if !valid {
					err = ErrInvalidNativeModelsResponse
				}
			}
		default:
			return nativeReasoning{}, ErrInvalidNativeModelsResponse
		}
		if err != nil {
			return nativeReasoning{}, ErrInvalidNativeModelsResponse
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || !seen["allowed_options"] || !seen["default"] {
		return nativeReasoning{}, ErrInvalidNativeModelsResponse
	}
	if !containsString(value.allowedOptions, value.defaultOption) {
		return nativeReasoning{}, ErrInvalidNativeModelsResponse
	}
	return value, nil
}

func decodeReasoningOptions(decoder *json.Decoder) ([]string, error) {
	if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
		return nil, ErrInvalidNativeModelsResponse
	}
	values := make([]string, 0)
	seen := make(map[string]struct{})
	for decoder.More() {
		if len(values) == len(nativeReasoningOptions) {
			return nil, ErrInvalidNativeModelsResponse
		}
		value, err := nativeStringToken(decoder)
		if err != nil {
			return nil, ErrInvalidNativeModelsResponse
		}
		if _, valid := nativeReasoningOptions[value]; !valid {
			return nil, ErrInvalidNativeModelsResponse
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, ErrInvalidNativeModelsResponse
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim(']') || len(values) == 0 {
		return nil, ErrInvalidNativeModelsResponse
	}
	sort.Strings(values)
	return values, nil
}

func decodeNativeVariants(decoder *json.Decoder) ([]string, error) {
	if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
		return nil, ErrInvalidNativeModelsResponse
	}
	values := make([]string, 0)
	seen := make(map[string]struct{})
	for decoder.More() {
		if len(values) == MaximumModelVariants {
			return nil, ErrInvalidNativeModelsResponse
		}
		value, err := nativeStringToken(decoder)
		if err != nil || !validNativeIdentifier(value) {
			return nil, ErrInvalidNativeModelsResponse
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, ErrInvalidNativeModelsResponse
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim(']') {
		return nil, ErrInvalidNativeModelsResponse
	}
	sort.Slice(values, func(i, j int) bool {
		left, right := strings.ToLower(values[i]), strings.ToLower(values[j])
		if left != right {
			return left < right
		}
		return values[i] < values[j]
	})
	return values, nil
}

func decodeNativeInstances(decoder *json.Decoder) ([]nativeInstance, error) {
	if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
		return nil, ErrInvalidNativeModelsResponse
	}
	values := make([]nativeInstance, 0)
	seen := make(map[string]struct{})
	for decoder.More() {
		if len(values) == MaximumLoadedInstances {
			return nil, ErrInvalidNativeModelsResponse
		}
		value, err := decodeNativeInstance(decoder)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[value.id]; duplicate {
			return nil, ErrInvalidNativeModelsResponse
		}
		seen[value.id] = struct{}{}
		values = append(values, value)
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim(']') {
		return nil, ErrInvalidNativeModelsResponse
	}
	sort.Slice(values, func(i, j int) bool {
		left, right := strings.ToLower(values[i].id), strings.ToLower(values[j].id)
		if left != right {
			return left < right
		}
		return values[i].id < values[j].id
	})
	return values, nil
}

func decodeNativeInstance(decoder *json.Decoder) (nativeInstance, error) {
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nativeInstance{}, ErrInvalidNativeModelsResponse
	}
	var value nativeInstance
	seen := make(map[string]bool, 2)
	for decoder.More() {
		key, err := nativeStringToken(decoder)
		if err != nil || seen[key] {
			return nativeInstance{}, ErrInvalidNativeModelsResponse
		}
		seen[key] = true
		switch key {
		case "id":
			err = decoder.Decode(&value.id)
		case "config":
			value, err = decodeNativeInstanceConfig(decoder, value)
		default:
			return nativeInstance{}, ErrInvalidNativeModelsResponse
		}
		if err != nil {
			return nativeInstance{}, ErrInvalidNativeModelsResponse
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || !seen["id"] || !seen["config"] || !validNativeIdentifier(value.id) {
		return nativeInstance{}, ErrInvalidNativeModelsResponse
	}
	return value, nil
}

func decodeNativeInstanceConfig(decoder *json.Decoder, value nativeInstance) (nativeInstance, error) {
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nativeInstance{}, ErrInvalidNativeModelsResponse
	}
	seen := make(map[string]bool, 6)
	for decoder.More() {
		key, err := nativeStringToken(decoder)
		if err != nil || seen[key] {
			return nativeInstance{}, ErrInvalidNativeModelsResponse
		}
		seen[key] = true
		switch key {
		case "context_length":
			value.contextLength, err = nativeUint64(decoder)
		case "eval_batch_size":
			value.evaluationBatchSize, err = nativeUint64(decoder)
			value.evaluationBatchSizeKnown = err == nil
		case "parallel":
			value.parallel, err = nativeUint64(decoder)
			value.parallelKnown = err == nil
		case "flash_attention":
			value.flashAttention, err = nativeBool(decoder)
			value.flashAttentionKnown = err == nil
		case "num_experts":
			value.numberOfExperts, err = nativeUint64(decoder)
			value.numberOfExpertsKnown = err == nil
		case "offload_kv_cache_to_gpu":
			value.offloadKVCacheToGPU, err = nativeBool(decoder)
			value.offloadKVCacheToGPUKnown = err == nil
		default:
			return nativeInstance{}, ErrInvalidNativeModelsResponse
		}
		if err != nil {
			return nativeInstance{}, ErrInvalidNativeModelsResponse
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || !seen["context_length"] {
		return nativeInstance{}, ErrInvalidNativeModelsResponse
	}
	return value, nil
}

func normalizeNativeModel(raw nativeModel, providerID, observedAt string, globalInstanceIDs map[string]struct{}) (provider.ModelCatalogEntry, error) {
	if raw.modelType != provider.ModelTypeLLM && raw.modelType != provider.ModelTypeEmbedding {
		return provider.ModelCatalogEntry{}, ErrInvalidNativeModelsResponse
	}
	if !validNativeIdentifier(raw.key) || !validNativeText(raw.displayName, maximumNativeDisplayLength) || !validNativeMetadata(raw.publisher) {
		return provider.ModelCatalogEntry{}, ErrInvalidNativeModelsResponse
	}
	if raw.architectureKnown && !validNativeMetadata(raw.architecture) {
		return provider.ModelCatalogEntry{}, ErrInvalidNativeModelsResponse
	}
	if raw.quantizationKnown {
		if raw.quantization.nameKnown && !validNativeMetadata(raw.quantization.name) {
			return provider.ModelCatalogEntry{}, ErrInvalidNativeModelsResponse
		}
		if raw.quantization.bitsPerWeightKnown && (raw.quantization.bitsPerWeight <= 0 || raw.quantization.bitsPerWeight > 128) {
			return provider.ModelCatalogEntry{}, ErrInvalidNativeModelsResponse
		}
	}
	if raw.parameterSizeKnown && !validNativeMetadata(raw.parameterSize) {
		return provider.ModelCatalogEntry{}, ErrInvalidNativeModelsResponse
	}
	if raw.maximumContextLength < 1 || raw.maximumContextLength > maximumNativeContextLength {
		return provider.ModelCatalogEntry{}, ErrInvalidNativeModelsResponse
	}
	if raw.formatKnown && raw.format != "gguf" && raw.format != "mlx" {
		return provider.ModelCatalogEntry{}, ErrInvalidNativeModelsResponse
	}
	if raw.descriptionKnown && !validNativeText(raw.description, maximumNativeDescriptionLength) {
		return provider.ModelCatalogEntry{}, ErrInvalidNativeModelsResponse
	}
	if raw.selectedVariantKnown && (!raw.variantsKnown || !validNativeIdentifier(raw.selectedVariant) || !containsString(raw.variants, raw.selectedVariant)) {
		return provider.ModelCatalogEntry{}, ErrInvalidNativeModelsResponse
	}
	if raw.modelType == provider.ModelTypeEmbedding && (raw.architectureKnown || raw.capabilitiesKnown || raw.descriptionKnown) {
		return provider.ModelCatalogEntry{}, ErrInvalidNativeModelsResponse
	}
	// Preserve raw.key in the returned catalog entry, but normalize its ASCII
	// case for identity so source-only case changes do not churn catalog IDs.
	modelDigest := sha256.Sum256([]byte(providerID + "\x00" + asciiLower(raw.key)))
	modelID := "lmstudio-" + hex.EncodeToString(modelDigest[:])
	instances := make([]provider.LoadedModelInstance, 0, len(raw.loadedInstances))
	for _, rawInstance := range raw.loadedInstances {
		if _, duplicate := globalInstanceIDs[rawInstance.id]; duplicate {
			return provider.ModelCatalogEntry{}, ErrInvalidNativeModelsResponse
		}
		globalInstanceIDs[rawInstance.id] = struct{}{}
		instance, err := normalizeNativeInstance(rawInstance, providerID, modelID, raw.key, observedAt, raw.modelType)
		if err != nil {
			return provider.ModelCatalogEntry{}, err
		}
		instances = append(instances, instance)
	}
	options := make([]string, len(raw.capabilities.reasoning.allowedOptions))
	copy(options, raw.capabilities.reasoning.allowedOptions)
	variants := make([]string, len(raw.variants))
	copy(variants, raw.variants)
	return provider.ModelCatalogEntry{
		ModelID:                 modelID,
		ProviderID:              providerID,
		CanonicalName:           raw.key,
		DisplayName:             raw.displayName,
		Type:                    raw.modelType,
		Publisher:               raw.publisher,
		Architecture:            raw.architecture,
		ArchitectureKnown:       raw.architectureKnown,
		QuantizationKnown:       raw.quantizationKnown,
		Quantization:            raw.quantization.name,
		QuantizationNameKnown:   raw.quantization.nameKnown,
		BitsPerWeight:           raw.quantization.bitsPerWeight,
		BitsPerWeightKnown:      raw.quantization.bitsPerWeightKnown,
		SizeBytes:               raw.sizeBytes,
		ParameterSize:           raw.parameterSize,
		ParameterSizeKnown:      raw.parameterSizeKnown,
		MaximumContextLength:    raw.maximumContextLength,
		Format:                  raw.format,
		FormatKnown:             raw.formatKnown,
		CapabilitiesKnown:       raw.capabilitiesKnown,
		Vision:                  raw.capabilities.vision,
		TrainedForToolUse:       raw.capabilities.trainedForToolUse,
		ReasoningKnown:          raw.capabilities.reasoningKnown,
		ReasoningAllowedOptions: options,
		ReasoningDefault:        raw.capabilities.reasoning.defaultOption,
		Description:             raw.description,
		DescriptionKnown:        raw.descriptionKnown,
		Variants:                variants,
		SelectedVariant:         raw.selectedVariant,
		SelectedVariantKnown:    raw.selectedVariantKnown,
		Loaded:                  len(instances) > 0,
		LoadedInstances:         instances,
	}, nil
}

func normalizeNativeInstance(raw nativeInstance, providerID, modelID, canonicalName, observedAt string, modelType provider.ModelType) (provider.LoadedModelInstance, error) {
	if raw.contextLength < 1 || raw.contextLength > maximumNativeContextLength ||
		(raw.evaluationBatchSizeKnown && (raw.evaluationBatchSize < 1 || raw.evaluationBatchSize > maximumNativeBatchSize)) ||
		(raw.parallelKnown && (raw.parallel < 1 || raw.parallel > maximumNativeParallel)) ||
		(raw.numberOfExpertsKnown && (raw.numberOfExperts < 1 || raw.numberOfExperts > maximumNativeExperts)) {
		return provider.LoadedModelInstance{}, ErrInvalidNativeModelsResponse
	}
	if modelType == provider.ModelTypeEmbedding && (raw.evaluationBatchSizeKnown || raw.parallelKnown || raw.flashAttentionKnown || raw.numberOfExpertsKnown || raw.offloadKVCacheToGPUKnown) {
		return provider.LoadedModelInstance{}, ErrInvalidNativeModelsResponse
	}
	instanceDigest := sha256.Sum256([]byte(providerID + "\x00" + canonicalName + "\x00" + raw.id))
	return provider.LoadedModelInstance{
		InstanceID:               "lmstudio-instance-" + hex.EncodeToString(instanceDigest[:]),
		ProviderInstanceID:       raw.id,
		ProviderID:               providerID,
		ModelID:                  modelID,
		CanonicalName:            canonicalName,
		ContextLength:            raw.contextLength,
		EvaluationBatchSize:      raw.evaluationBatchSize,
		EvaluationBatchSizeKnown: raw.evaluationBatchSizeKnown,
		Parallel:                 raw.parallel,
		ParallelKnown:            raw.parallelKnown,
		FlashAttention:           raw.flashAttention,
		FlashAttentionKnown:      raw.flashAttentionKnown,
		NumberOfExperts:          raw.numberOfExperts,
		NumberOfExpertsKnown:     raw.numberOfExpertsKnown,
		OffloadKVCacheToGPU:      raw.offloadKVCacheToGPU,
		OffloadKVCacheToGPUKnown: raw.offloadKVCacheToGPUKnown,
		ObservedAt:               observedAt,
	}, nil
}

func decodeNullableString(decoder *json.Decoder) (string, bool, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", false, err
	}
	if token == nil {
		return "", false, nil
	}
	value, ok := token.(string)
	if !ok {
		return "", false, ErrInvalidNativeModelsResponse
	}
	return value, true, nil
}

func decodeNullableFloat(decoder *json.Decoder) (float64, bool, error) {
	token, err := decoder.Token()
	if err != nil {
		return 0, false, err
	}
	if token == nil {
		return 0, false, nil
	}
	number, ok := token.(json.Number)
	if !ok {
		return 0, false, ErrInvalidNativeModelsResponse
	}
	value, err := strconv.ParseFloat(number.String(), 64)
	if err != nil || math.IsInf(value, 0) || math.IsNaN(value) {
		return 0, false, ErrInvalidNativeModelsResponse
	}
	return value, true, nil
}

func nativeUint64(decoder *json.Decoder) (uint64, error) {
	token, err := decoder.Token()
	if err != nil {
		return 0, err
	}
	number, ok := token.(json.Number)
	if !ok {
		return 0, ErrInvalidNativeModelsResponse
	}
	return strconv.ParseUint(number.String(), 10, 64)
}

func nativeStringToken(decoder *json.Decoder) (string, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", err
	}
	value, ok := token.(string)
	if !ok {
		return "", ErrInvalidNativeModelsResponse
	}
	return value, nil
}

func nativeBool(decoder *json.Decoder) (bool, error) {
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	value, ok := token.(bool)
	if !ok {
		return false, ErrInvalidNativeModelsResponse
	}
	return value, nil
}

func validNativeIdentifier(value string) bool {
	if !nativeIdentifierPattern.MatchString(value) {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func validNativeMetadata(value string) bool {
	return len(value) <= maximumNativeMetadataLength && nativeSimpleMetadataPattern.MatchString(value) && strings.TrimSpace(value) == value
}

func validNativeText(value string, maximum int) bool {
	if len(value) < 1 || len(value) > maximum || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f || character == utf8.RuneError {
			return false
		}
	}
	return true
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// asciiLower defines native model-key comparison semantics. Model keys are
// restricted to ASCII by validNativeIdentifier, so this deliberately avoids
// locale- or Unicode-dependent case folding.
func asciiLower(value string) string {
	buffer := []byte(value)
	for index, character := range buffer {
		if character >= 'A' && character <= 'Z' {
			buffer[index] = character + ('a' - 'A')
		}
	}
	return string(buffer)
}
