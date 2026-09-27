package provider

import "encoding/json"

// Kind identifies a model runtime adapter.
type Kind string

const KindOllama Kind = "ollama"

// Health is the normalized provider readiness state.
type Health string

const HealthReady Health = "ready"

// VersionInfo is a parsed provider version. Raw is the normalized version text.
// It marshals as that string so the provider probe wire contract remains scalar.
type VersionInfo struct {
	Raw        string
	Major      uint16
	Minor      uint16
	Patch      uint16
	Prerelease string
}

// UnknownVersion is the zero-value VersionInfo: the provider did not expose a
// usable version. It marshals as an empty scalar string, so the probe wire
// contract stays scalar whether or not a version is known.
func UnknownVersion() VersionInfo { return VersionInfo{} }

// MarshalJSON keeps VersionInfo's JSON representation a safely escaped string.
func (version VersionInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(version.Raw)
}

// ProviderProbe is the normalized result of a successful provider health probe.
// VersionKnown is true only when Version contains a provider-validated version.
// When VersionKnown is false, Version must equal the comparable zero value from
// UnknownVersion. ProviderProbe carries no model inventory: a health probe may
// validate inventory response shape, but never returns model identifiers.
type ProviderProbe struct {
	ProviderID   string      `json:"providerId"`
	Kind         Kind        `json:"kind"`
	Endpoint     string      `json:"endpoint"`
	Health       Health      `json:"health"`
	Version      VersionInfo `json:"version"`
	VersionKnown bool        `json:"versionKnown"`
	ObservedAt   string      `json:"observedAt"`
}

// InstalledModel is provider-neutral metadata for one locally installed model.
// ModelID is stable for the provider, canonical name, and content digest.
type InstalledModel struct {
	ModelID       string   `json:"modelId"`
	ProviderID    string   `json:"providerId"`
	CanonicalName string   `json:"canonicalName"`
	DisplayName   string   `json:"displayName"`
	Digest        string   `json:"digest"`
	SizeBytes     uint64   `json:"sizeBytes"`
	ModifiedAt    string   `json:"modifiedAt"`
	ParentModel   string   `json:"parentModel"`
	Format        string   `json:"format"`
	Family        string   `json:"family"`
	Families      []string `json:"families"`
	ParameterSize string   `json:"parameterSize"`
	Quantization  string   `json:"quantization"`
}

// AvailableModelState is the provider-reported availability of a model.
type AvailableModelState string

const (
	// AvailableModelStateAvailable means the provider currently exposes the model.
	AvailableModelStateAvailable AvailableModelState = "available"
)

// AvailableModel is provider-neutral metadata for a model exposed by a
// provider's model inventory. It intentionally contains only source-backed
// metadata; provider-specific artifact details must not be guessed. Owner and
// CreatedAt are populated only when their corresponding Known field is true.
type AvailableModel struct {
	ModelID        string              `json:"modelId"`
	ProviderID     string              `json:"providerId"`
	CanonicalName  string              `json:"canonicalName"`
	DisplayName    string              `json:"displayName"`
	State          AvailableModelState `json:"state"`
	Owner          string              `json:"owner"`
	OwnerKnown     bool                `json:"ownerKnown"`
	CreatedAt      string              `json:"createdAt"`
	CreatedAtKnown bool                `json:"createdAtKnown"`
	Capabilities   []string            `json:"capabilities"`
	Modalities     []string            `json:"modalities"`
}

// ModelType is the provider-reported purpose of a catalog model.
type ModelType string

const (
	ModelTypeLLM       ModelType = "llm"
	ModelTypeEmbedding ModelType = "embedding"
)

// ModelCatalogEntry is provider-neutral detailed metadata for one model in a
// provider's native catalog. CanonicalName preserves the provider's source key;
// adapters use an ASCII-lowercase copy only for key comparison, ordering, and
// stable identity. A Known field distinguishes an absent or explicit null
// source value from the corresponding Go zero value. All slices are non-nil,
// including when the provider reports no values. Loaded is derived only from
// whether LoadedInstances is non-empty.
type ModelCatalogEntry struct {
	ModelID                 string                `json:"modelId"`
	ProviderID              string                `json:"providerId"`
	CanonicalName           string                `json:"canonicalName"`
	DisplayName             string                `json:"displayName"`
	Type                    ModelType             `json:"type"`
	Publisher               string                `json:"publisher"`
	Architecture            string                `json:"architecture"`
	ArchitectureKnown       bool                  `json:"architectureKnown"`
	QuantizationKnown       bool                  `json:"quantizationKnown"`
	Quantization            string                `json:"quantization"`
	QuantizationNameKnown   bool                  `json:"quantizationNameKnown"`
	BitsPerWeight           float64               `json:"bitsPerWeight"`
	BitsPerWeightKnown      bool                  `json:"bitsPerWeightKnown"`
	SizeBytes               uint64                `json:"sizeBytes"`
	ParameterSize           string                `json:"parameterSize"`
	ParameterSizeKnown      bool                  `json:"parameterSizeKnown"`
	MaximumContextLength    uint64                `json:"maximumContextLength"`
	Format                  string                `json:"format"`
	FormatKnown             bool                  `json:"formatKnown"`
	CapabilitiesKnown       bool                  `json:"capabilitiesKnown"`
	Vision                  bool                  `json:"vision"`
	TrainedForToolUse       bool                  `json:"trainedForToolUse"`
	ReasoningKnown          bool                  `json:"reasoningKnown"`
	ReasoningAllowedOptions []string              `json:"reasoningAllowedOptions"`
	ReasoningDefault        string                `json:"reasoningDefault"`
	Description             string                `json:"description"`
	DescriptionKnown        bool                  `json:"descriptionKnown"`
	Variants                []string              `json:"variants"`
	SelectedVariant         string                `json:"selectedVariant"`
	SelectedVariantKnown    bool                  `json:"selectedVariantKnown"`
	Loaded                  bool                  `json:"loaded"`
	LoadedInstances         []LoadedModelInstance `json:"loadedInstances"`
}

// LoadedModelInstance is a provider-neutral observation of one native loaded
// model instance. InstanceID is a provider-scoped stable identifier generated
// by the adapter; ProviderInstanceID preserves the provider's opaque id. Known
// fields distinguish absent optional configuration from false or zero.
type LoadedModelInstance struct {
	InstanceID               string `json:"instanceId"`
	ProviderInstanceID       string `json:"providerInstanceId"`
	ProviderID               string `json:"providerId"`
	ModelID                  string `json:"modelId"`
	CanonicalName            string `json:"canonicalName"`
	ContextLength            uint64 `json:"contextLength"`
	EvaluationBatchSize      uint64 `json:"evaluationBatchSize"`
	EvaluationBatchSizeKnown bool   `json:"evaluationBatchSizeKnown"`
	Parallel                 uint64 `json:"parallel"`
	ParallelKnown            bool   `json:"parallelKnown"`
	FlashAttention           bool   `json:"flashAttention"`
	FlashAttentionKnown      bool   `json:"flashAttentionKnown"`
	NumberOfExperts          uint64 `json:"numberOfExperts"`
	NumberOfExpertsKnown     bool   `json:"numberOfExpertsKnown"`
	OffloadKVCacheToGPU      bool   `json:"offloadKvCacheToGpu"`
	OffloadKVCacheToGPUKnown bool   `json:"offloadKvCacheToGpuKnown"`
	ObservedAt               string `json:"observedAt"`
}

// RunningModel is a provider-neutral observation of one loaded model.
// RuntimeID is stable for the provider, canonical name, and content digest.
// Capabilities contains only capabilities explicitly reported by the source.
type RunningModel struct {
	RuntimeID     string    `json:"runtimeId"`
	ProviderID    string    `json:"providerId"`
	CanonicalName string    `json:"canonicalName"`
	DisplayName   string    `json:"displayName"`
	Digest        string    `json:"digest"`
	SizeBytes     uint64    `json:"sizeBytes"`
	SizeVRAMBytes uint64    `json:"sizeVramBytes"`
	ExpiresAt     string    `json:"expiresAt"`
	ContextLength uint64    `json:"contextLength"`
	ParentModel   string    `json:"parentModel"`
	Format        string    `json:"format"`
	Family        string    `json:"family"`
	Families      []string  `json:"families"`
	ParameterSize string    `json:"parameterSize"`
	Quantization  string    `json:"quantization"`
	Capabilities  []string  `json:"capabilities"`
	ObservedAt    string    `json:"observedAt"`
	Residency     Residency `json:"residency"`
	Modalities    []string  `json:"modalities"`
}

// Residency identifies how a running model's tensors are distributed across
// device memory. It is provider-neutral and normalized from size and size_vram
// only; it is never inferred from the model family, name, or capabilities.
type Residency string

const (
	// ResidencyCPU indicates no tensors were staged in device memory (size_vram is 0).
	ResidencyCPU Residency = "cpu"
	// ResidencyGPU indicates every tensor is staged in device memory (size_vram == size, size > 0).
	ResidencyGPU Residency = "gpu"
	// ResidencySplit indicates tensors span both host and device memory (0 < size_vram < size).
	ResidencySplit Residency = "split"
)
