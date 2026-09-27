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
