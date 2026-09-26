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

// MarshalJSON keeps VersionInfo's JSON representation a safely escaped string.
func (version VersionInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(version.Raw)
}

// ProviderProbe is the normalized result of a successful provider health probe.
type ProviderProbe struct {
	ProviderID string      `json:"providerId"`
	Kind       Kind        `json:"kind"`
	Endpoint   string      `json:"endpoint"`
	Health     Health      `json:"health"`
	Version    VersionInfo `json:"version"`
	ObservedAt string      `json:"observedAt"`
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
