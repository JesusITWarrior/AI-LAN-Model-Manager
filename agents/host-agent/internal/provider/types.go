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
