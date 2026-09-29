package fleet

import (
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
)

type ProviderObservation struct {
	ProviderID  string  `json:"providerId"`
	Kind        string  `json:"kind"`
	DisplayName string  `json:"displayName"`
	Endpoint    string  `json:"endpoint"`
	Health      string  `json:"health"`
	Version     *string `json:"version"`
	ObservedAt  string  `json:"observedAt"`
}
type ModelCapability struct {
	Tools         bool     `json:"tools"`
	Vision        bool     `json:"vision"`
	Reasoning     bool     `json:"reasoning"`
	Modalities    []string `json:"modalities"`
	ContextWindow *uint64  `json:"contextWindow"`
}
type InstalledModelObservation struct {
	ModelID          string          `json:"modelId"`
	ProviderID       string          `json:"providerId"`
	DisplayName      string          `json:"displayName"`
	ArtifactState    string          `json:"artifactState"`
	RuntimeState     string          `json:"runtimeState"`
	ActiveRequests   uint64          `json:"activeRequests"`
	SizeBytes        *uint64         `json:"sizeBytes"`
	ManagedTemporary bool            `json:"managedTemporary"`
	Pinned           bool            `json:"pinned"`
	Capability       ModelCapability `json:"capability"`
	ObservedAt       string          `json:"observedAt"`
}

// MapInventory converts the existing provider-neutral probe and installed model
// records into the exact shared fleet wire observations. It intentionally maps
// no credentials, provider-specific payloads, or inferred capabilities.
func MapInventory(probes []provider.ProviderProbe, models []provider.InstalledModel, observedAt string) ([]ProviderObservation, []InstalledModelObservation) {
	providers := make([]ProviderObservation, 0, len(probes))
	for _, probe := range probes {
		kind := string(probe.Kind)
		if kind == "lmstudio" {
			kind = "lm-studio"
		}
		var version *string
		if probe.VersionKnown {
			value := probe.Version.Raw
			version = &value
		}
		providers = append(providers, ProviderObservation{ProviderID: probe.ProviderID, Kind: kind, DisplayName: probe.ProviderID, Endpoint: probe.Endpoint, Health: string(probe.Health), Version: version, ObservedAt: probe.ObservedAt})
	}
	installed := make([]InstalledModelObservation, 0, len(models))
	for _, model := range models {
		var size *uint64
		if model.SizeBytes <= 9_007_199_254_740_991 {
			value := model.SizeBytes
			size = &value
		}
		installed = append(installed, InstalledModelObservation{ModelID: model.ModelID, ProviderID: model.ProviderID, DisplayName: model.DisplayName, ArtifactState: "installed", RuntimeState: "unloaded", SizeBytes: size, Capability: ModelCapability{Modalities: []string{}}, ObservedAt: observedAt})
	}
	return providers, installed
}
