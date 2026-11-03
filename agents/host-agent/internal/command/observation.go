package command

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
)

var ErrRuntimeObservation = errors.New("runtime observation unavailable")

// RuntimeObservation exposes only fleet state and admission counts, never handles.
type RuntimeObservation struct {
	ModelID        string
	RuntimeState   string
	ActiveRequests uint64
}

// NewHostRegistry owns admission for one host service lifetime, including all
// certificate sessions. Unbound registries cannot supply fleet authority.
func NewHostRegistry(hostID string, now func() time.Time) *Registry {
	r := NewRegistry(now)
	if identifier.MatchString(hostID) {
		r.hostID = hostID
	}
	return r
}

// ObserveRuntime reads the registered adapter and snapshots admission under lock.
// It never synchronizes running state or releases handles. On unavailable running
// evidence it returns unknown state with the actual admission counts and drain
// protection. Invalid identity bindings return no model authority at all.
func (r *Registry) ObserveRuntime(ctx context.Context, hostID, providerID string, installed []provider.InstalledModel) ([]RuntimeObservation, error) {
	if r == nil {
		return nil, ErrRuntimeObservation
	}
	r.mu.Lock()
	adapter := r.clients[providerID]
	bound := r.hostID != "" && r.hostID == hostID && provider.ValidateProviderID(providerID) && adapter != nil
	epoch, pending := r.inventoryEpoch, r.inventoryPending
	r.mu.Unlock()
	if !bound || len(installed) > 10000 {
		return nil, ErrRuntimeObservation
	}
	byName := make(map[string]provider.InstalledModel, len(installed))
	for _, m := range installed {
		canonical, ok := provider.CanonicalOllamaModelName(m.CanonicalName)
		sum := sha256.Sum256([]byte(providerID + "\x00" + m.CanonicalName + "\x00" + m.Digest))
		if !ok || canonical != m.CanonicalName || m.ProviderID != providerID || len(m.Digest) != 64 || strings.Trim(m.Digest, "0123456789abcdef") != "" || m.ModelID != "ollama-"+hex.EncodeToString(sum[:]) {
			return nil, ErrRuntimeObservation
		}
		if _, duplicate := byName[m.CanonicalName]; duplicate {
			return nil, ErrRuntimeObservation
		}
		byName[m.CanonicalName] = m
	}
	started := r.now()
	running, ok := adapter.(runtimeObserver)
	var rows []provider.RunningModel
	err := ErrRuntimeObservation
	if ok {
		rows, err = running.ListRunning(ctx)
	}
	ended := r.now()
	authoritative := err == nil && rows != nil && ctx.Err() == nil && !ended.Before(started) && ended.Sub(started) <= 30*time.Second && len(rows) <= 10000
	present := make(map[string]bool, len(rows))
	for _, row := range rows {
		m, exists := byName[row.CanonicalName]
		at, parseErr := time.Parse(time.RFC3339Nano, row.ObservedAt)
		if !exists || row.ProviderID != providerID || row.Digest != m.Digest || row.RuntimeID != "ollama-runtime-"+strings.TrimPrefix(m.ModelID, "ollama-") || present[row.CanonicalName] || parseErr != nil || at.Before(started.Truncate(time.Millisecond)) || at.After(ended) || row.SizeBytes > 9_007_199_254_740_991 || row.SizeVRAMBytes > row.SizeBytes {
			authoritative = false
		}
		present[row.CanonicalName] = true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if pending != 0 || r.inventoryPending != 0 || epoch != r.inventoryEpoch {
		authoritative = false
	}
	// Missing installed identities cannot turn outstanding admission into host idle.
	for key, handles := range r.active {
		if strings.HasPrefix(key, providerID+"\x00") && len(handles) > 0 {
			if _, exists := byName[strings.TrimPrefix(key, providerID+"\x00")]; !exists {
				authoritative = false
			}
		}
	}
	for key := range r.draining {
		if strings.HasPrefix(key, providerID+"\x00") {
			if _, exists := byName[strings.TrimPrefix(key, providerID+"\x00")]; !exists {
				authoritative = false
			}
		}
	}
	out := make([]RuntimeObservation, 0, len(installed))
	for _, m := range installed {
		key := modelKey(providerID, m.CanonicalName)
		count := uint64(len(r.active[key]))
		if count > 1_000_000 {
			return nil, ErrRuntimeObservation
		}
		state := "unknown"
		if authoritative {
			state = "unloaded"
			if present[m.CanonicalName] {
				state = "serving"
			}
		}
		if _, draining := r.draining[key]; draining {
			state = "draining"
		} else if count > 0 && !present[m.CanonicalName] {
			state = "unknown"
		}
		out = append(out, RuntimeObservation{ModelID: m.ModelID, RuntimeState: state, ActiveRequests: count})
	}
	if !authoritative {
		return out, ErrRuntimeObservation
	}
	return out, nil
}
