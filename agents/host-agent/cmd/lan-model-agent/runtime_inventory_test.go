package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/command"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/fleet"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider/ollama"
)

type runtimeInventoryDoer struct{ loaded, failed bool }

func (d *runtimeInventoryDoer) Do(r *http.Request) (*http.Response, error) {
	const name = "synthetic-model:fixture"
	base := `"name":"` + name + `","model":"` + name + `","digest":"` + strings.Repeat("a", 64) + `","size":123,"details":{"parent_model":"","format":"gguf","family":"synthetic","families":["synthetic"],"parameter_size":"1B","quantization_level":"Q4"}`
	body := ""
	switch r.URL.Path {
	case "/api/version":
		body = `{"version":"0.34.4"}`
	case "/api/tags":
		body = `{"models":[{` + base + `,"modified_at":"2026-01-01T00:00:00Z"}]}`
	case "/api/ps":
		if d.failed {
			return nil, errors.New("private failure")
		}
		body = `{"models":[]}`
		if d.loaded {
			body = `{"models":[{` + base + `,"expires_at":"2030-01-01T00:00:00Z","size_vram":123,"context_length":4096}]}`
		}
	case "/api/generate":
		d.loaded = true
		body = `{"model":"` + name + `","created_at":"2026-01-01T00:00:00Z","response":"","done":true,"done_reason":"load"}`
	default:
		return nil, errors.New("unexpected request")
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
}
func TestCollectorRuntimeLifecycle(t *testing.T) {
	ctx := context.Background()
	d := &runtimeInventoryDoer{}
	client, err := ollama.NewWithDependencies(ollama.Config{ProviderID: "synthetic-provider", Endpoint: "http://127.0.0.1:11434"}, d, provider.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	registry := command.NewHostRegistry("synthetic-host", time.Now)
	registry.RegisterOllama("synthetic-provider", client)
	c := fleetCollector{source: inventorySnapshotSource{}, ollama: client, registry: registry}
	check := func(state string, count uint64, idle bool) {
		t.Helper()
		s, err := c.Collect(ctx)
		rows, _ := s.Models.([]fleet.InstalledModelObservation)
		if err != nil || providerCount(s) != 1 || len(rows) != 1 || rows[0].RuntimeState != state || rows[0].ActiveRequests != count || s.Idle != idle {
			t.Fatalf("snapshot=%+v rows=%+v err=%v", s, rows, err)
		}
	}
	// Missing host/registry authority still publishes a valid healthy-provider
	// heartbeat, with an empty array rather than a wire-invalid null.
	unbound := c
	unbound.registry = nil
	unavailable, collectErr := unbound.Collect(ctx)
	raw, marshalErr := json.Marshal(unavailable)
	if collectErr != nil || marshalErr != nil || providerCount(unavailable) != 1 || unavailable.Idle || !strings.Contains(string(raw), `"models":[]`) {
		t.Fatal("unbound authority", string(raw), collectErr)
	}
	check("unloaded", 0, true)
	params := json.RawMessage(`{"providerId":"synthetic-provider","model":"synthetic-model:fixture","keepAlive":"30s"}`)
	if _, err = registry.Execute(ctx, "load", params); err != nil {
		t.Fatal(err)
	}
	check("serving", 0, true)
	handle, err := registry.Acquire(ctx, "synthetic-provider", "synthetic-model:fixture")
	if err != nil {
		t.Fatal(err)
	}
	check("serving", 1, false)
	d.failed = true
	check("unknown", 1, false)
	d.failed = false
	if _, err = registry.Execute(ctx, "drain", json.RawMessage(`{"providerId":"synthetic-provider","model":"synthetic-model:fixture"}`)); !errors.Is(err, command.ErrServingActive) {
		t.Fatal(err)
	}
	check("draining", 1, false)
	d.loaded = false
	check("draining", 1, false)
	_ = registry.Complete(ctx, handle)
	_ = registry.Complete(ctx, handle)
	check("draining", 0, false)
}
