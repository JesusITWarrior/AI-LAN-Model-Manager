package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/fleet"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider/ollama"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/snapshot"
)

type inventorySnapshotSource struct{}

func (inventorySnapshotSource) LatestSnapshot() (snapshot.State, bool) { return snapshot.State{}, true }

func TestFleetCollectorInventoryAndRedactedDiagnostics(t *testing.T) {
	for _, scenario := range []struct {
		name, version, tags string
		providers, models   int
		probe, list         string
	}{
		{"ready", `{"version":"0.34.4"}`, `{"models":[{"name":"ollama.com/example/synthetic:latest","model":"ollama.com/example/synthetic:latest","modified_at":"2026-01-01T00:00:00Z","size":123,"digest":"` + strings.Repeat("a", 64) + `","capabilities":["completion","tools"],"details":{"parent_model":"","format":"gguf","family":"synthetic","families":["synthetic"],"parameter_size":"1B","quantization_level":"Q4","context_length":262144,"embedding_length":3840}}]}`, 1, 1, "ok", "ok"},
		{"list_failed", `{"version":"0.34.4"}`, `{"models":[],"secret":"never-log-this"}`, 1, 0, "ok", "invalid_response"},
		{"probe_failed", `{"secret":"never-log-this"}`, `{"models":[]}`, 0, 0, "invalid_response", "ok"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					t.Error("non-read-only request")
				}
				if r.URL.Path == "/api/version" {
					_, _ = w.Write([]byte(scenario.version))
				} else if r.URL.Path == "/api/tags" {
					_, _ = w.Write([]byte(scenario.tags))
				} else {
					t.Error("unexpected endpoint")
				}
			}))
			defer server.Close()
			client, err := ollama.New(ollama.Config{ProviderID: "ollama-local", Endpoint: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			reporter := &inventoryReporter{stateDir: dir}
			collector := fleetCollector{source: inventorySnapshotSource{}, ollama: client, report: reporter}
			result, err := collector.Collect(context.Background())
			if err != nil || providerCount(result) != scenario.providers || modelCount(result) != scenario.models {
				t.Fatalf("mapping counts: providers=%d models=%d err=%v", providerCount(result), modelCount(result), err)
			}
			path := filepath.Join(dir, "inventory-status.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var record map[string]string
			if json.Unmarshal(raw, &record) != nil || record["probe"] != scenario.probe || record["list"] != scenario.list {
				t.Fatalf("diagnostic %s", raw)
			}
			for _, secret := range []string{"never-log-this", server.URL, "synthetic"} {
				if strings.Contains(string(raw), secret) {
					t.Fatal("provider data leaked")
				}
			}
			_, _ = collector.Collect(context.Background())
			again, _ := os.ReadFile(path)
			if string(raw) != string(again) {
				t.Fatal("unchanged outcome rewritten")
			}
			reporter.record(nil, nil)
			raw, _ = os.ReadFile(path)
			if strings.Contains(string(raw), "invalid_response") {
				t.Fatal("stale failure retained")
			}
		})
	}
	if inventoryReason(errors.New("private.endpoint token")) != "request_failed" {
		t.Fatal("untrusted error not redacted")
	}
}

// Explicit opt-in; GET-only and no provider payload printed or persisted.
func TestReadOnlyNativeOllamaInventory(t *testing.T) {
	if os.Getenv("LANMM_TEST_OLLAMA_READONLY") != "1" {
		t.Skip("requires explicit read-only native provider opt-in")
	}
	client, err := ollama.New(ollama.Config{ProviderID: "ollama-local", Endpoint: "http://127.0.0.1:11434"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := (fleetCollector{source: inventorySnapshotSource{}, ollama: client}).Collect(context.Background())
	if err != nil || providerCount(result) != 1 || modelCount(result) == 0 {
		t.Fatalf("read-only collection failed: providers=%d models=%d err=%v", providerCount(result), modelCount(result), err)
	}
	t.Logf("read-only native mapping: providers=%d models=%d", providerCount(result), modelCount(result))
}

func providerCount(s fleet.Snapshot) int {
	v, _ := s.Providers.([]fleet.ProviderObservation)
	return len(v)
}
func modelCount(s fleet.Snapshot) int {
	v, _ := s.Models.([]fleet.InstalledModelObservation)
	return len(v)
}
