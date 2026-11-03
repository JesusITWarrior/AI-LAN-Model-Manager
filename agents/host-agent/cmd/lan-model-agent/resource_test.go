package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/observation"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider/ollama"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/service"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/snapshot"
)

type syntheticResourceSource struct {
	value     observation.HostResourceObservation
	available bool
}

func (s syntheticResourceSource) LatestSnapshot() (snapshot.State, bool) {
	return snapshot.State{Record: snapshot.Record{HostID: "synthetic-host", Platform: "linux"}}, true
}
func (s syntheticResourceSource) LatestResourceObservation() (observation.HostResourceObservation, bool) {
	return s.value, s.available
}
func syntheticResource() observation.HostResourceObservation {
	return observation.HostResourceObservation{HostID: "synthetic-host", Platform: "linux", ObservedAt: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), CPULogicalCores: 4, Memory: observation.ResourceQuantity{TotalBytes: 100, UsedBytes: 20, AvailableBytes: 80}, Storage: observation.ResourceQuantity{TotalBytes: 200, UsedBytes: 30, AvailableBytes: 170}}
}
func TestCollectorResourceProjection(t *testing.T) {
	for _, scenario := range []string{"valid", "missing", "stale", "future", "host", "platform", "invalid", "memory-unsafe", "storage-unsafe", "accelerator-unsafe"} {
		t.Run(scenario, func(t *testing.T) {
			s := syntheticResourceSource{syntheticResource(), true}
			switch scenario {
			case "missing":
				s.available = false
			case "stale":
				s.value.ObservedAt = time.Now().Add(-time.Minute).UTC().Format("2006-01-02T15:04:05.000Z")
			case "future":
				s.value.ObservedAt = time.Now().Add(time.Minute).UTC().Format("2006-01-02T15:04:05.000Z")
			case "host":
				s.value.HostID = "other"
			case "platform":
				s.value.Platform = "windows"
			case "invalid":
				s.value.CPULogicalCores = 0
			case "memory-unsafe":
				s.value.Memory.TotalBytes = 1 << 53
			case "storage-unsafe":
				s.value.Storage.TotalBytes = 1 << 53
			case "accelerator-unsafe":
				s.value.Accelerators = []observation.AcceleratorObservation{{ID: "gpu-0", Name: "Synthetic GPU", Kind: "other", Memory: observation.ResourceQuantity{TotalBytes: 1 << 53}}}
			}
			got, err := (fleetCollector{source: s, resources: s}).Collect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if scenario != "valid" {
				if got.Resource != nil {
					t.Fatal("invalid resources emitted")
				}
				return
			}
			r := got.Resource.(observation.HostResourceObservation)
			if r.Memory != s.value.Memory || r.ObservedAt != s.value.ObservedAt || r.HostID != "synthetic-host" || r.Platform != observation.HostPlatform(got.Platform) {
				t.Fatal("resource changed")
			}
			got.ObservedAt = s.value.ObservedAt
			got.Sequence = 1
			raw, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			fmt.Printf("SYNTHETIC_RESOURCE=%s\n", raw)
		})
	}
}

type syntheticObserver struct {
	value observation.HostResourceObservation
}

func (s syntheticObserver) Observe(context.Context) (observation.HostResourceObservation, error) {
	return s.value, nil
}

type syntheticInventoryDoer struct{}

func (syntheticInventoryDoer) Do(r *http.Request) (*http.Response, error) {
	body := `{}`
	if r.URL.Path == "/api/version" {
		body = `{"version":"0.34.4"}`
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
}
func TestCollectorResourceServiceIntegration(t *testing.T) {
	value := syntheticResource()
	value.Platform = observation.HostPlatform(runtime.GOOS)
	cfg := service.Config{HostID: value.HostID, StateDir: filepath.Join(t.TempDir(), "state"), PollInterval: time.Minute, Registry: service.ProviderRegistry{Observers: []observation.Observer{syntheticObserver{value}}}}
	host, err := service.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close(context.Background())
	if err = host.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	client, err := ollama.NewWithDependencies(ollama.Config{ProviderID: "synthetic-provider", Endpoint: "http://127.0.0.1:11434"}, syntheticInventoryDoer{}, provider.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	collector := fleetCollector{source: host, resources: host, ollama: client}
	got, err := collector.Collect(context.Background())
	if err != nil || got.Resource == nil || providerCount(got) != 1 || modelCount(got) != 0 {
		t.Fatal("resource or healthy provider lost on list failure", err)
	}
	if got.Resource.(observation.HostResourceObservation).ObservedAt != value.ObservedAt {
		t.Fatal("timestamp changed")
	}
	host.Close(context.Background())
	got, err = collector.Collect(context.Background())
	if err != nil || got.Resource != nil || providerCount(got) != 1 {
		t.Fatal("closed resource authority or provider missing")
	}
	restarted, err := service.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close(context.Background())
	got, err = (fleetCollector{source: restarted, resources: restarted}).Collect(context.Background())
	if err != nil || got.Resource != nil {
		t.Fatal("restart promoted summary")
	}
}
