package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCrossLanguageFleetHelper(t *testing.T) {
	directory := os.Getenv("LANMM_CROSS_FLEET_CERT_DIR")
	if directory == "" {
		t.Skip("cross-language helper")
	}
	client, err := NewHTTPSClient(directory)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("LANMM_CROSS_FLEET_EXPECT_REJECT") == "1" {
		if os.Getenv("LANMM_CROSS_FLEET_STALE") == "1" {
			calls := 0
			client.now = func() time.Time {
				calls++
				if calls == 1 {
					return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
				}
				return time.Now()
			}
		}
		if _, err := client.Send(context.Background(), Snapshot{Platform: "linux", Idle: true}); !errors.Is(err, ErrHTTPClient) {
			t.Fatalf("expected redacted rejection, got %v", err)
		}
		fmt.Println("LANMM_CROSS_FLEET_REJECTED=true")
		return
	}
	hello, err := client.SendHello(context.Background(), "linux", "", 30*time.Second, 2*time.Second, 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	providers := []ProviderObservation{{ProviderID: "ollama-1", Kind: "ollama", DisplayName: "Ollama", Endpoint: "http://127.0.0.1:11434", Health: "ready", Version: nil, ObservedAt: at}}
	models := []InstalledModelObservation{{ModelID: "qwen", ProviderID: "ollama-1", DisplayName: "Qwen", ArtifactState: "installed", RuntimeState: "loaded-idle", SizeBytes: nil, Capability: ModelCapability{Modalities: []string{"text"}}, ObservedAt: at}}
	heartbeat, err := client.Send(context.Background(), Snapshot{Platform: "linux", Idle: true, Providers: providers, Models: models})
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewHTTPSClient(directory)
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := restarted.Send(context.Background(), Snapshot{Platform: "linux", Idle: true, Providers: providers, Models: models})
	if err != nil {
		t.Fatal(err)
	}
	value, _ := json.Marshal(map[string]uint64{"hello": hello.Sequence, "heartbeat": heartbeat, "resumed": resumed})
	fmt.Printf("LANMM_CROSS_FLEET_RESULT=%s\n", value)
}

func TestSequenceStoreDurablyResumesAndRejectsCorruption(t *testing.T) {
	directory := t.TempDir()
	store := SequenceStore{CertDir: directory}
	if value, err := store.Load(); err != nil || value != 0 {
		t.Fatalf("initial = %d, %v", value, err)
	}
	if err := store.Reserve(41); err != nil {
		t.Fatal(err)
	}
	if value, err := (SequenceStore{CertDir: directory}).Load(); err != nil || value != 41 {
		t.Fatalf("restart = %d, %v", value, err)
	}
	info, err := os.Stat(filepath.Join(directory, sequenceName))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, %v", info, err)
	}
	if err := os.WriteFile(filepath.Join(directory, sequenceName), []byte("41 trailing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrHTTPClient) {
		t.Fatalf("corruption was accepted: %v", err)
	}
}

func TestControllerTimingBounds(t *testing.T) {
	valid := Ack{Accepted: true, NextHeartbeatIntervalMs: 1000, NextHeartbeatIntervalJitterMs: 5000, NextHeartbeatWindowMs: 1000}
	if !validTiming(valid) {
		t.Fatal("valid bounds rejected")
	}
	valid.NextHeartbeatIntervalMs = int64(24*time.Hour/time.Millisecond) + 1
	if validTiming(valid) {
		t.Fatal("oversized interval accepted")
	}
	valid.NextHeartbeatIntervalMs = 1000
	valid.NextHeartbeatIntervalJitterMs = 5001
	if validTiming(valid) {
		t.Fatal("oversized jitter accepted")
	}
}
