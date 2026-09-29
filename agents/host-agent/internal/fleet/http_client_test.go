package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/command"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider/ollama"
	agenttransport "github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/transport"
)

func TestMaximumPeerChunkFitsSignedCommandResultEnvelope(t *testing.T) {
	chunk := strings.Repeat("A", 512000)
	digest := strings.Repeat("a", 64)
	result := command.PeerRelayResult{Version: 1, Action: "read", TransferID: "transfer-1", Role: "source", Status: "transferring", ChunkBase64: &chunk, ChunkDigest: &digest, ChainDigest: strings.Repeat("0", 64)}
	if _, err := agenttransport.NewEnvelope("host-1", "request-1", "agent.command.result", "nonce", strings.Repeat("b", 64), "AB", 1, time.Now(), result); err != nil {
		t.Fatalf("bounded peer result exceeds command envelope: %v", err)
	}
}

type crossCommandAdapter struct{}

func (crossCommandAdapter) Execute(_ context.Context, operation string, _ json.RawMessage) (any, error) {
	return map[string]any{"operation": operation, "health": "ready"}, nil
}

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
	if os.Getenv("LANMM_CROSS_FLEET_COMMAND") == "1" {
		request, _, pollErr := restarted.PollCommand(context.Background(), 0)
		if pollErr != nil || request == nil {
			t.Fatalf("command poll = %#v, %v", request, pollErr)
		}
		var adapter command.Adapter = crossCommandAdapter{}
		inference := false
		var registry *command.Registry
		if endpoint := os.Getenv("LANMM_CROSS_FLEET_INFERENCE_ENDPOINT"); endpoint != "" {
			inference = true
			ollamaClient, clientErr := ollama.New(ollama.Config{ProviderID: "ollama-1", Endpoint: endpoint, Timeout: 2 * time.Second})
			if clientErr != nil {
				t.Fatal(clientErr)
			}
			registry = command.NewRegistry(time.Now)
			registry.RegisterOllama("ollama-1", ollamaClient)
			adapter = registry
		}
		executor := command.New("agent-1", adapter, time.Now)
		result, executeErr := executor.Execute(context.Background(), *request)
		if executeErr != nil || restarted.SendCommandResult(context.Background(), result) != nil {
			t.Fatalf("command result = %#v, %v", result, executeErr)
		}
		encoded, _ := json.Marshal(result.Observation)
		fmt.Printf("LANMM_CROSS_COMMAND_RESULT=%s:bytes=%d\n", result.Status, len(encoded))
		if inference {
			replay, replayErr := executor.Execute(context.Background(), *request)
			if replayErr != nil || restarted.SendCommandResult(context.Background(), replay) != nil {
				t.Fatalf("inference replay = %#v, %v", replay, replayErr)
			}
			fmt.Println("LANMM_CROSS_COMMAND_REPLAY=succeeded")
		}
		if os.Getenv("LANMM_CROSS_FLEET_LIFECYCLE") == "1" {
			if registry == nil {
				t.Fatal("lifecycle registry unavailable")
			}
			for _, expected := range []string{"load", "drain", "unload"} {
				value, _, pollErr := restarted.PollCommand(context.Background(), time.Second)
				if pollErr != nil || value == nil || value.Operation != expected {
					t.Fatalf("lifecycle poll %s = %#v, %v", expected, value, pollErr)
				}
				if expected == "drain" {
					lease, acquireErr := registry.Acquire(context.Background(), "ollama-1", "qwen:latest")
					if acquireErr != nil {
						t.Fatal(acquireErr)
					}
					blocked, executeErr := executor.Execute(context.Background(), *value)
					if executeErr != nil || blocked.Status != "running" || restarted.SendCommandResult(context.Background(), blocked) != nil {
						t.Fatalf("blocked drain = %#v, %v", blocked, executeErr)
					}
					_ = registry.Complete(context.Background(), lease)
					value, _, pollErr = restarted.PollCommand(context.Background(), time.Second)
					if pollErr != nil || value == nil || value.Operation != expected {
						t.Fatalf("drain replay = %#v, %v", value, pollErr)
					}
					fmt.Println("LANMM_CROSS_LIFECYCLE_BLOCKED=drain")
				}
				completed, executeErr := executor.Execute(context.Background(), *value)
				if executeErr != nil || completed.Status != "succeeded" || restarted.SendCommandResult(context.Background(), completed) != nil {
					t.Fatalf("lifecycle %s = %#v, %v", expected, completed, executeErr)
				}
				fmt.Printf("LANMM_CROSS_LIFECYCLE=%s:%s\n", expected, completed.Status)
			}
		}
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
