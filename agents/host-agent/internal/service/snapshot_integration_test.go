package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/observation"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/snapshot"
)

func TestSnapshotPersistsObservationAndRestoresStaleContinuity(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	observer := baseObserver()
	healthy := &fakeProvider{kind: provider.KindOllama, succeeds: true, calls: new(int64), health: provider.HealthReady}
	failed := &fakeProvider{kind: provider.KindLMStudio, succeeds: false, calls: new(int64)}
	cfg := baseConfig(t)
	cfg.StateDir = stateDir
	cfg.PollInterval = time.Minute
	cfg.Registry = ProviderRegistry{Observers: []observation.Observer{observer}, Runtime: []LocalProvider{healthy, failed}}
	cfg.Output = make(chan ObservationRecord, 1)

	first, err := New(cfg)
	if err != nil {
		t.Fatalf("first New: %v", err)
	}
	if _, ok := first.LatestSnapshot(); ok {
		t.Fatal("unexpected snapshot before first observation")
	}
	if err := first.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	record := <-cfg.Output
	fresh, ok := first.LatestSnapshot()
	if !ok || !fresh.Fresh {
		t.Fatalf("fresh latest = %+v, %v; record=%+v; observation error=%v", fresh, ok, record, record.Err)
	}
	if fresh.Record.ProvidersHealthy != 1 || fresh.Record.ProvidersFailed != 1 || fresh.Record.NAccelerators != 1 {
		t.Fatalf("persisted record = %+v", fresh.Record)
	}
	if err := first.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	noInitial := false
	restartCfg := cfg
	restartCfg.InitialObservation = &noInitial
	restartCfg.Registry = ProviderRegistry{Observers: []observation.Observer{baseObserver()}}
	restarted, err := New(restartCfg)
	if err != nil {
		t.Fatalf("restart New: %v", err)
	}
	loaded, ok := restarted.LatestSnapshot()
	if !ok {
		t.Fatal("restart did not restore snapshot")
	}
	if loaded.Fresh {
		t.Fatal("restored snapshot must be explicitly stale")
	}
	if loaded.Record != fresh.Record {
		t.Fatalf("restored record = %+v, want %+v", loaded.Record, fresh.Record)
	}
}

func TestNewQuarantinesCorruptionAndStartsWithoutReplay(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	dir := filepath.Join(stateDir, "state", "snapshot")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snapshot.Path(dir), []byte(`{"version":1,"record":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := baseConfig(t)
	cfg.StateDir = stateDir
	cfg.Registry = ProviderRegistry{Observers: []observation.Observer{baseObserver()}}
	host, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := host.LatestSnapshot(); ok {
		t.Fatal("corrupt snapshot replayed")
	}
	if _, err := os.Stat(snapshot.QuarantinePath(dir)); err != nil {
		t.Fatalf("quarantine missing: %v", err)
	}
}

func TestCancelledStartDoesNotPersistSnapshot(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	cfg := baseConfig(t)
	cfg.StateDir = stateDir
	cfg.Registry = ProviderRegistry{Observers: []observation.Observer{baseObserver()}}
	host, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := host.Start(ctx); err == nil {
		t.Fatal("cancelled Start succeeded")
	}
	if _, ok := host.LatestSnapshot(); ok {
		t.Fatal("cancelled Start persisted snapshot")
	}
}
