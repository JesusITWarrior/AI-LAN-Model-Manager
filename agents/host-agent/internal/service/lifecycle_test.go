package service

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/observation"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
)

// recordingObserver is a programmable observer that records how many times it
// was driven and whether cancellation was observed. Its Observe honors ctx
// cancellation like a production platform observer would.
type recordingObserver struct {
	value     observation.HostResourceObservation
	fails     bool
	calls     *int64
	onObserve func()
}

func (o *recordingObserver) Observe(ctx context.Context) (observation.HostResourceObservation, error) {
	atomic.AddInt64(o.calls, 1)
	if o.onObserve != nil {
		o.onObserve()
	}
	if err := ctx.Err(); err != nil {
		return observation.HostResourceObservation{}, err
	}
	if o.fails {
		return observation.HostResourceObservation{}, &failingError{msg: "observer internal detail"}
	}
	return o.value, nil
}

type failingError struct{ msg string }

func (e *failingError) Error() string { return e.msg }

type fakeProvider struct {
	kind     provider.Kind
	succeeds bool
	calls    *int64
	health   provider.Health
}

func (p *fakeProvider) Kind() provider.Kind { return p.kind }

func (p *fakeProvider) Health(ctx context.Context) (provider.Health, error) {
	atomic.AddInt64(p.calls, 1)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if p.succeeds {
		return p.health, nil
	}
	return "", &failingError{msg: "provider health internal detail"}
}

func testConfig(t *testing.T, observers []observation.Observer, runtime []LocalProvider, poll time.Duration) Config {
	cfg := baseConfig(t)
	cfg.StateDir = testStateDirFor(t)
	cfg.PollInterval = poll
	cfg.Registry = ProviderRegistry{Observers: observers, Runtime: runtime}
	return cfg
}

// testStateDirFor returns a fresh state dir path under a unique temp root.
func testStateDirFor(t *testing.T) string {
	// Use a nested unique path so each test has its own containment root.
	return filepath.Join(t.TempDir(), "state")
}

func baseObserver() *recordingObserver {
	pct := uint8(20)
	return &recordingObserver{
		value: observation.HostResourceObservation{
			HostID: "host-1", ObservedAt: "2026-09-26T12:00:00.000Z", Platform: observation.PlatformLinux,
			CPULogicalCores: 8, CPUUtilizationPercent: &pct, Memory: observation.ResourceQuantity{TotalBytes: 100, UsedBytes: 40, AvailableBytes: 50}, Storage: observation.ResourceQuantity{TotalBytes: 200, UsedBytes: 50, AvailableBytes: 100},
			Accelerators: []observation.AcceleratorObservation{{ID: "gpu-0", Name: "Example GPU", Kind: observation.AcceleratorNVIDIA, Memory: observation.ResourceQuantity{TotalBytes: 80, UsedBytes: 20, AvailableBytes: 40}}},
		},
		calls: new(int64),
	}
}

func TestStartRunsInitialObservationThenLoop(t *testing.T) {
	obs := baseObserver()
	provider := &fakeProvider{kind: provider.KindOllama, succeeds: true, calls: new(int64), health: provider.HealthReady}

	cfg := testConfig(t, []observation.Observer{obs}, []LocalProvider{provider}, 30*time.Millisecond)
	output := make(chan ObservationRecord, 16)
	cfg.Output = output
	host, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer host.Close(context.Background())

	if err := host.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Drain loop records until the loop has run at least one pass.
	deadline := time.After(3 * time.Second)
	for {
		select {
		case record, ok := <-output:
			if !ok {
				t.Fatal("output closed unexpectedly")
			}
			if record.NAccelerators != 1 || record.ProvidersHealthy != 1 {
				t.Fatalf("unexpected record: %+v", record)
			}
			if atomic.LoadInt64(obs.calls) >= 2 {
				return
			}
		case <-deadline:
			t.Fatalf("loop did not drive observations; calls=%d", atomic.LoadInt64(obs.calls))
		}
	}
}

func TestStartWithCancelledContextFailsFast(t *testing.T) {
	obs := baseObserver()
	cfg := testConfig(t, []observation.Observer{obs}, nil, time.Minute)
	host, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer host.Close(context.Background())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := host.Start(ctx); err == nil {
		t.Fatal("expected error for pre-cancelled context")
	}
}

func TestCloseIsIdempotentAndTerminates(t *testing.T) {
	obs := baseObserver()
	cfg := testConfig(t, []observation.Observer{obs}, nil, 30*time.Millisecond)
	host, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := host.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := host.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// A second Close must be a no-op that returns nil.
	if err := host.Close(context.Background()); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	// A run may not restart: a second Start after Close must be rejected.
	if err := host.Start(context.Background()); err == nil {
		t.Fatal("expected restart to be rejected after Close")
	}
}

func TestRestartBeforeCloseIsRejected(t *testing.T) {
	obs := baseObserver()
	cfg := testConfig(t, []observation.Observer{obs}, nil, time.Minute)
	host, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := host.Start(context.Background()); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	// A second Start before Close must be rejected (idempotent-against-restart).
	if err := host.Start(context.Background()); err == nil {
		t.Fatal("expected second Start before Close to be rejected")
	}
	if err := host.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestObserverFailureIsDegradedNotFatal(t *testing.T) {
	failing := baseObserver()
	failing.fails = true
	cfg := testConfig(t, []observation.Observer{failing}, nil, time.Minute)
	host, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer host.Close(context.Background())

	// A degraded service must still start and stay alive.
	if err := host.Start(context.Background()); err != nil {
		t.Fatalf("Start with failing observer: %v", err)
	}

	// The loop continues running despite the observer failure.
	if atomic.LoadInt64(failing.calls) < 1 {
		t.Fatalf("observer was never driven")
	}
	// Give the loop a chance to run passes.
	time.Sleep(200 * time.Millisecond)
	if err := host.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestLocalProviderFailureCountedInRecord(t *testing.T) {
	obs := baseObserver()
	unhealthy := &fakeProvider{kind: provider.KindOllama, succeeds: false, calls: new(int64), health: provider.HealthReady}

	output := make(chan ObservationRecord, 16)
	cfg := testConfig(t, []observation.Observer{obs}, []LocalProvider{unhealthy}, 30*time.Millisecond)
	cfg.Output = output
	host, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer host.Close(context.Background())

	if err := host.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	deadline := time.After(3 * time.Second)
	for {
		select {
		case record, ok := <-output:
			if !ok {
				t.Fatal("output closed unexpectedly")
			}
			if record.ProvidersFailed == 0 {
				t.Fatalf("expected a failed provider in record")
			}
			if atomic.LoadInt64(unhealthy.calls) < 2 {
				continue
			}
			return
		case <-deadline:
			t.Fatalf("provider was never probed; calls=%d", atomic.LoadInt64(unhealthy.calls))
		}
	}
}

func TestCancellationExitsLoop(t *testing.T) {
	obs := baseObserver()
	cfg := testConfig(t, []observation.Observer{obs}, nil, 30*time.Millisecond)
	host, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := host.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := host.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// After Close the loop has exited: a subsequent Close is a no-op and no
	// goroutine leak is observed by Close returning promptly.
	if err := host.Close(context.Background()); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestStateDirectoryPermissionsRestrictive(t *testing.T) {
	obs := baseObserver()
	cfg := testConfig(t, []observation.Observer{obs}, nil, time.Minute)
	host, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer host.Close(context.Background())

	state, cert, cache, runtime := host.StateDirs()
	for name, dir := range map[string]string{"state": state, "cert": cert, "cache": cache, "runtime": runtime} {
		if dir == "" {
			continue
		}
		info, statErr := os.Stat(dir)
		if statErr != nil {
			t.Fatalf("%s dir: %v", name, statErr)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s dir group/other bits set: %v", name, info.Mode().Perm())
		}
		_ = runtime
	}
}
