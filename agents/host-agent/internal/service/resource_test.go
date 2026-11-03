package service

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/observation"
)

func TestRuntimeResourceAuthority(t *testing.T) {
	obs := baseObserver()
	obs.value.Platform = observation.HostPlatform(runtime.GOOS)
	obs.value.ObservedAt = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	pct := uint8(30)
	obs.value.Accelerators[0].UtilizationPercent = &pct
	cfg := testConfig(t, []observation.Observer{obs}, nil, time.Minute)
	host, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	host.runObservation(ctx)
	got, ok := host.LatestResourceObservation()
	if !ok || got.Memory != obs.value.Memory || got.ObservedAt != obs.value.ObservedAt {
		t.Fatal("missing original resources")
	}
	*obs.value.CPUUtilizationPercent = 99
	*obs.value.Accelerators[0].UtilizationPercent = 99
	obs.value.Accelerators[0].Name = "changed"
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				v, ok := host.LatestResourceObservation()
				if !ok || *v.CPUUtilizationPercent != 20 || *v.Accelerators[0].UtilizationPercent != 30 || v.Accelerators[0].Name == "changed" {
					t.Error("shared resource memory")
					return
				}
				*v.CPUUtilizationPercent = 70
				*v.Accelerators[0].UtilizationPercent = 70
				v.Accelerators[0].Name = "caller"
			}
		}()
	}
	wg.Wait()
	restarted, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := restarted.LatestResourceObservation(); ok {
		t.Fatal("disk summary became authority")
	}
	if _, ok := restarted.LatestSnapshot(); !ok {
		t.Fatal("summary not restored")
	}
	obs.fails = true
	host.runObservation(ctx)
	if _, ok := host.LatestResourceObservation(); ok {
		t.Fatal("failure retained authority")
	}
	obs.fails = false
	host.runObservation(ctx)
	cancel()
	if _, ok := host.LatestResourceObservation(); ok {
		t.Fatal("cancellation retained authority")
	}
	host.runObservation(context.Background())
	host.Close(context.Background())
	if _, ok := host.LatestResourceObservation(); ok {
		t.Fatal("closed authority")
	}
}

func TestRuntimeRejectsInvalidResources(t *testing.T) {
	for _, scenario := range []string{"stale", "future", "host", "platform", "invalid", "unsafe"} {
		t.Run(scenario, func(t *testing.T) {
			obs := baseObserver()
			obs.value.Platform = observation.HostPlatform(runtime.GOOS)
			obs.value.ObservedAt = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
			cfg := testConfig(t, []observation.Observer{obs}, nil, time.Minute)
			host, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer host.Close(context.Background())
			host.runObservation(context.Background())
			if _, ok := host.LatestResourceObservation(); !ok {
				t.Fatal("initial authority missing")
			}
			switch scenario {
			case "stale":
				obs.value.ObservedAt = time.Now().Add(-time.Minute).UTC().Format("2006-01-02T15:04:05.000Z")
			case "future":
				obs.value.ObservedAt = time.Now().Add(time.Minute).UTC().Format("2006-01-02T15:04:05.000Z")
			case "host":
				obs.value.HostID = "other-host"
			case "platform":
				obs.value.Platform = "other"
			case "invalid":
				obs.value.Memory.UsedBytes = 101
			case "unsafe":
				obs.value.Storage.TotalBytes = 1 << 53
			}
			host.runObservation(context.Background())
			if _, ok := host.LatestResourceObservation(); ok {
				t.Fatal("invalid pass retained authority")
			}
		})
	}
}

func TestRuntimeResourceExpiresAndCancelsInFlight(t *testing.T) {
	obs := baseObserver()
	obs.value.Platform = observation.HostPlatform(runtime.GOOS)
	obs.value.ObservedAt = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	host, err := New(testConfig(t, []observation.Observer{obs}, nil, time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close(context.Background())
	host.runObservation(context.Background())
	host.mu.Lock()
	host.resource.ObservedAt = time.Now().Add(-time.Minute).UTC().Format("2006-01-02T15:04:05.000Z")
	host.mu.Unlock()
	if _, ok := host.LatestResourceObservation(); ok {
		t.Fatal("aged resource remained authoritative")
	}
	ctx, cancel := context.WithCancel(context.Background())
	obs.onObserve = cancel
	host.runObservation(ctx)
	if _, ok := host.LatestResourceObservation(); ok {
		t.Fatal("cancelled observation published")
	}
}
