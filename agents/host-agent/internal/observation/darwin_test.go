//go:build darwin

package observation

import (
	"context"
	"errors"
	"reflect"
	"syscall"
	"testing"
	"time"
)

type darwinFixtureRunner struct {
	outputs map[string][]byte
	errPath string
	calls   []string
	args    map[string][]string
}

func (r *darwinFixtureRunner) Run(ctx context.Context, path string, args []string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.calls = append(r.calls, path)
	r.args[path] = append([]string(nil), args...)
	if path == r.errPath {
		return []byte("private command output"), errors.New("private command error")
	}
	return append([]byte(nil), r.outputs[path]...), nil
}

func darwinFixtureDeps(runner CommandRunner) darwinDeps {
	return darwinDeps{
		runner: runner,
		statFS: func(_ string, stat *syscall.Statfs_t) error {
			*stat = syscall.Statfs_t{Blocks: 100, Bfree: 40, Bavail: 30, Bsize: 1024}
			return nil
		},
		numCPU: func() int { return 12 },
		now:    func() time.Time { return time.Date(2026, 9, 26, 13, 0, 0, 999999999, time.FixedZone("local", 3600)) },
	}
}

func TestDarwinObserverAndFixedCommands(t *testing.T) {
	runner := &darwinFixtureRunner{outputs: map[string][]byte{
		darwinSysctlPath:         []byte("409600"),
		darwinVMStatPath:         []byte("Mach Virtual Memory Statistics: (page size of 4096 bytes)\nPages free: 10.\nPages inactive: 20.\nPages speculative: 5.\n"),
		darwinTopPath:            []byte("CPU usage: 10% user, 5% sys, 85% idle\n"),
		darwinSystemProfilerPath: []byte(`{"_items":[]}`),
	}, args: make(map[string][]string)}
	observer, err := newDarwinObserver(DarwinObserverConfig{HostID: "mac-1", StoragePath: "/"}, darwinFixtureDeps(runner))
	if err != nil {
		t.Fatal(err)
	}
	first, err := observer.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.Platform != PlatformDarwin || first.ObservedAt != "2026-09-26T12:00:00.999Z" || first.CPULogicalCores != 12 || first.CPUUtilizationPercent == nil || *first.CPUUtilizationPercent != 15 || first.Accelerators == nil {
		t.Fatalf("unexpected observation: %#v", first)
	}
	if !reflect.DeepEqual(runner.args[darwinSysctlPath], []string{"-n", "hw.memsize"}) || !reflect.DeepEqual(runner.args[darwinTopPath], []string{"-l", "2", "-n", "0"}) || !reflect.DeepEqual(runner.args[darwinSystemProfilerPath], []string{"SPDisplaysDataType", "-json"}) {
		t.Fatalf("unexpected argv: %#v", runner.args)
	}
	first.Accelerators = append(first.Accelerators, AcceleratorObservation{ID: "mutation"})
	second, err := observer.Observe(context.Background())
	if err != nil || len(second.Accelerators) != 0 {
		t.Fatalf("copy isolation: %#v %v", second, err)
	}
}

func TestDarwinConfigurationCancellationAndRedaction(t *testing.T) {
	if _, err := NewDarwinObserver(DarwinObserverConfig{HostID: "bad/id", StoragePath: "/"}); !errors.Is(err, ErrDarwinConfig) {
		t.Fatal(err)
	}
	if _, err := NewDarwinObserver(DarwinObserverConfig{HostID: "mac", StoragePath: "relative"}); !errors.Is(err, ErrDarwinConfig) {
		t.Fatal(err)
	}
	runner := &darwinFixtureRunner{outputs: map[string][]byte{}, errPath: darwinSysctlPath, args: make(map[string][]string)}
	observer, _ := newDarwinObserver(DarwinObserverConfig{HostID: "mac", StoragePath: "/"}, darwinFixtureDeps(runner))
	if _, err := observer.Observe(context.Background()); !errors.Is(err, ErrDarwinMemory) || err.Error() != ErrDarwinMemory.Error() {
		t.Fatalf("unclassified or unredacted: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := observer.Observe(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}
