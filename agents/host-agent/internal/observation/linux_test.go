//go:build linux

package observation

import (
	"context"
	"errors"
	"math"
	"syscall"
	"testing"
	"time"
)

func fixtureDeps(files map[string][]byte, stat syscall.Statfs_t) linuxDeps {
	return linuxDeps{
		readFile: func(path string) ([]byte, error) {
			data, ok := files[path]
			if !ok {
				return nil, errors.New("missing")
			}
			return data, nil
		},
		statFS: func(_ string, output *syscall.Statfs_t) error { *output = stat; return nil },
		numCPU: func() int { return 8 }, now: func() time.Time { return time.Date(2026, 9, 26, 13, 0, 0, 123456789, time.FixedZone("x", 3600)) },
		sleep: func(context.Context, time.Duration) error { return nil },
	}
}

func TestLinuxObserverDeterministicResult(t *testing.T) {
	reads := 0
	deps := fixtureDeps(map[string][]byte{"/proc/meminfo": []byte("MemTotal: 100 kB\nMemAvailable: 40 kB\n"), "/proc/stat": []byte("cpu  100 0 100 800 0\n")}, syscall.Statfs_t{Blocks: 100, Bfree: 40, Bavail: 30, Bsize: 1024})
	deps.readFile = func(path string) ([]byte, error) {
		if path == "/proc/meminfo" {
			return []byte("MemTotal: 100 kB\nMemAvailable: 40 kB\n"), nil
		}
		reads++
		if reads == 1 {
			return []byte("cpu  100 0 100 800 0\n"), nil
		}
		return []byte("cpu  150 0 150 900 0\n"), nil
	}
	observer, err := newLinuxObserver(LinuxObserverConfig{HostID: "host-1", StoragePath: "/tmp", SampleInterval: time.Millisecond}, deps)
	if err != nil {
		t.Fatal(err)
	}
	result, err := observer.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.ObservedAt != "2026-09-26T12:00:00.123Z" || result.Platform != PlatformLinux || result.CPULogicalCores != 8 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.Memory.TotalBytes != 102400 || result.Memory.AvailableBytes != 40960 || result.Storage.UsedBytes != 61440 || result.Storage.AvailableBytes != 30720 {
		t.Fatalf("bad resources: %#v", result)
	}
	if result.CPUUtilizationPercent == nil || *result.CPUUtilizationPercent != 50 || result.Accelerators == nil || len(result.Accelerators) != 0 {
		t.Fatalf("bad optional values: %#v", result)
	}
}

func TestMemoryFallbackAndFailures(t *testing.T) {
	observer, _ := newLinuxObserver(LinuxObserverConfig{HostID: "host", StoragePath: "/"}, fixtureDeps(map[string][]byte{"/proc/meminfo": []byte("MemTotal: 100 kB\nMemFree: 10 kB\nBuffers: 5 kB\nCached: 20 kB\n")}, syscall.Statfs_t{}))
	memory, err := observer.readMemory()
	if err != nil || memory.AvailableBytes != 35840 {
		t.Fatalf("fallback: %#v %v", memory, err)
	}
	for _, content := range []string{"MemFree: 1 kB\n", "MemTotal: nope kB\n", "MemTotal: 1 MB\n", "MemTotal: 1 kB\nMemAvailable: 2 kB\n"} {
		observer.deps.readFile = func(string) ([]byte, error) { return []byte(content), nil }
		if _, err := observer.readMemory(); !errors.Is(err, ErrProcParse) {
			t.Fatalf("expected parse error for %q: %v", content, err)
		}
	}
}

func TestStorageUsesBfreeAndBavailAndRejectsOverflow(t *testing.T) {
	deps := fixtureDeps(nil, syscall.Statfs_t{Blocks: 10, Bfree: 4, Bavail: 3, Bsize: 100})
	observer, _ := newLinuxObserver(LinuxObserverConfig{HostID: "host", StoragePath: "/"}, deps)
	storage, err := observer.readStorage()
	if err != nil || storage.UsedBytes != 600 || storage.AvailableBytes != 300 {
		t.Fatalf("storage: %#v %v", storage, err)
	}
	observer.deps.statFS = func(string, *syscall.Statfs_t) error { return errors.New("stat") }
	if _, err := observer.readStorage(); !errors.Is(err, ErrStorage) {
		t.Fatal(err)
	}
	observer.deps.statFS = func(_ string, output *syscall.Statfs_t) error {
		*output = syscall.Statfs_t{Blocks: math.MaxUint64, Bsize: 2}
		return nil
	}
	if _, err := observer.readStorage(); !errors.Is(err, ErrStorage) {
		t.Fatal(err)
	}
}

func TestCPUUnavailableIsNil(t *testing.T) {
	cases := [][]byte{[]byte("bad\n"), []byte("cpu 100 0 0 900\n")}
	for _, second := range cases {
		reads := 0
		deps := fixtureDeps(nil, syscall.Statfs_t{})
		deps.readFile = func(string) ([]byte, error) {
			reads++
			if reads == 1 {
				return []byte("cpu 100 0 0 900 0\n"), nil
			}
			return second, nil
		}
		observer, _ := newLinuxObserver(LinuxObserverConfig{HostID: "host", StoragePath: "/"}, deps)
		value, err := observer.readCPUUtilization(context.Background())
		if err != nil || value != nil {
			t.Fatalf("expected nil: %v %v", value, err)
		}
	}
}

func TestCancellationAndConfiguration(t *testing.T) {
	if _, err := NewLinuxObserver(LinuxObserverConfig{HostID: "bad/id", StoragePath: "/"}); !errors.Is(err, ErrLinuxConfig) {
		t.Fatal(err)
	}
	if _, err := NewLinuxObserver(LinuxObserverConfig{HostID: "host", StoragePath: "relative"}); !errors.Is(err, ErrLinuxConfig) {
		t.Fatal(err)
	}
	deps := fixtureDeps(map[string][]byte{"/proc/meminfo": []byte("MemTotal: 1 kB\nMemAvailable: 1 kB\n"), "/proc/stat": []byte("cpu 1 0 0 9 0\n")}, syscall.Statfs_t{Blocks: 1, Bfree: 1, Bavail: 1, Bsize: 1})
	ctx, cancel := context.WithCancel(context.Background())
	deps.sleep = func(context.Context, time.Duration) error { cancel(); return context.Canceled }
	observer, _ := newLinuxObserver(LinuxObserverConfig{HostID: "host", StoragePath: "/"}, deps)
	if _, err := observer.Observe(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}
