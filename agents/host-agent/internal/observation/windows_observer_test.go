//go:build windows

package observation

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// recordingRunner is a deterministic CommandRunner that records every exact
// (path, args) call so tests can assert the fixed executable + fixed argv
// template, storage volume handling, redaction, and cancellation behavior.
type recordingRunner struct {
	calls []recordedCall
	// handler maps a single-letter-drive query to its canned output and error.
	handler func(query string) ([]byte, error)
}

type recordedCall struct {
	path string
	args []string
}

func (r *recordingRunner) Run(_ context.Context, path string, args []string) ([]byte, error) {
	r.calls = append(r.calls, recordedCall{path: path, args: append([]string(nil), args...)})
	if r.handler == nil {
		return nil, nil
	}
	if len(args) < 4 {
		return nil, errors.New("argv must be [-NoProfile -NonInteractive -Command <query>]")
	}
	return r.handler(args[3])
}

// newWindowsTestObserver builds a WindowsObserver with a recording runner wired
// to handler, plus fixed numCPU/now deps.
func newWindowsTestObserver(handler func(query string) ([]byte, error)) (*WindowsObserver, *recordingRunner) {
	runner := &recordingRunner{handler: handler}
	observer, err := newWindowsObserver(
		WindowsObserverConfig{HostID: "win-host", StoragePath: "C:\\"},
		windowsDeps{runner: runner, numCPU: func() int { return 8 }, now: func() time.Time { return time.Date(2026, 9, 26, 13, 0, 0, 0, time.UTC) }},
	)
	if err != nil {
		panic(err)
	}
	return observer, runner
}

func writeMemoryJSON() []byte {
	return mustJSON(map[string]interface{}{
		"__CLASS":                "Win32_OperatingSystem",
		"TotalVisibleMemorySize": float64(16777216),
		"FreePhysicalMemory":     float64(8388608),
	})
}

func writeStorageJSON(total, free uint64) []byte {
	return mustJSON(map[string]interface{}{
		"__CLASS":   "Win32_LogicalDisk",
		"DeviceID":  "C:",
		"Size":      float64(total),
		"FreeSpace": float64(free),
	})
}

func writeCPUJSON(load int) []byte {
	return mustJSON(map[string]interface{}{
		"__CLASS":        "Win32_Processor",
		"LoadPercentage": float64(load),
	})
}

func writeGPUJSON() []byte {
	return mustJSON(map[string]interface{}{
		"__CLASS":              "Win32_VideoController",
		"PNPDeviceID":          "PCI\\VEN_10DE&DEV_1E30",
		"Name":                 "Test RTX",
		"AdapterRAM":           float64(1073741824),
		"AdapterCompatibility": "NVIDIA",
		"VideoProcessor":       "Test RTX",
	})
}

func mustJSON(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// buildHandler routes each fixed query to a canned response. Each observation
// performs memory, storage, CPU, then GPU runs, in that order.
func buildHandler(cpuOut []byte, cpuErr error, gpuOut []byte) func(query string) ([]byte, error) {
	return func(query string) ([]byte, error) {
		switch {
		case strings.Contains(query, "Win32_OperatingSystem"):
			return writeMemoryJSON(), nil
		case strings.Contains(query, "Win32_LogicalDisk"):
			return writeStorageJSON(1024*1024*1024, 512*1024*1024), nil
		case strings.Contains(query, "Win32_Processor"):
			return cpuOut, cpuErr
		case strings.Contains(query, "Win32_VideoController"):
			return gpuOut, nil
		}
		return nil, nil
	}
}

func TestWindowsObserverUsesFixedExecutableAndArgv(t *testing.T) {
	observer, runner := newWindowsTestObserver(buildHandler(writeCPUJSON(42), nil, writeGPUJSON()))
	if _, err := observer.Observe(context.Background()); err != nil {
		t.Fatalf("observe: %v", err)
	}

	if len(runner.calls) != 4 {
		t.Fatalf("expected 4 fixed runs, got %d", len(runner.calls))
	}
	wantArgs := [][]string{
		memoryArgs[:],
		{psNoProfile, psNonInteractive, psCommand, storageScript, "C:"},
		cpuArgs[:],
		gpuArgs[:],
	}
	for index, call := range runner.calls {
		if call.path != powershellPath {
			t.Errorf("call %d path = %q, want %q", index, call.path, powershellPath)
		}
		if !reflect.DeepEqual(call.args, wantArgs[index]) {
			t.Errorf("call %d argv = %#v, want %#v", index, call.args, wantArgs[index])
		}
	}
}

func TestWindowsObserverStorageVolumeHandling(t *testing.T) {
	runner := &recordingRunner{handler: buildHandler(writeCPUJSON(10), nil, writeGPUJSON())}
	observer, err := newWindowsObserver(
		WindowsObserverConfig{HostID: "win-host", StoragePath: "d:\\Program Files"},
		windowsDeps{runner: runner, numCPU: func() int { return 8 }, now: time.Now},
	)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if _, err := observer.Observe(context.Background()); err != nil {
		t.Fatalf("observe: %v", err)
	}

	storageCall := runner.calls[1]
	want := []string{psNoProfile, psNonInteractive, psCommand, storageScript, "D:"}
	if !reflect.DeepEqual(storageCall.args, want) {
		t.Fatalf("storage argv = %#v, want %#v", storageCall.args, want)
	}
	// The arbitrary storage path ("C:\\Program Files") must never appear joined
	// into the PowerShell argv.
	for _, call := range runner.calls {
		for _, arg := range call.args {
			if strings.Contains(arg, "Program Files") {
				t.Errorf("storage path fragment leaked into argv: %q", arg)
			}
		}
	}
}

func TestWindowsObserverRejectsUNCStorage(t *testing.T) {
	runner := &recordingRunner{}
	_, err := newWindowsObserver(
		WindowsObserverConfig{HostID: "win-host", StoragePath: `\\server\share`},
		windowsDeps{runner: runner, numCPU: func() int { return 8 }, now: time.Now},
	)
	if !errors.Is(err, ErrWindowsConfig) {
		t.Fatalf("expected ErrWindowsConfig for UNC path, got %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("constructor must not run probes, got %d calls", len(runner.calls))
	}
}

func TestWindowsObserverCPUBestEffortInvocationFailure(t *testing.T) {
	// CPU invocation fails, but Observe must still succeed with nil utilization.
	observer, _ := newWindowsTestObserver(buildHandler(nil, errors.New("ps crashed"), writeGPUJSON()))
	result, err := observer.Observe(context.Background())
	if err != nil {
		t.Fatalf("CPU invocation failure must not fail Observe: %v", err)
	}
	if result.CPUUtilizationPercent != nil {
		t.Fatalf("expected nil utilization on CPU failure, got %v", *result.CPUUtilizationPercent)
	}
}

func TestWindowsObserverCPUBestEffortMalformedOutput(t *testing.T) {
	// Missing/malformed CPU output returns nil without failing Observe.
	observer, _ := newWindowsTestObserver(buildHandler([]byte("garbage"), nil, writeGPUJSON()))
	result, err := observer.Observe(context.Background())
	if err != nil {
		t.Fatalf("malformed CPU output must not fail Observe: %v", err)
	}
	if result.CPUUtilizationPercent != nil {
		t.Fatalf("expected nil utilization on malformed CPU output, got %v", *result.CPUUtilizationPercent)
	}
}

func TestWindowsObserverCPUBestEffortUnavailability(t *testing.T) {
	// LoadPercentage absent / LoadPercentage out of range => best-effort nil.
	observer, _ := newWindowsTestObserver(buildHandler([]byte(`{"__CLASS":"Win32_Processor"}`), nil, writeGPUJSON()))
	result, err := observer.Observe(context.Background())
	if err != nil || result.CPUUtilizationPercent != nil {
		t.Fatalf("expected nil utilization on unavailable CPU, got %#v %v", result.CPUUtilizationPercent, err)
	}
}

func TestWindowsObserverCPUCancellationPropagates(t *testing.T) {
	// Context cancellation during the best-effort CPU probe must propagate
	// instead of being swallowed.
	handler := func(query string) ([]byte, error) {
		switch {
		case strings.Contains(query, "Win32_OperatingSystem"):
			return writeMemoryJSON(), nil
		case strings.Contains(query, "Win32_LogicalDisk"):
			return writeStorageJSON(1024, 512), nil
		case strings.Contains(query, "Win32_Processor"):
			return nil, context.Canceled
		default:
			return writeGPUJSON(), nil
		}
	}
	observer, _ := newWindowsTestObserver(handler)
	if _, err := observer.Observe(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled to propagate from CPU probe, got %v", err)
	}
}

func TestWindowsObserverCancellationPropagates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	observer, _ := newWindowsTestObserver(buildHandler(writeCPUJSON(10), nil, writeGPUJSON()))
	if _, err := observer.Observe(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestWindowsObserverCPUDeadlinePropagates(t *testing.T) {
	observer, _ := newWindowsTestObserver(buildHandler(nil, context.DeadlineExceeded, writeGPUJSON()))
	if _, err := observer.Observe(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
}

func TestWindowsObserverRedactsRunnerError(t *testing.T) {
	const secret = "sensitive command stderr"
	observer, _ := newWindowsTestObserver(nil)
	observer.deps.runner = &recordingRunner{handler: func(string) ([]byte, error) {
		return []byte("sensitive command output"), errors.New(secret)
	}}
	_, err := observer.Observe(context.Background())
	if !errors.Is(err, ErrWindowsMemory) {
		t.Fatalf("expected ErrWindowsMemory, got %v", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "sensitive command output") {
		t.Fatalf("raw runner details leaked: %v", err)
	}
}

func TestWindowsObserverRedactionNoRawOutput(t *testing.T) {
	// Oversized memory output must fail with a joined error and must NOT echo the
	// raw command bytes back in the error.
	overflow := make([]byte, maxCommandOutput+1)
	for i := range overflow {
		overflow[i] = 'S'
	}
	payload := string(overflow[:16])

	observer, _ := newWindowsTestObserver(buildHandler(writeCPUJSON(10), nil, writeGPUJSON()))
	observer.deps.runner = &recordingRunner{handler: func(query string) ([]byte, error) {
		if strings.Contains(query, "Win32_OperatingSystem") {
			return overflow, nil
		}
		return writeMemoryJSON(), nil
	}}

	_, err := observer.Observe(context.Background())
	if err == nil {
		t.Fatal("expected error for oversized output")
	}
	if !errors.Is(err, ErrWindowsMemory) {
		t.Errorf("expected joined ErrWindowsMemory, got %v", err)
	}
	if strings.Contains(err.Error(), payload) {
		t.Errorf("raw command output leaked into error: %q", payload)
	}
}

func TestWindowsObserverCompleteResult(t *testing.T) {
	observer, _ := newWindowsTestObserver(buildHandler(writeCPUJSON(42), nil, writeGPUJSON()))
	result, err := observer.Observe(context.Background())
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if result.Platform != PlatformWindows {
		t.Errorf("platform = %s, want %s", result.Platform, PlatformWindows)
	}
	if result.HostID != "win-host" {
		t.Errorf("host id = %s", result.HostID)
	}
	if result.CPULogicalCores != 8 {
		t.Errorf("cores = %d, want 8", result.CPULogicalCores)
	}
	if result.CPUUtilizationPercent == nil || *result.CPUUtilizationPercent != 42 {
		t.Errorf("utilization = %v, want 42", result.CPUUtilizationPercent)
	}
	if result.Memory.TotalBytes != ByteAmount(16777216*1024) {
		t.Errorf("memory total = %d", result.Memory.TotalBytes)
	}
	if result.Storage.TotalBytes != ByteAmount(1024*1024*1024) || result.Storage.UsedBytes != ByteAmount(512*1024*1024) {
		t.Errorf("storage = total %d used %d", result.Storage.TotalBytes, result.Storage.UsedBytes)
	}
	if len(result.Accelerators) != 1 || result.Accelerators[0].Kind != AcceleratorNVIDIA {
		t.Errorf("accelerators = %v", result.Accelerators)
	}
	if err := result.Validate(); err != nil {
		t.Errorf("complete result must validate: %v", err)
	}
}

func TestWindowsObserverCopyIsolation(t *testing.T) {
	observer, _ := newWindowsTestObserver(buildHandler(writeCPUJSON(42), nil, writeGPUJSON()))
	first, err := observer.Observe(context.Background())
	if err != nil {
		t.Fatalf("first observe: %v", err)
	}
	// Mutate the returned copy and observe again.
	if first.CPUUtilizationPercent != nil {
		*first.CPUUtilizationPercent = 99
	}
	if len(first.Accelerators) > 0 {
		first.Accelerators = append(first.Accelerators, AcceleratorObservation{ID: "injected"})
	}
	second, err := observer.Observe(context.Background())
	if err != nil {
		t.Fatalf("second observe: %v", err)
	}
	if second.CPUUtilizationPercent == nil || *second.CPUUtilizationPercent != 42 {
		t.Errorf("CPU utilization not isolated: %v", second.CPUUtilizationPercent)
	}
	if len(second.Accelerators) != 1 {
		t.Errorf("accelerators not isolated after copy: len = %d", len(second.Accelerators))
	}
}

func TestNewWindowsObserverConfigValidation(t *testing.T) {
	invalid := []WindowsObserverConfig{
		{HostID: "", StoragePath: `C:\`},
		{HostID: "host", StoragePath: "relative"},
		{HostID: "host", StoragePath: `\\server\share`},
		{HostID: "host", StoragePath: `3:\data`},
		{HostID: "host", StoragePath: `C:relative`},
		{HostID: "host", StoragePath: `C:\data\..\other`},
		{HostID: "host", StoragePath: `C:/data`},
	}
	for _, config := range invalid {
		if _, err := NewWindowsObserver(config); !errors.Is(err, ErrWindowsConfig) {
			t.Errorf("expected ErrWindowsConfig for %#v, got %v", config, err)
		}
	}
	if _, err := NewWindowsObserver(WindowsObserverConfig{HostID: "host", StoragePath: `c:\data`}); err != nil {
		t.Errorf("expected valid clean drive path, got %v", err)
	}
}
