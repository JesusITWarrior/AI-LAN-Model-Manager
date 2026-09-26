//go:build windows

package observation

import (
	"context"
	"errors"
	"runtime"
	"time"
)

var (
	ErrWindowsConfig  = errors.New("invalid windows observer configuration")
	ErrWindowsCPU     = errors.New("windows cpu probe failed")
	ErrWindowsMemory  = errors.New("windows memory probe failed")
	ErrWindowsStorage = errors.New("windows storage probe failed")
	ErrWindowsGPU     = errors.New("windows gpu probe failed")
)

const (
	powershellPath   = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	psNoProfile      = "-NoProfile"
	psNonInteractive = "-NonInteractive"
	psCommand        = "-Command"

	memoryScript  = `Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory | ConvertTo-Json -Compress`
	storageScript = `& { param([string]$drive) Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$drive'" | Select-Object Size,FreeSpace | ConvertTo-Json -Compress }`
	cpuScript     = `Get-CimInstance Win32_Processor | Select-Object -First 1 LoadPercentage | ConvertTo-Json -Compress`
	gpuScript     = `Get-CimInstance Win32_VideoController | Select-Object PNPDeviceID,Name,AdapterRAM,AdapterCompatibility,VideoProcessor | ConvertTo-Json -Compress`
)

var (
	memoryArgs = [...]string{psNoProfile, psNonInteractive, psCommand, memoryScript}
	cpuArgs    = [...]string{psNoProfile, psNonInteractive, psCommand, cpuScript}
	gpuArgs    = [...]string{psNoProfile, psNonInteractive, psCommand, gpuScript}
)

type WindowsObserverConfig struct {
	HostID      string
	StoragePath string
}

type windowsDeps struct {
	runner CommandRunner
	numCPU func() int
	now    func() time.Time
}

type WindowsObserver struct {
	config WindowsObserverConfig
	drive  string
	deps   windowsDeps
}

func NewWindowsObserver(config WindowsObserverConfig) (*WindowsObserver, error) {
	return newWindowsObserver(config, windowsDeps{runner: execRunner{}, numCPU: runtime.NumCPU, now: time.Now})
}

func newWindowsObserver(config WindowsObserverConfig, deps windowsDeps) (*WindowsObserver, error) {
	drive, validPath := windowsDriveIdentifier(config.StoragePath)
	if !validID(config.HostID) || !validPath || deps.runner == nil || deps.numCPU == nil || deps.now == nil {
		return nil, ErrWindowsConfig
	}
	return &WindowsObserver{config: config, drive: drive, deps: deps}, nil
}

func (o *WindowsObserver) Observe(ctx context.Context) (HostResourceObservation, error) {
	if err := ctx.Err(); err != nil {
		return HostResourceObservation{}, err
	}
	memory, err := o.readMemory(ctx)
	if err != nil {
		return HostResourceObservation{}, err
	}
	storage, err := o.readStorage(ctx)
	if err != nil {
		return HostResourceObservation{}, err
	}
	utilization, err := o.readCPUUtilization(ctx)
	if err != nil {
		return HostResourceObservation{}, err
	}
	gpus, err := o.readGPUs(ctx)
	if err != nil {
		return HostResourceObservation{}, err
	}
	if err := ctx.Err(); err != nil {
		return HostResourceObservation{}, err
	}
	cores := o.deps.numCPU()
	if cores < 1 || cores > 4096 {
		return HostResourceObservation{}, ErrWindowsCPU
	}
	result := HostResourceObservation{
		HostID:                o.config.HostID,
		ObservedAt:            o.deps.now().UTC().Format("2006-01-02T15:04:05.000Z"),
		Platform:              PlatformWindows,
		CPULogicalCores:       uint16(cores),
		CPUUtilizationPercent: utilization,
		Memory:                memory,
		Storage:               storage,
		Accelerators:          gpus,
	}
	if err := result.Validate(); err != nil {
		return HostResourceObservation{}, errors.Join(ErrWindowsConfig, err)
	}
	return clone(result), nil
}

// runPowerShell accepts only caller-owned fixed argv arrays. It enforces the
// shared output bound and maps all command details to stable probe errors.
func (o *WindowsObserver) runPowerShell(ctx context.Context, args []string, class error) ([]byte, error) {
	output, err := o.deps.runner.Run(ctx, powershellPath, args)
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			return nil, context.Canceled
		case errors.Is(err, context.DeadlineExceeded):
			return nil, context.DeadlineExceeded
		case ctx.Err() != nil:
			return nil, ctx.Err()
		case errors.Is(err, ErrAcceleratorOutput):
			return nil, errors.Join(class, ErrAcceleratorOutput)
		default:
			return nil, class
		}
	}
	if len(output) > maxCommandOutput {
		return nil, errors.Join(class, ErrAcceleratorOutput)
	}
	return output, nil
}

func (o *WindowsObserver) readMemory(ctx context.Context) (ResourceQuantity, error) {
	output, err := o.runPowerShell(ctx, memoryArgs[:], ErrWindowsMemory)
	if err != nil {
		return ResourceQuantity{}, err
	}
	value, err := ParseWindowsMemory(output)
	if err != nil {
		return ResourceQuantity{}, errors.Join(ErrWindowsMemory, err)
	}
	return value, nil
}

func (o *WindowsObserver) readStorage(ctx context.Context) (ResourceQuantity, error) {
	// The script is immutable. The separately validated two-character drive ID is
	// the only variable argument and occupies exactly argv[4].
	args := []string{psNoProfile, psNonInteractive, psCommand, storageScript, o.drive}
	output, err := o.runPowerShell(ctx, args, ErrWindowsStorage)
	if err != nil {
		return ResourceQuantity{}, err
	}
	value, err := ParseWindowsStorage(output)
	if err != nil {
		return ResourceQuantity{}, errors.Join(ErrWindowsStorage, err)
	}
	return value, nil
}

func (o *WindowsObserver) readCPUUtilization(ctx context.Context) (*uint8, error) {
	output, err := o.runPowerShell(ctx, cpuArgs[:], ErrWindowsCPU)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, nil
	}
	value, ok := ParseWindowsCPU(output)
	if !ok {
		return nil, nil
	}
	return value, nil
}

func (o *WindowsObserver) readGPUs(ctx context.Context) ([]AcceleratorObservation, error) {
	output, err := o.runPowerShell(ctx, gpuArgs[:], ErrWindowsGPU)
	if err != nil {
		return nil, err
	}
	value, err := ParseWindowsGPUs(output)
	if err != nil {
		return nil, errors.Join(ErrWindowsGPU, err)
	}
	return value, nil
}
