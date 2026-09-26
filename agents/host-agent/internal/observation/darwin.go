//go:build darwin

package observation

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

const (
	darwinTopPath            = "/usr/bin/top"
	darwinSysctlPath         = "/usr/sbin/sysctl"
	darwinVMStatPath         = "/usr/bin/vm_stat"
	darwinSystemProfilerPath = "/usr/sbin/system_profiler"
)

type DarwinObserverConfig struct {
	HostID      string
	StoragePath string
}

type darwinStatFSFunc func(string, *syscall.Statfs_t) error

type darwinDeps struct {
	runner CommandRunner
	statFS darwinStatFSFunc
	numCPU func() int
	now    func() time.Time
}

type DarwinObserver struct {
	config DarwinObserverConfig
	deps   darwinDeps
}

func NewDarwinObserver(config DarwinObserverConfig) (*DarwinObserver, error) {
	return newDarwinObserver(config, darwinDeps{runner: execRunner{}, statFS: syscall.Statfs, numCPU: runtime.NumCPU, now: time.Now})
}

func newDarwinObserver(config DarwinObserverConfig, deps darwinDeps) (*DarwinObserver, error) {
	if !validID(config.HostID) || !filepath.IsAbs(config.StoragePath) || filepath.Clean(config.StoragePath) != config.StoragePath || deps.runner == nil || deps.statFS == nil || deps.numCPU == nil || deps.now == nil {
		return nil, ErrDarwinConfig
	}
	return &DarwinObserver{config: config, deps: deps}, nil
}

func (o *DarwinObserver) Observe(ctx context.Context) (HostResourceObservation, error) {
	if err := ctx.Err(); err != nil {
		return HostResourceObservation{}, err
	}
	totalOutput, err := o.runRequired(ctx, darwinSysctlPath, []string{"-n", "hw.memsize"}, ErrDarwinMemory)
	if err != nil {
		return HostResourceObservation{}, err
	}
	if err := ctx.Err(); err != nil {
		return HostResourceObservation{}, err
	}
	vmOutput, err := o.runRequired(ctx, darwinVMStatPath, nil, ErrDarwinMemory)
	if err != nil {
		return HostResourceObservation{}, err
	}
	memory, err := parseDarwinMemory(totalOutput, vmOutput)
	if err != nil {
		return HostResourceObservation{}, err
	}
	if err := ctx.Err(); err != nil {
		return HostResourceObservation{}, err
	}
	storage, err := o.readStorage()
	if err != nil {
		return HostResourceObservation{}, err
	}
	if err := ctx.Err(); err != nil {
		return HostResourceObservation{}, err
	}

	// top provides no stable machine-readable cumulative counters on macOS. Its
	// final sample is therefore a nullable, best-effort utilization snapshot.
	var utilization *uint8
	if output, runErr := o.deps.runner.Run(ctx, darwinTopPath, []string{"-l", "2", "-n", "0"}); runErr == nil {
		utilization, _ = parseDarwinCPU(output)
	} else if ctxErr := ctx.Err(); ctxErr != nil {
		return HostResourceObservation{}, ctxErr
	}
	if err := ctx.Err(); err != nil {
		return HostResourceObservation{}, err
	}
	gpuOutput, err := o.runRequired(ctx, darwinSystemProfilerPath, []string{"SPDisplaysDataType", "-json"}, ErrDarwinGPU)
	if err != nil {
		return HostResourceObservation{}, err
	}
	accelerators, err := parseDarwinGPUs(gpuOutput)
	if err != nil {
		return HostResourceObservation{}, err
	}
	if accelerators == nil {
		accelerators = make([]AcceleratorObservation, 0)
	}
	if err := ctx.Err(); err != nil {
		return HostResourceObservation{}, err
	}
	cores := o.deps.numCPU()
	if cores < 1 || cores > 4096 {
		return HostResourceObservation{}, ErrDarwinCPU
	}
	result := HostResourceObservation{
		HostID:                o.config.HostID,
		ObservedAt:            o.deps.now().UTC().Format("2006-01-02T15:04:05.000Z"),
		Platform:              PlatformDarwin,
		CPULogicalCores:       uint16(cores),
		CPUUtilizationPercent: utilization,
		Memory:                memory,
		Storage:               storage,
		Accelerators:          accelerators,
	}
	if err := result.Validate(); err != nil {
		return HostResourceObservation{}, errors.Join(ErrInvalidObservation, err)
	}
	return clone(result), nil
}

func (o *DarwinObserver) runRequired(ctx context.Context, path string, args []string, class error) ([]byte, error) {
	output, err := o.deps.runner.Run(ctx, path, append([]string(nil), args...))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if errors.Is(err, ErrAcceleratorOutput) {
			return nil, errors.Join(class, ErrAcceleratorOutput)
		}
		return nil, class
	}
	if len(output) > maxCommandOutput {
		return nil, errors.Join(class, ErrAcceleratorOutput)
	}
	return output, nil
}

func (o *DarwinObserver) readStorage() (ResourceQuantity, error) {
	var stat syscall.Statfs_t
	if err := o.deps.statFS(o.config.StoragePath, &stat); err != nil {
		return ResourceQuantity{}, ErrDarwinStorage
	}
	if stat.Bsize <= 0 {
		return ResourceQuantity{}, ErrDarwinStorage
	}
	blockSize := uint64(stat.Bsize)
	total, overflow := multiply(stat.Blocks, blockSize)
	if overflow {
		return ResourceQuantity{}, ErrDarwinStorage
	}
	free, overflow := multiply(stat.Bfree, blockSize)
	if overflow || free > total {
		return ResourceQuantity{}, ErrDarwinStorage
	}
	available, overflow := multiply(stat.Bavail, blockSize)
	if overflow || available > total {
		return ResourceQuantity{}, ErrDarwinStorage
	}
	result := ResourceQuantity{TotalBytes: ByteAmount(total), UsedBytes: ByteAmount(total - free), AvailableBytes: ByteAmount(available)}
	if result.Validate() != nil {
		return ResourceQuantity{}, ErrDarwinStorage
	}
	return result, nil
}
