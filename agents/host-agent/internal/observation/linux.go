//go:build linux

package observation

import (
	"bufio"
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	ErrLinuxConfig = errors.New("invalid linux observer configuration")
	ErrProcRead    = errors.New("proc read failed")
	ErrProcParse   = errors.New("proc parse failed")
	ErrStorage     = errors.New("storage probe failed")
)

type statFSFunc func(string, *syscall.Statfs_t) error

type LinuxObserverConfig struct {
	HostID         string
	StoragePath    string
	SampleInterval time.Duration
}

type linuxDeps struct {
	readFile func(string) ([]byte, error)
	statFS   statFSFunc
	numCPU   func() int
	now      func() time.Time
	sleep    func(context.Context, time.Duration) error
}

type LinuxObserver struct {
	config LinuxObserverConfig
	deps   linuxDeps
}

func NewLinuxObserver(config LinuxObserverConfig) (*LinuxObserver, error) {
	return newLinuxObserver(config, linuxDeps{
		readFile: os.ReadFile,
		statFS:   syscall.Statfs,
		numCPU:   runtime.NumCPU,
		now:      time.Now,
		sleep: func(ctx context.Context, duration time.Duration) error {
			timer := time.NewTimer(duration)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		},
	})
}

func newLinuxObserver(config LinuxObserverConfig, deps linuxDeps) (*LinuxObserver, error) {
	if !validID(config.HostID) || !filepath.IsAbs(config.StoragePath) || filepath.Clean(config.StoragePath) != config.StoragePath {
		return nil, ErrLinuxConfig
	}
	if config.SampleInterval == 0 {
		config.SampleInterval = 200 * time.Millisecond
	}
	if config.SampleInterval < 0 || deps.readFile == nil || deps.statFS == nil || deps.numCPU == nil || deps.now == nil || deps.sleep == nil {
		return nil, ErrLinuxConfig
	}
	return &LinuxObserver{config: config, deps: deps}, nil
}

func (o *LinuxObserver) Observe(ctx context.Context) (HostResourceObservation, error) {
	if err := ctx.Err(); err != nil {
		return HostResourceObservation{}, err
	}
	memory, err := o.readMemory()
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
	utilization, err := o.readCPUUtilization(ctx)
	if err != nil {
		return HostResourceObservation{}, err
	}
	cores := o.deps.numCPU()
	if cores < 1 || cores > 4096 {
		return HostResourceObservation{}, ErrProcParse
	}
	result := HostResourceObservation{
		HostID: o.config.HostID, ObservedAt: o.deps.now().UTC().Format("2006-01-02T15:04:05.000Z"), Platform: PlatformLinux,
		CPULogicalCores: uint16(cores), CPUUtilizationPercent: utilization, Memory: memory, Storage: storage,
		Accelerators: make([]AcceleratorObservation, 0),
	}
	if err := result.Validate(); err != nil {
		return HostResourceObservation{}, errors.Join(ErrProcParse, err)
	}
	return result, nil
}

func (o *LinuxObserver) readMemory() (ResourceQuantity, error) {
	data, err := o.deps.readFile("/proc/meminfo")
	if err != nil {
		return ResourceQuantity{}, errors.Join(ErrProcRead, err)
	}
	values := make(map[string]uint64)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSuffix(parts[0], ":")
		if key != "MemTotal" && key != "MemAvailable" && key != "MemFree" && key != "Buffers" && key != "Cached" {
			continue
		}
		value, parseErr := strconv.ParseUint(parts[1], 10, 64)
		if parseErr != nil || (len(parts) >= 3 && parts[2] != "kB") {
			return ResourceQuantity{}, ErrProcParse
		}
		if value > math.MaxUint64/1024 {
			return ResourceQuantity{}, ErrProcParse
		}
		values[key] = value * 1024
	}
	if err := scanner.Err(); err != nil {
		return ResourceQuantity{}, errors.Join(ErrProcRead, err)
	}
	total, ok := values["MemTotal"]
	if !ok {
		return ResourceQuantity{}, ErrProcParse
	}
	available, ok := values["MemAvailable"]
	if !ok {
		var overflow bool
		available, overflow = add3(values["MemFree"], values["Buffers"], values["Cached"])
		if overflow {
			return ResourceQuantity{}, ErrProcParse
		}
	}
	if available > total {
		return ResourceQuantity{}, ErrProcParse
	}
	result := ResourceQuantity{TotalBytes: ByteAmount(total), UsedBytes: ByteAmount(total - available), AvailableBytes: ByteAmount(available)}
	if err := result.Validate(); err != nil {
		return ResourceQuantity{}, errors.Join(ErrProcParse, err)
	}
	return result, nil
}

func (o *LinuxObserver) readStorage() (ResourceQuantity, error) {
	var stat syscall.Statfs_t
	if err := o.deps.statFS(o.config.StoragePath, &stat); err != nil {
		return ResourceQuantity{}, errors.Join(ErrStorage, err)
	}
	if stat.Bsize <= 0 {
		return ResourceQuantity{}, ErrStorage
	}
	blockSize := uint64(stat.Bsize)
	total, overflow := multiply(stat.Blocks, blockSize)
	if overflow {
		return ResourceQuantity{}, ErrStorage
	}
	free, overflow := multiply(stat.Bfree, blockSize)
	if overflow || free > total {
		return ResourceQuantity{}, ErrStorage
	}
	available, overflow := multiply(stat.Bavail, blockSize)
	if overflow || available > total {
		return ResourceQuantity{}, ErrStorage
	}
	result := ResourceQuantity{TotalBytes: ByteAmount(total), UsedBytes: ByteAmount(total - free), AvailableBytes: ByteAmount(available)}
	if err := result.Validate(); err != nil {
		return ResourceQuantity{}, errors.Join(ErrStorage, err)
	}
	return result, nil
}

type cpuCounters struct{ total, idle uint64 }

func parseCPU(data []byte) (cpuCounters, bool) {
	line, _, _ := strings.Cut(string(data), "\n")
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuCounters{}, false
	}
	var result cpuCounters
	for index, field := range fields[1:] {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil || result.total > math.MaxUint64-value {
			return cpuCounters{}, false
		}
		result.total += value
		if index == 3 || index == 4 {
			if result.idle > math.MaxUint64-value {
				return cpuCounters{}, false
			}
			result.idle += value
		}
	}
	return result, true
}
func (o *LinuxObserver) readCPUUtilization(ctx context.Context) (*uint8, error) {
	firstData, err := o.deps.readFile("/proc/stat")
	if err != nil {
		return nil, nil
	}
	first, ok := parseCPU(firstData)
	if !ok {
		return nil, nil
	}
	if err := o.deps.sleep(ctx, o.config.SampleInterval); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	secondData, err := o.deps.readFile("/proc/stat")
	if err != nil {
		return nil, nil
	}
	second, ok := parseCPU(secondData)
	if !ok || second.total <= first.total || second.idle < first.idle {
		return nil, nil
	}
	totalDelta := second.total - first.total
	idleDelta := second.idle - first.idle
	if idleDelta > totalDelta {
		return nil, nil
	}
	value := uint8(((totalDelta - idleDelta) * 100) / totalDelta)
	return &value, nil
}
