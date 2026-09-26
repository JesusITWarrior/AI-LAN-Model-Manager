//go:build linux

package observation

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"io"
	"math"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type NVIDIAObserver struct {
	path      string
	runner    CommandRunner
	available bool
}

func NewNVIDIAObserver() (*NVIDIAObserver, error) {
	path, err := exec.LookPath("nvidia-smi")
	if errors.Is(err, exec.ErrNotFound) {
		return &NVIDIAObserver{runner: execRunner{}}, nil
	}
	if err != nil {
		return nil, ErrAcceleratorProbe
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, ErrAcceleratorProbe
	}
	return &NVIDIAObserver{path: absolute, runner: execRunner{}, available: true}, nil
}

func NewNVIDIAObserverWithRunner(runner CommandRunner) (*NVIDIAObserver, error) {
	if runner == nil {
		return nil, ErrAcceleratorProbe
	}
	return &NVIDIAObserver{path: "/usr/bin/nvidia-smi", runner: runner, available: true}, nil
}

var nvidiaArgs = []string{
	"--query-gpu=index,uuid,name,memory.total,memory.used,utilization.gpu",
	"--format=csv,noheader,nounits",
}

func (o *NVIDIAObserver) ObserveAccelerators(ctx context.Context) ([]AcceleratorObservation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !o.available {
		return make([]AcceleratorObservation, 0), nil
	}
	output, err := o.runner.Run(ctx, o.path, append([]string(nil), nvidiaArgs...))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if errors.Is(err, ErrAcceleratorOutput) {
			return nil, ErrAcceleratorOutput
		}
		if noNVIDIADevices(output) {
			return make([]AcceleratorObservation, 0), nil
		}
		return nil, ErrAcceleratorProbe
	}
	if len(output) > maxCommandOutput {
		return nil, ErrAcceleratorOutput
	}
	if len(bytes.TrimSpace(output)) == 0 || noNVIDIADevices(output) {
		return make([]AcceleratorObservation, 0), nil
	}
	return parseNVIDIACSV(output)
}

func noNVIDIADevices(output []byte) bool {
	text := strings.ToLower(string(bytes.TrimSpace(output)))
	return strings.Contains(text, "no devices were found") || strings.Contains(text, "no devices found")
}

func parseNVIDIACSV(output []byte) ([]AcceleratorObservation, error) {
	reader := csv.NewReader(bytes.NewReader(output))
	reader.FieldsPerRecord = 6
	reader.TrimLeadingSpace = true
	observations := make([]AcceleratorObservation, 0)
	seen := make(map[string]struct{})
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, ErrAcceleratorProbe
		}
		if len(observations) >= 32 {
			return nil, ErrAcceleratorProbe
		}
		index, uuid, name := strings.TrimSpace(record[0]), strings.TrimSpace(record[1]), strings.TrimSpace(record[2])
		totalMiB, ok := strictUint(record[3])
		if !ok {
			return nil, ErrAcceleratorProbe
		}
		usedMiB, ok := strictUint(record[4])
		if !ok {
			return nil, ErrAcceleratorProbe
		}
		utilization, ok := strictPercent(record[5])
		if !ok {
			return nil, ErrAcceleratorProbe
		}
		total, overflow := mibToBytes(totalMiB)
		if overflow {
			return nil, ErrAcceleratorProbe
		}
		used, overflow := mibToBytes(usedMiB)
		if overflow || used > total {
			return nil, ErrAcceleratorProbe
		}
		id := uuid
		if !validID(id) {
			if !digits(index) {
				return nil, ErrAcceleratorProbe
			}
			id = "nvidia-" + index
		}
		if !validID(id) || !validName(name) {
			return nil, ErrAcceleratorProbe
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, ErrDuplicateID
		}
		seen[id] = struct{}{}
		value := AcceleratorObservation{ID: id, Name: name, Kind: AcceleratorNVIDIA, Memory: ResourceQuantity{TotalBytes: ByteAmount(total), UsedBytes: ByteAmount(used), AvailableBytes: ByteAmount(total - used)}, UtilizationPercent: utilization}
		if err := value.Validate(); err != nil {
			return nil, ErrAcceleratorProbe
		}
		observations = append(observations, value)
	}
	return observations, nil
}

func strictUint(value string) (uint64, bool) {
	value = strings.TrimSpace(value)
	if !digits(value) {
		return 0, false
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	return parsed, err == nil
}
func digits(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}
func strictPercent(value string) (*uint8, bool) {
	parsed, ok := strictUint(value)
	if !ok || parsed > 100 {
		return nil, false
	}
	result := uint8(parsed)
	return &result, true
}
func mibToBytes(value uint64) (uint64, bool) {
	const mib = uint64(1024 * 1024)
	if value > math.MaxUint64/mib {
		return 0, true
	}
	return value * mib, false
}

// CompositeObserver enriches a base host observation with accelerator observers.
type CompositeObserver struct {
	Base         Observer
	Accelerators []AcceleratorObserver
}

func (o CompositeObserver) Observe(ctx context.Context) (HostResourceObservation, error) {
	base, err := o.Base.Observe(ctx)
	if err != nil {
		return HostResourceObservation{}, err
	}
	combined := append([]AcceleratorObservation(nil), base.Accelerators...)
	seen := make(map[string]struct{}, len(combined))
	for _, value := range combined {
		if _, exists := seen[value.ID]; exists {
			return HostResourceObservation{}, ErrDuplicateID
		}
		seen[value.ID] = struct{}{}
	}
	for _, observer := range o.Accelerators {
		if observer == nil {
			return HostResourceObservation{}, ErrAcceleratorProbe
		}
		values, err := observer.ObserveAccelerators(ctx)
		if err != nil {
			return HostResourceObservation{}, err
		}
		for _, value := range values {
			if len(combined) >= 32 {
				return HostResourceObservation{}, ErrAcceleratorProbe
			}
			if _, exists := seen[value.ID]; exists {
				return HostResourceObservation{}, ErrDuplicateID
			}
			seen[value.ID] = struct{}{}
			combined = append(combined, value)
		}
	}
	base.Accelerators = combined
	if err := base.Validate(); err != nil {
		return HostResourceObservation{}, err
	}
	return clone(base), nil
}
