package observation

import (
	"context"
	"errors"
	"regexp"
	"time"
)

type ByteAmount uint64
type AcceleratorKind string

type HostPlatform string

const (
	AcceleratorNVIDIA AcceleratorKind = "nvidia"
	AcceleratorAMD    AcceleratorKind = "amd"
	AcceleratorIntel  AcceleratorKind = "intel"
	AcceleratorApple  AcceleratorKind = "apple"
	AcceleratorOther  AcceleratorKind = "other"
	PlatformLinux     HostPlatform    = "linux"
	PlatformDarwin    HostPlatform    = "darwin"
	PlatformWindows   HostPlatform    = "windows"
)

// AcceleratorObserver probes a specific accelerator class and returns observations.
// Graceful absence (no executable, no devices) must return an empty non-nil slice with nil error.
type AcceleratorObserver interface {
	ObserveAccelerators(ctx context.Context) ([]AcceleratorObservation, error)
}

var (
	ErrInvalidObservation = errors.New("invalid observation")
	ErrInvalidResource    = errors.New("invalid resource quantity")
	ErrDuplicateID        = errors.New("duplicate accelerator id")
	ErrAcceleratorProbe   = errors.New("accelerator probe failed")
	idPattern             = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
)

type ResourceQuantity struct {
	TotalBytes     ByteAmount `json:"totalBytes"`
	UsedBytes      ByteAmount `json:"usedBytes"`
	AvailableBytes ByteAmount `json:"availableBytes"`
}

type AcceleratorObservation struct {
	ID                 string           `json:"id"`
	Name               string           `json:"name"`
	Kind               AcceleratorKind  `json:"kind"`
	Memory             ResourceQuantity `json:"memory"`
	UtilizationPercent *uint8           `json:"utilizationPercent"`
}

type HostResourceObservation struct {
	HostID                string                   `json:"hostId"`
	ObservedAt            string                   `json:"observedAt"`
	Platform              HostPlatform             `json:"platform"`
	CPULogicalCores       uint16                   `json:"cpuLogicalCores"`
	CPUUtilizationPercent *uint8                   `json:"cpuUtilizationPercent"`
	Memory                ResourceQuantity         `json:"memory"`
	Storage               ResourceQuantity         `json:"storage"`
	Accelerators          []AcceleratorObservation `json:"accelerators"`
}

func (r ResourceQuantity) Validate() error {
	if r.UsedBytes > r.TotalBytes || r.AvailableBytes > r.TotalBytes || r.UsedBytes > r.TotalBytes-r.AvailableBytes {
		return ErrInvalidResource
	}
	return nil
}

func validID(value string) bool {
	return len(value) >= 1 && len(value) <= 128 && idPattern.MatchString(value)
}
func validName(value string) bool {
	if len(value) < 1 || len(value) > 256 {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
func validPercent(value *uint8) bool { return value == nil || *value <= 100 }
func validTimestamp(value string) bool {
	if len(value) != len("2006-01-02T15:04:05.000Z") {
		return false
	}
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z", value)
	return err == nil && parsed.UTC().Format("2006-01-02T15:04:05.000Z") == value
}

func (a AcceleratorObservation) Validate() error {
	if !validID(a.ID) || !validName(a.Name) || !validPercent(a.UtilizationPercent) {
		return ErrInvalidObservation
	}
	switch a.Kind {
	case AcceleratorNVIDIA, AcceleratorAMD, AcceleratorIntel, AcceleratorApple, AcceleratorOther:
	default:
		return ErrInvalidObservation
	}
	if err := a.Memory.Validate(); err != nil {
		return err
	}
	return nil
}

func (h HostResourceObservation) Validate() error {
	if !validID(h.HostID) || !validTimestamp(h.ObservedAt) || h.CPULogicalCores < 1 || h.CPULogicalCores > 4096 || !validPercent(h.CPUUtilizationPercent) {
		return ErrInvalidObservation
	}
	switch h.Platform {
	case PlatformLinux, PlatformDarwin, PlatformWindows:
	default:
		return ErrInvalidObservation
	}
	if err := h.Memory.Validate(); err != nil {
		return err
	}
	if err := h.Storage.Validate(); err != nil {
		return err
	}
	if len(h.Accelerators) > 32 {
		return ErrInvalidObservation
	}
	seen := make(map[string]struct{}, len(h.Accelerators))
	for _, accelerator := range h.Accelerators {
		if err := accelerator.Validate(); err != nil {
			return err
		}
		if _, exists := seen[accelerator.ID]; exists {
			return ErrDuplicateID
		}
		seen[accelerator.ID] = struct{}{}
	}
	return nil
}
