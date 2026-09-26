//go:build linux

package observation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const intelVendorID = "0x8086"
const defaultDRMRoot = "/sys/class/drm"

type IntelObserver struct {
	drmRoot string
}

func NewIntelObserver() *IntelObserver {
	return &IntelObserver{drmRoot: defaultDRMRoot}
}

func (o *IntelObserver) ObserveAccelerators(ctx context.Context) ([]AcceleratorObservation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Graceful absence: missing/empty DRM root
	entries, err := os.ReadDir(o.drmRoot)
	if err != nil || len(entries) == 0 {
		return make([]AcceleratorObservation, 0), nil
	}

	var candidates []string
	for _, entry := range entries {
		name := entry.Name()
		// Only cardN device nodes (exclude render/control/connectors)
		if !strings.HasPrefix(name, "card") || len(name) < 5 {
			continue
		}
		numStr := name[4:]
		if !digits(numStr) {
			continue
		}
		candidates = append(candidates, name)
	}

	if len(candidates) > 32 {
		return nil, ErrAcceleratorProbe
	}

	// Deterministic numeric card order
	sort.Slice(candidates, func(i, j int) bool {
		ni, _ := strconv.Atoi(candidates[i][4:])
		nj, _ := strconv.Atoi(candidates[j][4:])
		return ni < nj
	})

	var observations []AcceleratorObservation
	seen := make(map[string]struct{})

	for _, cardName := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		devicePath := filepath.Join(o.drmRoot, cardName, "device")
		vendorPath := filepath.Join(devicePath, "vendor")

		// Read vendor ID from symlink target content
		vendorBytes, err := os.ReadFile(vendorPath)
		if err != nil {
			return nil, ErrAcceleratorProbe
		}

		vendor := strings.TrimSpace(string(vendorBytes))
		if !strings.EqualFold(vendor, intelVendorID) {
			continue // Not Intel
		}

		// Build ID: prefer PCI slot from canonical device symlink when valid
		id := "intel-" + cardName
		resolvedPath, err := filepath.EvalSymlinks(devicePath)
		if err == nil && len(resolvedPath) > 0 {
			pciSlot := filepath.Base(resolvedPath)
			// PCI slot format like 0000:01:00.0 is valid ID
			if digitsOrColon(pciSlot) {
				id = pciSlot
			}
		}

		if !validID(id) {
			id = "intel-" + cardName
		}

		// Build name from optional safe product/device label. `product` is
		// human-readable text; `device` holds a numeric device-id that is
		// only treated as a label when it is a clean decimal value.
		name := ""
		productNamePath := filepath.Join(devicePath, "product")
		deviceLabelPath := filepath.Join(devicePath, "device")

		for _, p := range []string{productNamePath, deviceLabelPath} {
			if b, err := os.ReadFile(p); err == nil {
				candidate := strings.TrimSpace(string(b))
				if len(candidate) == 0 {
					continue
				}
				// Skip values that look binary (contain embedded NULs or
				// control bytes) rather than exposing raw device-id bytes.
				if looksBinary(candidate) {
					continue
				}
				name = candidate
				break
			}
		}

		if name == "" {
			num, _ := strconv.Atoi(cardName[4:])
			name = fmt.Sprintf("Intel GPU card%d", num)
		}

		// Memory: only when trustworthy explicit sysfs values exist
		memory := ResourceQuantity{}
		memTotalPath := filepath.Join(devicePath, "mem_info_vram_total")
		memUsedPath := filepath.Join(devicePath, "mem_info_vram_used")

		totalBytes, totalPresent, totalErr := readOptionalMemValue(memTotalPath)
		usedBytes, usedPresent, usedErr := readOptionalMemValue(memUsedPath)
		if totalErr != nil || usedErr != nil || totalPresent != usedPresent {
			return nil, ErrAcceleratorProbe
		}
		if totalPresent {
			if usedBytes > totalBytes {
				return nil, ErrAcceleratorProbe
			}
			memory = ResourceQuantity{
				TotalBytes:     ByteAmount(totalBytes),
				UsedBytes:      ByteAmount(usedBytes),
				AvailableBytes: ByteAmount(totalBytes - usedBytes),
			}
		}
		// If neither trustworthy memory field exists, zeros explicitly mean unknown.

		observation := AcceleratorObservation{
			ID:     id,
			Name:   name,
			Kind:   AcceleratorIntel,
			Memory: memory,
			// Utilization nil unless trustworthy percent source exists; do not invent.
		}

		if err := observation.Validate(); err != nil {
			return nil, ErrAcceleratorProbe
		}

		if _, duplicate := seen[id]; duplicate {
			return nil, ErrDuplicateID
		}
		seen[id] = struct{}{}

		observations = append(observations, observation)
	}

	return observations, nil
}

func readOptionalMemValue(path string) (uint64, bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	parsed, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, true, err
	}
	return parsed, true, nil
}

// digitsOrColon reports whether s is a conservative PCI slot identifier.
func digitsOrColon(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':' || c == '.') {
			return false
		}
	}
	return len(s) > 0
}

// looksBinary reports whether the value contains NUL or other control bytes
// that indicate a raw binary device-id rather than readable text.
func looksBinary(s string) bool {
	for _, c := range s {
		if c == '\x00' {
			return true
		}
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}
