//go:build linux

package observation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIntelMixedVendors(t *testing.T) {
	tmpDir := t.TempDir()

	// Create fake DRM structure with mixed vendors
	intelCard := filepath.Join(tmpDir, "card0", "device")
	amdCard := filepath.Join(tmpDir, "card1", "device")

	os.MkdirAll(intelCard, 0755)
	os.MkdirAll(amdCard, 0755)

	os.WriteFile(filepath.Join(intelCard, "vendor"), []byte("0x8086\n"), 0644)
	os.WriteFile(filepath.Join(amdCard, "vendor"), []byte("0x1002\n"), 0644)

	observer := &IntelObserver{drmRoot: tmpDir}
	values, err := observer.ObserveAccelerators(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || values[0].Kind != AcceleratorIntel {
		t.Fatalf("expected only Intel card: %#v", values)
	}
}

func TestIntelNumericOrdering(t *testing.T) {
	tmpDir := t.TempDir()

	// Create cards in non-numeric order
	for _, n := range []string{"card10", "card2", "card5"} {
		devicePath := filepath.Join(tmpDir, n, "device")
		os.MkdirAll(devicePath, 0755)
		os.WriteFile(filepath.Join(devicePath, "vendor"), []byte("0x8086\n"), 0644)
	}

	observer := &IntelObserver{drmRoot: tmpDir}
	values, err := observer.ObserveAccelerators(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// card2 should come before card10 (numeric order)
	if len(values) < 3 || !strings.Contains(values[0].ID, "card2") || !strings.Contains(values[1].ID, "card5") || !strings.Contains(values[2].ID, "card10") {
		t.Fatalf("expected numeric ordering: %#v", values)
	}
}

func TestIntelGracefulAbsence(t *testing.T) {
	// Missing root
	observer := &IntelObserver{drmRoot: "/nonexistent/path"}
	values, err := observer.ObserveAccelerators(context.Background())
	if err != nil || len(values) != 0 {
		t.Fatalf("missing root should be graceful absence: %#v %v", values, err)
	}

	// Empty directory (no cardN entries)
	tmpDir := t.TempDir()
	observer = &IntelObserver{drmRoot: tmpDir}
	values, err = observer.ObserveAccelerators(context.Background())
	if err != nil || len(values) != 0 {
		t.Fatalf("empty dir should be graceful absence: %#v %v", values, err)
	}

	// No Intel cards (all AMD)
	intelDir := filepath.Join(tmpDir, "card0")
	os.MkdirAll(filepath.Join(intelDir, "device"), 0755)
	os.WriteFile(filepath.Join(intelDir, "device", "vendor"), []byte("0x1002\n"), 0644)

	values, err = observer.ObserveAccelerators(context.Background())
	if err != nil || len(values) != 0 {
		t.Fatalf("no Intel should be graceful absence: %#v %v", values, err)
	}
}

func TestIntelPermissionError(t *testing.T) {
	tmpDir := t.TempDir()

	intelCard := filepath.Join(tmpDir, "card0", "device")
	os.MkdirAll(intelCard, 0755)
	vendorPath := filepath.Join(intelCard, "vendor")
	os.WriteFile(vendorPath, []byte("0x8086\n"), 0644)

	// Make vendor unreadable
	os.Chmod(vendorPath, 0000)

	observer := &IntelObserver{drmRoot: tmpDir}
	_, err := observer.ObserveAccelerators(context.Background())
	if !errors.Is(err, ErrAcceleratorProbe) {
		t.Fatalf("permission error should be ErrAcceleratorProbe: %v", err)
	}

	// Restore for cleanup
	os.Chmod(vendorPath, 0644)
}

func TestIntelMemoryCompleteIncompleteUsedGreaterThanTotal(t *testing.T) {
	tmpDir := t.TempDir()

	intelCard := filepath.Join(tmpDir, "card0", "device")
	os.MkdirAll(intelCard, 0755)
	os.WriteFile(filepath.Join(intelCard, "vendor"), []byte("0x8086\n"), 0644)

	// Complete memory values
	memDir := filepath.Join(tmpDir, "card1", "device")
	os.MkdirAll(memDir, 0755)
	os.WriteFile(filepath.Join(memDir, "vendor"), []byte("0x8086\n"), 0644)
	os.WriteFile(filepath.Join(memDir, "mem_info_vram_total"), []byte("1024\n"), 0644)
	os.WriteFile(filepath.Join(memDir, "mem_info_vram_used"), []byte("512\n"), 0644)

	observer := &IntelObserver{drmRoot: tmpDir}
	values, err := observer.ObserveAccelerators(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// card0 has no memory (zeros = unknown)
	if len(values) < 2 {
		t.Fatalf("expected 2 cards: %#v", values)
	}

	// Find the one with memory
	for _, v := range values {
		if strings.Contains(v.ID, "card1") {
			if v.Memory.TotalBytes != 1024 || v.Memory.UsedBytes != 512 || v.Memory.AvailableBytes != 512 {
				t.Fatalf("bad memory: %#v", v.Memory)
			}
		}
	}

	// used > total should be rejected
	badMemDir := filepath.Join(tmpDir, "card2", "device")
	os.MkdirAll(badMemDir, 0755)
	os.WriteFile(filepath.Join(badMemDir, "vendor"), []byte("0x8086\n"), 0644)
	os.WriteFile(filepath.Join(badMemDir, "mem_info_vram_total"), []byte("100\n"), 0644)
	os.WriteFile(filepath.Join(badMemDir, "mem_info_vram_used"), []byte("200\n"), 0644)

	_, err = observer.ObserveAccelerators(context.Background())
	if !errors.Is(err, ErrAcceleratorProbe) {
		t.Fatalf("used > total should be rejected: %v", err)
	}
}

func TestIntelInvalidNames(t *testing.T) {
	tmpDir := t.TempDir()

	intelCard := filepath.Join(tmpDir, "card0", "device")
	os.MkdirAll(intelCard, 0755)
	os.WriteFile(filepath.Join(intelCard, "vendor"), []byte("0x8086\n"), 0644)

	// Invalid name with newline
	productNamePath := filepath.Join(tmpDir, "card1", "device")
	os.MkdirAll(productNamePath, 0755)
	os.WriteFile(filepath.Join(productNamePath, "vendor"), []byte("0x8086\n"), 0644)
	os.WriteFile(filepath.Join(productNamePath, "product"), []byte("bad\nname\n"), 0644)

	observer := &IntelObserver{drmRoot: tmpDir}
	values, err := observer.ObserveAccelerators(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Should fall back to default name "Intel GPU card1"
	found := false
	for _, v := range values {
		if strings.Contains(v.ID, "card1") {
			if v.Name != "Intel GPU card1" {
				t.Fatalf("expected fallback name: %s", v.Name)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("card1 not found in results")
	}
}

func TestIntelMax32(t *testing.T) {
	tmpDir := t.TempDir()

	var rows []string
	for i := 0; i < 35; i++ {
		cardName := fmt.Sprintf("card%d", i)
		devicePath := filepath.Join(tmpDir, cardName, "device")
		os.MkdirAll(devicePath, 0755)
		rows = append(rows, cardName)
	}

	for _, cardName := range rows {
		devicePath := filepath.Join(tmpDir, cardName, "device")
		os.WriteFile(filepath.Join(devicePath, "vendor"), []byte("0x8086\n"), 0644)
	}

	observer := &IntelObserver{drmRoot: tmpDir}
	if _, err := observer.ObserveAccelerators(context.Background()); !errors.Is(err, ErrAcceleratorProbe) {
		t.Fatalf("more than 32 cards must be rejected: %v", err)
	}
}

func TestIntelCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tmpDir := t.TempDir()
	observer := &IntelObserver{drmRoot: tmpDir}
	_, err := observer.ObserveAccelerators(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation: %v", err)
	}
}

func TestIntelCopyIsolation(t *testing.T) {
	tmpDir := t.TempDir()

	intelCard := filepath.Join(tmpDir, "card0", "device")
	os.MkdirAll(intelCard, 0755)
	os.WriteFile(filepath.Join(intelCard, "vendor"), []byte("0x8086\n"), 0644)

	observer := &IntelObserver{drmRoot: tmpDir}
	first, err := observer.ObserveAccelerators(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Modify the result
	first[0].Name = "changed"

	// Observe again - should be unchanged
	second, err := observer.ObserveAccelerators(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(second) == 0 || strings.Contains(second[0].Name, "changed") {
		t.Fatalf("copy isolation failed: %#v", second)
	}
}

func TestIntelCompositionAfterNVIDIAAMD(t *testing.T) {
	tmpDir := t.TempDir()

	intelCard := filepath.Join(tmpDir, "card0", "device")
	os.MkdirAll(intelCard, 0755)
	os.WriteFile(filepath.Join(intelCard, "vendor"), []byte("0x8086\n"), 0644)

	observer := &IntelObserver{drmRoot: tmpDir}
	if _, err := observer.ObserveAccelerators(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Drop the base accelerators so the composed set is exactly
	// NVIDIA, AMD, Intel in that order (composition order preserved).
	raw := validObservation()
	raw.Accelerators = nil
	base, _ := NewSyntheticObserver(raw, nil)
	nvidia := acceleratorFixture{[]AcceleratorObservation{{ID: "nvidia-extra", Name: "NVIDIA", Kind: AcceleratorNVIDIA, Memory: quantity(10, 1, 9)}}}
	amd := acceleratorFixture{[]AcceleratorObservation{{ID: "amd-extra", Name: "AMD", Kind: AcceleratorAMD, Memory: quantity(10, 1, 9)}}}

	composite := CompositeObserver{Base: base, Accelerators: []AcceleratorObserver{nvidia, amd, observer}}
	combined, err := composite.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// NVIDIA first, then AMD, then Intel (composition order preserved)
	if len(combined.Accelerators) != 3 || combined.Accelerators[0].Kind != AcceleratorNVIDIA ||
		combined.Accelerators[1].Kind != AcceleratorAMD || combined.Accelerators[2].Kind != AcceleratorIntel {
		t.Fatalf("wrong composition order: %#v", combined.Accelerators)
	}
}

func TestIntelSymlinkPCISlot(t *testing.T) {
	tmpDir := t.TempDir()

	// card0/device is a symlink to the real PCI device directory; the vendor
	// file lives in the target directory, mirroring real sysfs. (No regular
	// card0/device may pre-exist, otherwise the symlink cannot be created.)
	pciTarget := filepath.Join(tmpDir, "pci", "0000:af:00.0")
	os.MkdirAll(pciTarget, 0755)
	os.WriteFile(filepath.Join(pciTarget, "vendor"), []byte("0x8086\n"), 0644)
	os.MkdirAll(filepath.Join(tmpDir, "card0"), 0755)
	os.Symlink(pciTarget, filepath.Join(tmpDir, "card0", "device"))

	observer := &IntelObserver{drmRoot: tmpDir}
	values, err := observer.ObserveAccelerators(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Should use PCI slot as ID when valid
	found := false
	for _, v := range values {
		if strings.Contains(v.ID, "0000:af") {
			found = true
		}
	}
	if !found && len(values) > 0 {
		t.Fatalf("expected PCI slot ID: %s", values[0].ID)
	}
}

func TestIntelDuplicateIDs(t *testing.T) {
	tmpDir := t.TempDir()

	// Create two cards that would resolve to same PCI slot (duplicate IDs)
	for i := 0; i < 2; i++ {
		cardName := fmt.Sprintf("card%d", i)
		devicePath := filepath.Join(tmpDir, cardName, "device")
		os.MkdirAll(devicePath, 0755)
		os.WriteFile(filepath.Join(devicePath, "vendor"), []byte("0x8086\n"), 0644)
	}

	observer := &IntelObserver{drmRoot: tmpDir}
	values, err := observer.ObserveAccelerators(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Should not have duplicate IDs (fallback to intel-cardN when PCI invalid)
	seen := make(map[string]bool)
	for _, v := range values {
		if seen[v.ID] {
			t.Fatalf("duplicate ID: %s", v.ID)
		}
		seen[v.ID] = true
	}
}

func TestIntelExcludedNodeTypes(t *testing.T) {
	tmpDir := t.TempDir()

	// Create various node types that should be excluded
	for _, name := range []string{"renderD128", "controlD64", "card0", "connector-DP-1"} {
		os.MkdirAll(filepath.Join(tmpDir, name), 0755)
	}

	// Only card0 should be included (has vendor file)
	devicePath := filepath.Join(tmpDir, "card0", "device")
	os.MkdirAll(devicePath, 0755)
	os.WriteFile(filepath.Join(devicePath, "vendor"), []byte("0x8086\n"), 0644)

	observer := &IntelObserver{drmRoot: tmpDir}
	values, err := observer.ObserveAccelerators(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Only card0 should be found (render/control/connectors excluded by prefix check)
	if len(values) != 1 || !strings.Contains(values[0].ID, "card0") {
		t.Fatalf("expected only card0: %#v", values)
	}
}

func TestIntelMemoryIncomplete(t *testing.T) {
	tmpDir := t.TempDir()

	intelCard := filepath.Join(tmpDir, "card0", "device")
	os.MkdirAll(intelCard, 0755)
	os.WriteFile(filepath.Join(intelCard, "vendor"), []byte("0x8086\n"), 0644)

	// Only total memory (no used) - incomplete
	memDir := filepath.Join(tmpDir, "card1", "device")
	os.MkdirAll(memDir, 0755)
	os.WriteFile(filepath.Join(memDir, "vendor"), []byte("0x8086\n"), 0644)
	os.WriteFile(filepath.Join(memDir, "mem_info_vram_total"), []byte("1024\n"), 0644)

	observer := &IntelObserver{drmRoot: tmpDir}
	if _, err := observer.ObserveAccelerators(context.Background()); !errors.Is(err, ErrAcceleratorProbe) {
		t.Fatalf("incomplete memory pair must be rejected: %v", err)
	}
}

func TestIntelRejectsMalformedMemoryValue(t *testing.T) {
	tmpDir := t.TempDir()
	device := filepath.Join(tmpDir, "card0", "device")
	if err := os.MkdirAll(device, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(device, "vendor"), []byte("0x8086\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(device, "mem_info_vram_total"), []byte("not-a-number\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(device, "mem_info_vram_used"), []byte("1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	observer := &IntelObserver{drmRoot: tmpDir}
	if _, err := observer.ObserveAccelerators(context.Background()); !errors.Is(err, ErrAcceleratorProbe) {
		t.Fatalf("malformed memory must be rejected: %v", err)
	}
}
