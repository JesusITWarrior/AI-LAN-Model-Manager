package observation

import (
	"encoding/json"
	"fmt"
	"math"
	"testing"
)

// ---- Memory Parser Tests ----

func TestParseWindowsMemory_scalarObject(t *testing.T) {
	data := map[string]uint64{
		"__CLASS":                0,        // will be string below
		"TotalVisibleMemorySize": 16777216, // 16 GiB in KiB
		"FreePhysicalMemory":     8388608,  // 8 GiB in KiB
	}
	data["__CLASS"] = 0
	raw := map[string]interface{}{
		"__CLASS":                "Win32_OperatingSystem",
		"TotalVisibleMemorySize": float64(16777216),
		"FreePhysicalMemory":     float64(8388608),
	}
	output, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}

	result, err := ParseWindowsMemory(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedTotal := uint64(16777216 * 1024) // KiB → bytes
	expectedFree := uint64(8388608 * 1024)
	if result.TotalBytes != ByteAmount(expectedTotal) {
		t.Errorf("total = %d, want %d", result.TotalBytes, expectedTotal)
	}
	if result.UsedBytes != ByteAmount(expectedTotal-expectedFree) {
		t.Errorf("used = %d, want %d", result.UsedBytes, expectedTotal-expectedFree)
	}
	if result.AvailableBytes != ByteAmount(expectedFree) {
		t.Errorf("available = %d, want %d", result.AvailableBytes, expectedFree)
	}
}

func TestParseWindowsMemory_overflowKiB(t *testing.T) {
	raw := map[string]interface{}{
		"__CLASS":                "Win32_OperatingSystem",
		"TotalVisibleMemorySize": float64(math.MaxUint64/512 + 1), // would overflow when ×1024
		"FreePhysicalMemory":     float64(1024),
	}
	output, _ := json.Marshal(raw)

	_, err := ParseWindowsMemory(output)
	if err == nil {
		t.Fatal("expected error for overflow KiB→bytes")
	}
}

func TestParseWindowsMemory_malformedJSON(t *testing.T) {
	for _, input := range []string{"", "not json", "{invalid}", "[1,2,3]"} {
		_, err := ParseWindowsMemory([]byte(input))
		if err == nil {
			t.Fatalf("expected error for malformed JSON: %q", input)
		}
	}
}

func TestParseWindowsMemory_missingFields(t *testing.T) {
	raw := map[string]interface{}{
		"__CLASS": "Win32_OperatingSystem",
		// TotalVisibleMemorySize missing
		"FreePhysicalMemory": float64(1024),
	}
	output, _ := json.Marshal(raw)

	_, err := ParseWindowsMemory(output)
	if err == nil {
		t.Fatal("expected error for missing TotalVisibleMemorySize")
	}

	raw["TotalVisibleMemorySize"] = float64(2048)
	delete(raw, "FreePhysicalMemory")
	output, _ = json.Marshal(raw)

	_, err = ParseWindowsMemory(output)
	if err == nil {
		t.Fatal("expected error for missing FreePhysicalMemory")
	}
}

func TestParseWindowsMemory_inconsistent(t *testing.T) {
	raw := map[string]interface{}{
		"__CLASS":                "Win32_OperatingSystem",
		"TotalVisibleMemorySize": float64(1024),
		"FreePhysicalMemory":     float64(2048), // free > total
	}
	output, _ := json.Marshal(raw)

	_, err := ParseWindowsMemory(output)
	if err == nil {
		t.Fatal("expected error for free > total")
	}
}

func TestParseWindowsMemory_zeroTotal(t *testing.T) {
	raw := map[string]interface{}{
		"__CLASS":                "Win32_OperatingSystem",
		"TotalVisibleMemorySize": float64(0),
		"FreePhysicalMemory":     float64(0),
	}
	output, _ := json.Marshal(raw)

	_, err := ParseWindowsMemory(output)
	if err == nil {
		t.Fatal("expected error for zero total memory")
	}
}

func TestParseWindowsMemory_extraJSONTokens(t *testing.T) {
	raw := map[string]interface{}{
		"__CLASS":                "Win32_OperatingSystem",
		"TotalVisibleMemorySize": float64(1024),
		"FreePhysicalMemory":     float64(512),
	}
	output, _ := json.Marshal(raw)
	output = append(output, []byte(` {"extra":"token"} `)...)

	_, err := ParseWindowsMemory(output)
	if err == nil {
		t.Fatal("expected error for extra JSON tokens")
	}
}

// ---- CPU Parser Tests ----

func TestParseWindowsCPU_validLoadPercentage(t *testing.T) {
	tests := []struct {
		name    string
		loadPct int
		wantNil bool
		wantVal uint8
	}{
		{"zero", 0, false, 0},
		{"fifty", 50, false, 50},
		{"hundred", 100, false, 100},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := map[string]interface{}{
				"__CLASS":        "Win32_Processor",
				"LoadPercentage": float64(tc.loadPct),
			}
			output, _ := json.Marshal(raw)

			result, ok := ParseWindowsCPU(output)
			if !ok {
				t.Fatalf("ParseWindowsCPU returned false for valid input")
			}
			if tc.wantNil && result != nil {
				t.Fatal("expected nil pointer")
			}
			if !tc.wantNil && (result == nil || *result != tc.wantVal) {
				t.Errorf("got %v, want %d", result, tc.wantVal)
			}
		})
	}
}

func TestParseWindowsCPU_nullUnavailable(t *testing.T) {
	raw := map[string]interface{}{
		"__CLASS": "Win32_Processor",
		// LoadPercentage is nil/missing
	}
	output, _ := json.Marshal(raw)

	result, ok := ParseWindowsCPU(output)
	if !ok {
		t.Fatal("ParseWindowsCPU returned false for null LoadPercentage")
	}
	if result != nil {
		t.Errorf("expected nil pointer for unavailable CPU, got %v", result)
	}
}

func TestParseWindowsCPU_outOfBounds(t *testing.T) {
	tests := []int{-1, 101, -100, 999}
	for _, lp := range tests {
		raw := map[string]interface{}{
			"__CLASS":        "Win32_Processor",
			"LoadPercentage": float64(lp),
		}
		output, _ := json.Marshal(raw)

		_, ok := ParseWindowsCPU(output)
		if ok {
			t.Errorf("expected false for LoadPercentage=%d", lp)
		}
	}
}

func TestParseWindowsCPU_malformedJSON(t *testing.T) {
	for _, input := range []string{"", "not json", "{invalid}", "[1,2]"} {
		_, ok := ParseWindowsCPU([]byte(input))
		if ok {
			t.Fatalf("expected false for malformed JSON: %q", input)
		}
	}
}

func TestParseWindowsCPU_extraTokens(t *testing.T) {
	raw := map[string]interface{}{
		"__CLASS":        "Win32_Processor",
		"LoadPercentage": float64(50),
	}
	output, _ := json.Marshal(raw)
	output = append(output, []byte(` {"extra":"token"} `)...)

	_, ok := ParseWindowsCPU(output)
	if ok {
		t.Fatal("expected false for extra JSON tokens")
	}
}

// ---- Storage Parser Tests ----

func TestParseWindowsStorage_singleObject(t *testing.T) {
	raw := map[string]interface{}{
		"__CLASS":        "Win32_LogicalDisk",
		"DeviceID":       "C:",
		"Size":           float64(500 * 1024 * 1024 * 1024), // 500 GiB in bytes
		"FreeSpace":      float64(250 * 1024 * 1024 * 1024),
		"AvailableBytes": float64(250 * 1024 * 1024 * 1024),
	}
	output, _ := json.Marshal(raw)

	result, err := ParseWindowsStorage(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedTotal := uint64(500 * 1024 * 1024 * 1024)
	if result.TotalBytes != ByteAmount(expectedTotal) {
		t.Errorf("total = %d, want %d", result.TotalBytes, expectedTotal)
	}
	if result.UsedBytes != ByteAmount(250*1024*1024*1024) {
		t.Errorf("used = %d, want %d", result.UsedBytes, 250*1024*1024*1024)
	}
	if result.AvailableBytes != ByteAmount(250*1024*1024*1024) {
		t.Errorf("available = %d, want %d", result.AvailableBytes, 250*1024*1024*1024)
	}
}

func TestParseWindowsStorage_arrayObject(t *testing.T) {
	raw := []map[string]interface{}{
		{
			"__CLASS":        "Win32_LogicalDisk",
			"DeviceID":       "C:",
			"Size":           float64(1073741824), // 1 GiB
			"FreeSpace":      float64(536870912),  // 512 MiB
			"AvailableBytes": float64(536870912),
		},
	}
	output, _ := json.Marshal(raw)

	result, err := ParseWindowsStorage(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TotalBytes == 0 {
		t.Fatal("expected non-zero total")
	}
}

func TestParseWindowsStorage_missingFields(t *testing.T) {
	raw := map[string]interface{}{
		"__CLASS":  "Win32_LogicalDisk",
		"DeviceID": "C:",
		// Size, FreeSpace, AvailableBytes all missing
	}
	output, _ := json.Marshal(raw)

	_, err := ParseWindowsStorage(output)
	if err == nil {
		t.Fatal("expected error for missing fields")
	}
}

func TestParseWindowsStorage_freeGreaterThanTotal(t *testing.T) {
	raw := map[string]interface{}{
		"__CLASS":        "Win32_LogicalDisk",
		"DeviceID":       "C:",
		"Size":           float64(1024),
		"FreeSpace":      float64(2048), // free > total
		"AvailableBytes": float64(1024),
	}
	output, _ := json.Marshal(raw)

	_, err := ParseWindowsStorage(output)
	if err == nil {
		t.Fatal("expected error for free > total")
	}
}

func TestParseWindowsStorage_zeroSize(t *testing.T) {
	raw := map[string]interface{}{
		"__CLASS":        "Win32_LogicalDisk",
		"DeviceID":       "C:",
		"Size":           float64(0),
		"FreeSpace":      float64(0),
		"AvailableBytes": float64(0),
	}
	output, _ := json.Marshal(raw)

	_, err := ParseWindowsStorage(output)
	if err == nil {
		t.Fatal("expected error for zero size")
	}
}

func TestParseWindowsStorage_emptyArray(t *testing.T) {
	raw := []map[string]interface{}{}
	output, _ := json.Marshal(raw)

	_, err := ParseWindowsStorage(output)
	if err == nil {
		t.Fatal("expected error for empty array")
	}
}

// ---- GPU Parser Tests ----

func TestParseWindowsGPUs_NVIDIA(t *testing.T) {
	pnpID := "PCI\\VEN_10DE&DEV_1E30"
	name := "NVIDIA GeForce RTX 2080 Ti"
	raw := []map[string]interface{}{
		{
			"__CLASS":              "Win32_VideoController",
			"PNPDeviceID":          pnpID,
			"Name":                 name,
			"AdapterRAM":           float64(8589934592), // 8 GiB
			"AdapterCompatibility": "NVIDIA",
			"VideoProcessor":       "NVIDIA GeForce RTX 2080 Ti",
		},
	}
	output, _ := json.Marshal(raw)

	gpus, err := ParseWindowsGPUs(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gpus) != 1 {
		t.Fatalf("expected 1 GPU, got %d", len(gpus))
	}

	gpu := gpus[0]
	if gpu.Kind != AcceleratorNVIDIA {
		t.Errorf("kind = %s, want %s", gpu.Kind, AcceleratorNVIDIA)
	}
	if gpu.ID != "PCIVEN_10DEDEV_1E30" {
		t.Errorf("id = %s, want PCIVEN_10DEDEV_1E30 (sanitized)", gpu.ID)
	}
	if gpu.Name != name {
		t.Errorf("name = %s, want %s", gpu.Name, name)
	}
	if gpu.Memory.TotalBytes != ByteAmount(8589934592) {
		t.Errorf("total memory = %d, want 8589934592", gpu.Memory.TotalBytes)
	}
	if gpu.Memory.UsedBytes != 0 {
		t.Errorf("used memory = %d, want 0", gpu.Memory.UsedBytes)
	}
	if gpu.Memory.AvailableBytes != ByteAmount(8589934592) {
		t.Errorf("available memory = %d, want 8589934592", gpu.Memory.AvailableBytes)
	}
	if gpu.UtilizationPercent != nil {
		t.Error("expected nil utilization")
	}
}

func TestParseWindowsGPUs_AMD(t *testing.T) {
	raw := []map[string]interface{}{
		{
			"__CLASS":              "Win32_VideoController",
			"PNPDeviceID":          "PCI\\VEN_1002&DEV_67DF",
			"Name":                 "AMD Radeon RX 580",
			"AdapterRAM":           float64(4294967296), // 4 GiB
			"AdapterCompatibility": "Advanced Micro Devices, Inc.",
			"VideoProcessor":       "Radeon RX 580 Series",
		},
	}
	output, _ := json.Marshal(raw)

	gpus, err := ParseWindowsGPUs(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gpus) != 1 || gpus[0].Kind != AcceleratorAMD {
		t.Errorf("expected AMD kind")
	}
}

func TestParseWindowsGPUs_Intel(t *testing.T) {
	raw := []map[string]interface{}{
		{
			"__CLASS":              "Win32_VideoController",
			"PNPDeviceID":          "PCI\\VEN_8086&DEV_3E9B",
			"Name":                 "Intel UHD Graphics 630",
			"AdapterRAM":           float64(1073741824), // 1 GiB
			"AdapterCompatibility": "Intel Corporation",
			"VideoProcessor":       "Intel(R) UHD Graphics 630",
		},
	}
	output, _ := json.Marshal(raw)

	gpus, err := ParseWindowsGPUs(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gpus) != 1 || gpus[0].Kind != AcceleratorIntel {
		t.Errorf("expected Intel kind")
	}
}

func TestParseWindowsGPUs_other(t *testing.T) {
	raw := []map[string]interface{}{
		{
			"__CLASS":              "Win32_VideoController",
			"PNPDeviceID":          "PCI\\VEN_1AB&DEV_0890",
			"Name":                 "Parallels Display Adapter",
			"AdapterRAM":           float64(536870912), // 512 MiB
			"AdapterCompatibility": "Parallels",
			"VideoProcessor":       "Parallels Video Processor",
		},
	}
	output, _ := json.Marshal(raw)

	gpus, err := ParseWindowsGPUs(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gpus) != 1 || gpus[0].Kind != AcceleratorOther {
		t.Errorf("expected other kind")
	}
}

func TestParseWindowsGPUs_fallbackID(t *testing.T) {
	raw := []map[string]interface{}{
		{
			"__CLASS": "Win32_VideoController",
			// No PNPDeviceID → fallback to windows-gpu-0
			"Name":                 "Generic GPU",
			"AdapterRAM":           float64(1073741824),
			"AdapterCompatibility": "Unknown",
			"VideoProcessor":       "Generic Processor",
		},
	}
	output, _ := json.Marshal(raw)

	gpus, err := ParseWindowsGPUs(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gpus) != 1 || gpus[0].ID != "windows-gpu-0" {
		t.Errorf("expected fallback ID windows-gpu-0, got %s", gpus[0].ID)
	}
}

func TestParseWindowsGPUs_negativeAdapterRAM(t *testing.T) {
	raw := []map[string]interface{}{
		{
			"__CLASS":              "Win32_VideoController",
			"PNPDeviceID":          "PCI\\VEN_10DE&DEV_TEST",
			"Name":                 "GPU with negative RAM",
			"AdapterRAM":           float64(-1), // invalid
			"AdapterCompatibility": "NVIDIA",
			"VideoProcessor":       "Test GPU",
		},
	}
	output, _ := json.Marshal(raw)

	if _, err := ParseWindowsGPUs(output); err == nil {
		t.Fatal("expected negative AdapterRAM to be rejected")
	}
}

func TestParseWindowsGPUs_missingAdapterRAM(t *testing.T) {
	raw := []map[string]interface{}{
		{
			"__CLASS":     "Win32_VideoController",
			"PNPDeviceID": "PCI\\VEN_10DE&DEV_TEST",
			"Name":        "GPU without RAM field",
			// AdapterRAM missing
			"AdapterCompatibility": "NVIDIA",
			"VideoProcessor":       "Test GPU",
		},
	}
	output, _ := json.Marshal(raw)

	gpus, err := ParseWindowsGPUs(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gpus) != 1 || gpus[0].Memory.TotalBytes != 0 {
		t.Errorf("expected zero memory for missing AdapterRAM")
	}
}

func TestParseWindowsGPUs_emptyArray(t *testing.T) {
	raw := []map[string]interface{}{}
	output, _ := json.Marshal(raw)

	gpus, err := ParseWindowsGPUs(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gpus == nil {
		t.Fatal("expected non-nil empty slice")
	}
	if len(gpus) != 0 {
		t.Errorf("expected empty slice, got %d entries", len(gpus))
	}
}

func TestParseWindowsGPUs_nullOutput(t *testing.T) {
	gpus, err := ParseWindowsGPUs([]byte("null"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gpus == nil {
		t.Fatal("expected non-nil empty slice for null")
	}
	if len(gpus) != 0 {
		t.Errorf("expected empty slice, got %d entries", len(gpus))
	}
}

func TestParseWindowsGPUs_emptyOutput(t *testing.T) {
	gpus, err := ParseWindowsGPUs([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gpus == nil {
		t.Fatal("expected non-nil empty slice for empty")
	}
	if len(gpus) != 0 {
		t.Errorf("expected empty slice, got %d entries", len(gpus))
	}
}

func TestParseWindowsGPUs_duplicateIDs(t *testing.T) {
	raw := []map[string]interface{}{
		{
			"__CLASS":              "Win32_VideoController",
			"PNPDeviceID":          "PCI\\VEN_10DE&DEV_AAA",
			"Name":                 "GPU 1",
			"AdapterRAM":           float64(1073741824),
			"AdapterCompatibility": "NVIDIA",
			"VideoProcessor":       "Test GPU 1",
		},
		{
			"__CLASS":              "Win32_VideoController",
			"PNPDeviceID":          "PCI\\VEN_10DE&DEV_AAA", // duplicate
			"Name":                 "GPU 2",
			"AdapterRAM":           float64(1073741824),
			"AdapterCompatibility": "NVIDIA",
			"VideoProcessor":       "Test GPU 2",
		},
	}
	output, _ := json.Marshal(raw)

	_, err := ParseWindowsGPUs(output)
	if err == nil {
		t.Fatal("expected error for duplicate IDs")
	}
}

func TestParseWindowsGPUs_moreThan32(t *testing.T) {
	raw := make([]map[string]interface{}, 34)
	for i := range raw {
		pnpID := "PCI\\VEN_10DE&DEV_" + fmt.Sprintf("%02d", i)
		raw[i] = map[string]interface{}{
			"__CLASS":              "Win32_VideoController",
			"PNPDeviceID":          pnpID,
			"Name":                 "GPU " + string(rune(i)),
			"AdapterRAM":           float64(1073741824),
			"AdapterCompatibility": "NVIDIA",
			"VideoProcessor":       "Test GPU",
		}
	}
	output, _ := json.Marshal(raw)

	_, err := ParseWindowsGPUs(output)
	if err == nil {
		t.Fatal("expected error for >32 GPUs")
	}
}

func TestParseWindowsGPUs_safeName(t *testing.T) {
	raw := []map[string]interface{}{
		{
			"__CLASS":              "Win32_VideoController",
			"PNPDeviceID":          "PCI\\VEN_10DE&DEV_TEST",
			"Name":                 string([]byte{0x01, 0x02, 'A', 'B'}), // control chars
			"AdapterRAM":           float64(1073741824),
			"AdapterCompatibility": "NVIDIA",
			"VideoProcessor":       "Test GPU",
		},
	}
	output, _ := json.Marshal(raw)

	if _, err := ParseWindowsGPUs(output); err == nil {
		t.Fatal("expected control characters in GPU name to be rejected")
	}
}

func TestParseWindowsGPUs_malformedJSON(t *testing.T) {
	// Empty string is graceful absence (no GPUs), not malformed.
	if gpus, err := ParseWindowsGPUs([]byte("")); err != nil {
		t.Fatalf("expected no error for empty GPU output: %v", err)
	} else if len(gpus) != 0 || gpus == nil {
		t.Errorf("expected non-nil empty slice for empty GPU output, got %d entries", len(gpus))
	}

	for _, input := range []string{"not json", "{invalid}", "[1,2]"} {
		_, err := ParseWindowsGPUs([]byte(input))
		if err == nil {
			t.Fatalf("expected error for malformed JSON: %q", input)
		}
	}
}

func TestParseWindowsGPUs_singleObject(t *testing.T) {
	raw := map[string]interface{}{
		"__CLASS":              "Win32_VideoController",
		"PNPDeviceID":          "PCI\\VEN_10DE&DEV_SINGLE",
		"Name":                 "Single GPU",
		"AdapterRAM":           float64(536870912),
		"AdapterCompatibility": "NVIDIA",
		"VideoProcessor":       "Test GPU",
	}
	output, _ := json.Marshal(raw)

	gpus, err := ParseWindowsGPUs(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gpus) != 1 {
		t.Errorf("expected 1 GPU from single object, got %d", len(gpus))
	}
}

// ---- Copy Isolation Tests ----

func TestClone_GPUPointers(t *testing.T) {
	util := uint8(50)
	orig := HostResourceObservation{
		HostID:                "test-host",
		ObservedAt:            "2026-01-01T00:00:00.000Z",
		Platform:              PlatformWindows,
		CPULogicalCores:       8,
		CPUUtilizationPercent: &util,
		Memory:                ResourceQuantity{TotalBytes: 1024, UsedBytes: 512, AvailableBytes: 512},
		Storage:               ResourceQuantity{TotalBytes: 2048, UsedBytes: 1024, AvailableBytes: 1024},
		Accelerators: []AcceleratorObservation{
			{ID: "gpu-0", Name: "Test GPU", Kind: AcceleratorNVIDIA, Memory: ResourceQuantity{TotalBytes: 1073741824}},
		},
	}

	cloned := clone(orig)

	// Modify original and verify cloned is independent
	if orig.CPUUtilizationPercent != nil && cloned.CPUUtilizationPercent != nil {
		*orig.CPUUtilizationPercent = 99
		if *cloned.CPUUtilizationPercent == 99 {
			t.Error("CPU utilization pointer not isolated after clone")
		}
	}

	if len(orig.Accelerators) > 0 && len(cloned.Accelerators) > 0 {
		if orig.Accelerators[0].UtilizationPercent != nil {
			*orig.Accelerators[0].UtilizationPercent = 99
			if *cloned.Accelerators[0].UtilizationPercent == 99 {
				t.Error("GPU utilization pointer not isolated after clone")
			}
		}

		// Verify slice is independent (different backing array)
		cloned.Accelerators = append(cloned.Accelerators, AcceleratorObservation{ID: "gpu-1"})
		if len(orig.Accelerators) != 1 {
			t.Error("GPU accelerators slice not isolated after clone")
		}
	}

	// Verify memory values are independent (they're uint64 so value copy is fine, but check struct field independence)
	cloned.Memory.TotalBytes = 9999
	if orig.Memory.TotalBytes == ByteAmount(9999) {
		t.Error("Memory TotalBytes not isolated after clone")
	}
}

// ---- Output Cap / Redaction Tests (via parser functions) ----

func TestParseWindowsMemory_outputCap(t *testing.T) {
	// Create output that exceeds maxCommandOutput — should be caught by the size check in ParseWindowsMemory
	large := make([]byte, maxCommandOutput+1)
	for i := range large {
		large[i] = 'x'
	}

	_, err := ParseWindowsMemory(large)
	if err == nil {
		t.Fatal("expected error for oversized input")
	}
}

func TestParseWindowsCPU_outputCap(t *testing.T) {
	large := make([]byte, maxCommandOutput+1)
	_, ok := ParseWindowsCPU(large)
	if ok {
		t.Fatal("expected false for oversized CPU input")
	}
}

func TestParseWindowsStorage_outputCap(t *testing.T) {
	large := make([]byte, maxCommandOutput+1)
	_, err := ParseWindowsStorage(large)
	if err == nil {
		t.Fatal("expected error for oversized storage input")
	}
}

func TestParseWindowsGPUs_outputCap(t *testing.T) {
	large := make([]byte, maxCommandOutput+1)
	_, err := ParseWindowsGPUs(large)
	if err == nil {
		t.Fatal("expected error for oversized GPU input")
	}
}

// ---- extractDriveLetter Tests ----

func TestExtractDriveLetter(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"C:\\Windows", "C"},
		{"D:\\Data\\files", "D"},
		{"c:\\lowercase", "C"}, // should uppercase
		{"Z:", ""},
		{":\\noletter", ""},
		{"", ""},
		{"a", ""},
		{"//network/share", ""},
	}

	for _, tc := range tests {
		result := extractDriveLetter(tc.input)
		if result != tc.expected {
			t.Errorf("extractDriveLetter(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}
