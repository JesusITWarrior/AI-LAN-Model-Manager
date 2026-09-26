package observation

import (
	"encoding/json"
	"fmt"
	"math"
	"testing"
)

// ---- validWindowsStoragePath tests (platform-independent) ----

func TestValidWindowsStoragePath(t *testing.T) {
	cases := []struct {
		name  string
		path  string
		valid bool
	}{
		{"drive root no slash", "", false},
		{"drive root c only", "C", false},
		{"drive root c colon", "C:", false},
		{"drive root backslash", "C:\\", true},
		{"drive root forward slash", "C:/", false},
		{"drive root deep", "C:\\Program Files\\Common Files", true},
		{"drive root lowercase", "c:\\data", true},
		{"drive root trailing backslash clean", "C:\\data\\", false}, // not clean
		{"drive relative", "C:data", false},
		{"drive leading spaces unclean", "C:\\x ..\\y", false},
		{"unc server share", `\\server\share`, false},
		{"unc server share trailing", `\\server\share\`, false}, // not clean
		{"unc no share", `\\server`, false},
		{"unc three slashes", `\\\\server\share`, false},
		{"unc with url slash", `\\server\share\deep`, false},
		{"abs non-drive", `\data`, false},
		{"drive letter with number", "3:\\x", false},
		{"drive colon uppercase", "Z:\\", true},
		{"mixed case drive cleaned", "c:\\DATA", true}, // Clean preserves case; case-folding is platform-specific
	}
	for _, tc := range cases {
		if got := validWindowsStoragePath(tc.path); got != tc.valid {
			t.Errorf("%s: validWindowsStoragePath(%q) = %v, want %v", tc.name, tc.path, got, tc.valid)
		}
	}
}

func TestValidWindowsStoragePathRejectsRelativeAndUNC(t *testing.T) {
	for _, path := range []string{"data\\folder", "C:relative", `\\server\share`, `\\server\share\subdir`, `C:\x\..\y`, `C:\x\.\y`, `C:\\x`, `C:\x\`} {
		if validWindowsStoragePath(path) {
			t.Errorf("unsafe or unclean path must be rejected: %q", path)
		}
	}
}

// ---- ParseWindowsStorage tests (real shape: Size/FreeSpace) ----

func TestParseWindowsStorage_realShape(t *testing.T) {
	// Size and FreeSpace are expressed in bytes directly (Win32_LogicalDisk).
	raw := map[string]interface{}{
		"__CLASS":   "Win32_LogicalDisk",
		"DeviceID":  "C:",
		"Size":      float64(1000 * 1024 * 1024 * 1024), // 1000 GiB
		"FreeSpace": float64(250 * 1024 * 1024 * 1024),  // 250 GiB free
	}
	output, _ := json.Marshal(raw)

	result, err := ParseWindowsStorage(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	const oneThousandGiB = uint64(1000 * 1024 * 1024 * 1024)
	const twoFiftyGiB = uint64(250 * 1024 * 1024 * 1024)
	if result.TotalBytes != ByteAmount(oneThousandGiB) {
		t.Errorf("total = %d, want %d", result.TotalBytes, oneThousandGiB)
	}
	if result.UsedBytes != ByteAmount(oneThousandGiB-twoFiftyGiB) {
		t.Errorf("used = %d, want %d", result.UsedBytes, oneThousandGiB-twoFiftyGiB)
	}
	if result.AvailableBytes != ByteAmount(twoFiftyGiB) {
		t.Errorf("available = %d, want %d", result.AvailableBytes, twoFiftyGiB)
	}
}

func TestParseWindowsStorage_availableBytesIgnored(t *testing.T) {
	// Modern PowerShell output includes AvailableBytes. It must be ignored; the
	// free figure always comes from FreeSpace.
	raw := map[string]interface{}{
		"__CLASS":        "Win32_LogicalDisk",
		"DeviceID":       "D:",
		"Size":           float64(1000),
		"FreeSpace":      float64(400),
		"AvailableBytes": float64(999), // should be ignored
	}
	output, _ := json.Marshal(raw)

	result, err := ParseWindowsStorage(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TotalBytes != ByteAmount(1000) || result.UsedBytes != ByteAmount(600) || result.AvailableBytes != ByteAmount(400) {
		t.Fatalf("storage = %#v, want total 1000 used 600 available 400", result)
	}
}

func TestParseWindowsStorage_singleAndArray(t *testing.T) {
	// Single object.
	single := map[string]interface{}{
		"__CLASS":   "Win32_LogicalDisk",
		"DeviceID":  "C:",
		"Size":      float64(1073741824), // 1 GiB
		"FreeSpace": float64(536870912),  // 512 MiB
	}
	out1, _ := json.Marshal(single)
	one, err := ParseWindowsStorage(out1)
	if err != nil || one.TotalBytes != ByteAmount(1073741824) || one.AvailableBytes != ByteAmount(536870912) {
		t.Fatalf("single object: %#v %v", one, err)
	}

	// Array form.
	arr := []map[string]interface{}{
		{
			"__CLASS":   "Win32_LogicalDisk",
			"DeviceID":  "C:",
			"Size":      float64(2147483648), // 2 GiB
			"FreeSpace": float64(2147483648), // 2 GiB
		},
	}
	out2, _ := json.Marshal(arr)
	two, err := ParseWindowsStorage(out2)
	if err != nil || two.TotalBytes != ByteAmount(2147483648) {
		t.Fatalf("array form: %#v %v", two, err)
	}
}

func TestParseWindowsStorage_errors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input map[string]interface{}
	}{
		{"missing size", map[string]interface{}{"__CLASS": "Win32_LogicalDisk", "DeviceID": "C:", "FreeSpace": float64(1)}},
		{"missing free", map[string]interface{}{"__CLASS": "Win32_LogicalDisk", "DeviceID": "C:", "Size": float64(1)}},
		{"zero size", map[string]interface{}{"__CLASS": "Win32_LogicalDisk", "DeviceID": "C:", "Size": float64(0), "FreeSpace": float64(0)}},
		{"free greater than total", map[string]interface{}{"__CLASS": "Win32_LogicalDisk", "DeviceID": "C:", "Size": float64(10), "FreeSpace": float64(20)}},
		{"negative size (JSON)", nil},
	} {
		if tc.input == nil {
			// Negative Size overflows uint64 on JSON unmarshal.
			raw := map[string]interface{}{
				"__CLASS":   "Win32_LogicalDisk",
				"DeviceID":  "C:",
				"Size":      float64(-1),
				"FreeSpace": float64(5),
			}
			out, _ := json.Marshal(raw)
			if _, err := ParseWindowsStorage(out); err == nil {
				t.Errorf("%s: expected error", tc.name)
			}
			continue
		}
		out, _ := json.Marshal(tc.input)
		if _, err := ParseWindowsStorage(out); err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
}

func TestParseWindowsStorage_malformedJSON(t *testing.T) {
	for _, input := range []string{"", "not json", "{invalid}", "[1,2,3]"} {
		if _, err := ParseWindowsStorage([]byte(input)); err == nil {
			t.Fatalf("expected error for malformed JSON: %q", input)
		}
	}
}

// Existing windows_test.go already covers empty-array and oversized-input
// behavior; that coverage is retained there.
func TestParseWindowsStorage_overflow(t *testing.T) {
	// Size just below overflow; FreeSpace slightly larger but valid within total.
	raw := map[string]interface{}{
		"__CLASS":   "Win32_LogicalDisk",
		"DeviceID":  "C:",
		"Size":      float64(math.MaxUint64 / 4),
		"FreeSpace": float64(math.MaxUint64 / 4 / 2),
	}
	out, _ := json.Marshal(raw)
	if _, err := ParseWindowsStorage(out); err != nil {
		t.Fatalf("expected no error for within-overflow values: %v", err)
	}
}

// ---- ParseWindowsGPUs edge cases ----

func TestParseWindowsGPUs_noPNPIDFallback(t *testing.T) {
	raw := []map[string]interface{}{
		{
			"__CLASS":    "Win32_VideoController",
			"Name":       "Fallback Name",
			"AdapterRAM": float64(1073741824),
		},
	}
	out, _ := json.Marshal(raw)
	gpus, err := ParseWindowsGPUs(out)
	if err != nil || len(gpus) != 1 || gpus[0].ID != "windows-gpu-0" {
		t.Fatalf("expected fallback ID windows-gpu-0, got %d %v", len(gpus), err)
	}
}

func TestParseWindowsGPUs_noPNPIDInvalidName(t *testing.T) {
	// No PNPDeviceID and an empty Name -> fallback ID windows-gpu-0, and the
	// empty Name is normalized to the valid unknown, so exactly one entry is
	// produced (graceful, not skipped).
	raw := []map[string]interface{}{
		{"__CLASS": "Win32_VideoController", "Name": ""},
	}
	out, _ := json.Marshal(raw)
	gpus, err := ParseWindowsGPUs(out)
	if err != nil || len(gpus) != 1 {
		t.Fatalf("expected 1 normalized entry, got %d %v", len(gpus), err)
	}
	if gpus[0].ID != "windows-gpu-0" || gpus[0].Name != "unknown" {
		t.Fatalf("unexpected entry: id=%q name=%q", gpus[0].ID, gpus[0].Name)
	}
}

func TestParseWindowsGPUs_negativeAdapterRAMRejected(t *testing.T) {
	raw := []map[string]interface{}{
		{
			"__CLASS":              "Win32_VideoController",
			"PNPDeviceID":          "PCI\\VEN_10DE&DEV_TEST",
			"Name":                 "Negative",
			"AdapterRAM":           float64(-8), // treated as unknown
			"AdapterCompatibility": "NVIDIA",
		},
	}
	out, _ := json.Marshal(raw)
	if _, err := ParseWindowsGPUs(out); err == nil {
		t.Fatal("expected negative AdapterRAM to be rejected")
	}
}

func TestParseWindowsGPUs_emptyAndNull(t *testing.T) {
	if gpus, err := ParseWindowsGPUs([]byte("")); err != nil || gpus == nil || len(gpus) != 0 {
		t.Fatalf("empty: %v %d", err, len(gpus))
	}
	if gpus, err := ParseWindowsGPUs([]byte("null")); err != nil || gpus == nil || len(gpus) != 0 {
		t.Fatalf("null: %v %d", err, len(gpus))
	}
}

func TestParseWindowsGPUs_dedupAndMax32(t *testing.T) {
	// Duplicate IDs must error.
	raw := []map[string]interface{}{
		{"__CLASS": "Win32_VideoController", "PNPDeviceID": "PCI\\VEN_10DE&DEV_A", "Name": "A", "AdapterRAM": float64(1073741824)},
		{"__CLASS": "Win32_VideoController", "PNPDeviceID": "PCI\\VEN_10DE&DEV_A", "Name": "B", "AdapterRAM": float64(1073741824)},
	}
	out, _ := json.Marshal(raw)
	if _, err := ParseWindowsGPUs(out); err == nil {
		t.Error("expected duplicate ID error")
	}

	// Exactly 32 valid distinct GPUs is allowed; 33 is rejected.
	exact := make([]map[string]interface{}, 32)
	for i := range exact {
		exact[i] = map[string]interface{}{
			"__CLASS":              "Win32_VideoController",
			"PNPDeviceID":          "PCI\\VEN_10DE&DEV_" + fmt.Sprintf("%02d", i),
			"Name":                 fmt.Sprintf("GPU-%02d", i),
			"AdapterRAM":           float64(1073741824),
			"AdapterCompatibility": "NVIDIA",
		}
	}
	o32, _ := json.Marshal(exact)
	if _, err := ParseWindowsGPUs(o32); err != nil {
		t.Errorf("expected 32 GPUs to be accepted, got %v", err)
	}

	many := make([]map[string]interface{}, 33)
	for i := range many {
		many[i] = map[string]interface{}{
			"__CLASS":              "Win32_VideoController",
			"PNPDeviceID":          "PCI\\VEN_10DE&DEV_" + fmt.Sprintf("%02d", i),
			"Name":                 fmt.Sprintf("GPU-%02d", i),
			"AdapterRAM":           float64(1073741824),
			"AdapterCompatibility": "NVIDIA",
		}
	}
	o33, _ := json.Marshal(many)
	if _, err := ParseWindowsGPUs(o33); err == nil {
		t.Error("expected error for >32 GPUs")
	}
}

func TestParseWindowsGPUs_kindClassification(t *testing.T) {
	cases := []struct {
		name      string
		compat    string
		processor string
		vendor    string
		pnpID     string
		wantKind  string
	}{
		{"nvidia", "NVIDIA", "NVIDIA GeForce", "NVIDIA Inc.", "PCI\\VEN_10DE&DEV_1E30", string(AcceleratorNVIDIA)},
		{"amd", "Advanced Micro Devices, Inc.", "Radeon RX", "Advanced Micro Devices", "PCI\\VEN_1002&DEV_67DF", string(AcceleratorAMD)},
		{"intel", "Intel Corporation", "Intel UHD", "Intel Corporation", "PCI\\VEN_8086&DEV_3E9B", string(AcceleratorIntel)},
		{"other", "Parallels", "Parallels", "Parallels", "PCI\\VEN_1AB&DEV_0890", string(AcceleratorOther)},
	}
	for _, tc := range cases {
		raw := []map[string]interface{}{{
			"__CLASS":              "Win32_VideoController",
			"PNPDeviceID":          tc.pnpID,
			"Name":                 tc.name,
			"AdapterRAM":           float64(1073741824),
			"AdapterCompatibility": tc.compat,
			"VideoProcessor":       tc.processor,
		}}
		out, _ := json.Marshal(raw)
		gpus, err := ParseWindowsGPUs(out)
		if err != nil || len(gpus) != 1 || string(gpus[0].Kind) != tc.wantKind {
			t.Errorf("%s: kind = %v, want %s (%v)", tc.name, gpus, tc.wantKind, err)
		}
	}
}
