package observation

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	ErrWindowsMemoryParse  = errors.New("windows memory parse failed")
	ErrWindowsCPUError     = errors.New("windows cpu parse failed")
	ErrWindowsStorageParse = errors.New("windows storage parse failed")
	ErrWindowsGPUParse     = errors.New("windows gpu parse failed")
)

type winMemoryItem struct {
	TotalVisibleMemorySize *uint64 `json:"TotalVisibleMemorySize"`
	FreePhysicalMemory     *uint64 `json:"FreePhysicalMemory"`
}

type winCPUItem struct {
	LoadPercentage *int `json:"LoadPercentage"`
}

type winStorageItem struct {
	Size      *uint64 `json:"Size"`
	FreeSpace *uint64 `json:"FreeSpace"`
}

type winGPUItem struct {
	PNPDeviceID          *string `json:"PNPDeviceID"`
	Name                 *string `json:"Name"`
	AdapterRAM           *int64  `json:"AdapterRAM"`
	AdapterCompatibility *string `json:"AdapterCompatibility"`
	VideoProcessor       *string `json:"VideoProcessor"`
}

// validWindowsStoragePath performs Windows lexical validation on every host.
// Only clean, drive-rooted paths are supported because Win32_LogicalDisk can be
// queried safely by drive identifier. UNC paths are deliberately unsupported.
func validWindowsStoragePath(path string) bool {
	if len(path) < 3 || path[1] != ':' || path[2] != '\\' || !asciiLetter(path[0]) {
		return false
	}
	if strings.Contains(path, "/") || strings.HasPrefix(path, `\\`) {
		return false
	}
	if len(path) == 3 {
		return true
	}
	if path[len(path)-1] == '\\' {
		return false
	}
	for _, part := range strings.Split(path[3:], `\`) {
		if !validWindowsPathComponent(part) {
			return false
		}
	}
	return true
}

func asciiLetter(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func validWindowsPathComponent(part string) bool {
	if part == "" || part == "." || part == ".." || strings.HasSuffix(part, " ") || strings.HasSuffix(part, ".") {
		return false
	}
	for _, r := range part {
		if r < 0x20 || strings.ContainsRune(`<>:"/\\|?*`, r) {
			return false
		}
	}
	return true
}

func windowsDriveIdentifier(path string) (string, bool) {
	if !validWindowsStoragePath(path) {
		return "", false
	}
	return strings.ToUpper(path[:1]) + ":", true
}

func extractDriveLetter(path string) string {
	drive, ok := windowsDriveIdentifier(path)
	if !ok {
		return ""
	}
	return drive[:1]
}

func ParseWindowsMemory(output []byte) (ResourceQuantity, error) {
	if len(output) > maxCommandOutput {
		return ResourceQuantity{}, errors.Join(ErrWindowsMemoryParse, ErrAcceleratorOutput)
	}
	var item winMemoryItem
	if err := decodeSingleJSON(output, &item); err != nil || item.TotalVisibleMemorySize == nil || item.FreePhysicalMemory == nil {
		return ResourceQuantity{}, ErrWindowsMemoryParse
	}
	totalKiB, freeKiB := *item.TotalVisibleMemorySize, *item.FreePhysicalMemory
	if totalKiB == 0 || totalKiB > math.MaxUint64/1024 || freeKiB > math.MaxUint64/1024 || freeKiB > totalKiB {
		return ResourceQuantity{}, ErrWindowsMemoryParse
	}
	total, free := totalKiB*1024, freeKiB*1024
	return checkedQuantity(total, free, ErrWindowsMemoryParse)
}

func ParseWindowsCPU(output []byte) (*uint8, bool) {
	if len(output) > maxCommandOutput {
		return nil, false
	}
	var item winCPUItem
	if err := decodeSingleJSON(output, &item); err != nil {
		return nil, false
	}
	if item.LoadPercentage == nil {
		return nil, true
	}
	if *item.LoadPercentage < 0 || *item.LoadPercentage > 100 {
		return nil, false
	}
	value := uint8(*item.LoadPercentage)
	return &value, true
}

func ParseWindowsStorage(output []byte) (ResourceQuantity, error) {
	if len(output) > maxCommandOutput {
		return ResourceQuantity{}, errors.Join(ErrWindowsStorageParse, ErrAcceleratorOutput)
	}
	var items []winStorageItem
	if err := decodeScalarOrArray(output, &items); err != nil || len(items) != 1 {
		return ResourceQuantity{}, ErrWindowsStorageParse
	}
	item := items[0]
	if item.Size == nil || item.FreeSpace == nil || *item.Size == 0 || *item.FreeSpace > *item.Size {
		return ResourceQuantity{}, ErrWindowsStorageParse
	}
	return checkedQuantity(*item.Size, *item.FreeSpace, ErrWindowsStorageParse)
}

func ParseWindowsGPUs(output []byte) ([]AcceleratorObservation, error) {
	if len(output) > maxCommandOutput {
		return nil, errors.Join(ErrWindowsGPUParse, ErrAcceleratorOutput)
	}
	trimmed := bytes.TrimSpace(output)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return []AcceleratorObservation{}, nil
	}
	var items []winGPUItem
	if err := decodeScalarOrArray(trimmed, &items); err != nil || len(items) > 32 {
		return nil, ErrWindowsGPUParse
	}
	result := make([]AcceleratorObservation, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for index, item := range items {
		value, err := windowsGPU(item, index)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[value.ID]; duplicate {
			return nil, errors.Join(ErrWindowsGPUParse, ErrDuplicateID)
		}
		seen[value.ID] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}

func windowsGPU(item winGPUItem, index int) (AcceleratorObservation, error) {
	if item.AdapterRAM != nil && *item.AdapterRAM < 0 {
		return AcceleratorObservation{}, ErrWindowsGPUParse
	}
	id := "windows-gpu-" + strconv.Itoa(index)
	if item.PNPDeviceID != nil && *item.PNPDeviceID != "" {
		if !utf8.ValidString(*item.PNPDeviceID) {
			return AcceleratorObservation{}, ErrWindowsGPUParse
		}
		if candidate := sanitizePNPDeviceID(*item.PNPDeviceID); validID(candidate) {
			id = candidate
		}
	}
	name, ok := safeGPUName(item.Name)
	if !ok {
		return AcceleratorObservation{}, ErrWindowsGPUParse
	}
	memory := ResourceQuantity{}
	if item.AdapterRAM != nil {
		memory.TotalBytes = ByteAmount(*item.AdapterRAM)
		memory.AvailableBytes = memory.TotalBytes
	}
	value := AcceleratorObservation{ID: id, Name: name, Kind: classifyGPUKind(item), Memory: memory}
	if err := value.Validate(); err != nil {
		return AcceleratorObservation{}, errors.Join(ErrWindowsGPUParse, err)
	}
	return value, nil
}

func sanitizePNPDeviceID(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("._:-", r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func safeGPUName(raw *string) (string, bool) {
	if raw == nil || strings.TrimSpace(*raw) == "" {
		return "unknown", true
	}
	name := strings.TrimSpace(*raw)
	if !utf8.ValidString(name) || !validName(name) {
		return "", false
	}
	return name, true
}

func classifyGPUKind(item winGPUItem) AcceleratorKind {
	values := []*string{item.AdapterCompatibility, item.VideoProcessor, item.PNPDeviceID}
	var text strings.Builder
	for _, value := range values {
		if value != nil {
			text.WriteByte(' ')
			text.WriteString(strings.ToLower(*value))
		}
	}
	joined := text.String()
	switch {
	case strings.Contains(joined, "nvidia"), strings.Contains(joined, `ven_10de`):
		return AcceleratorNVIDIA
	case strings.Contains(joined, "advanced micro devices"), strings.Contains(joined, "amd"), strings.Contains(joined, "ati technologies"), strings.Contains(joined, `ven_1002`):
		return AcceleratorAMD
	case strings.Contains(joined, "intel"), strings.Contains(joined, `ven_8086`):
		return AcceleratorIntel
	default:
		return AcceleratorOther
	}
}

func checkedQuantity(total, available uint64, class error) (ResourceQuantity, error) {
	value := ResourceQuantity{TotalBytes: ByteAmount(total), UsedBytes: ByteAmount(total - available), AvailableBytes: ByteAmount(available)}
	if err := value.Validate(); err != nil {
		return ResourceQuantity{}, errors.Join(class, err)
	}
	return value, nil
}

func decodeSingleJSON(output []byte, destination any) error {
	if len(bytes.TrimSpace(output)) == 0 {
		return io.ErrUnexpectedEOF
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return ensureJSONEnd(decoder)
}

func decodeScalarOrArray(output []byte, destination any) error {
	trimmed := bytes.TrimSpace(output)
	if len(trimmed) == 0 {
		return io.ErrUnexpectedEOF
	}
	if trimmed[0] == '[' {
		return decodeSingleJSON(trimmed, destination)
	}
	// Decode through RawMessage so the caller's concrete []T type remains known.
	var raw json.RawMessage
	if err := decodeSingleJSON(trimmed, &raw); err != nil {
		return err
	}
	array := append([]byte{'['}, raw...)
	array = append(array, ']')
	return decodeSingleJSON(array, destination)
}
