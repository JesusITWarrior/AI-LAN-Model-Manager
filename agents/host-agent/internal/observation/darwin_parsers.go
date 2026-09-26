package observation

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
)

var (
	ErrDarwinConfig  = errors.New("invalid darwin observer configuration")
	ErrDarwinCPU     = errors.New("darwin cpu probe failed")
	ErrDarwinMemory  = errors.New("darwin memory probe failed")
	ErrDarwinStorage = errors.New("darwin storage probe failed")
	ErrDarwinGPU     = errors.New("darwin gpu probe failed")
)

var cpuUsageLine = regexp.MustCompile(`^CPU usage:\s*([0-9]+(?:\.[0-9]+)?)% user,\s*([0-9]+(?:\.[0-9]+)?)% sys,\s*([0-9]+(?:\.[0-9]+)?)% idle\s*$`)

// parseDarwinCPU parses only the final top sample. top's percentages are rounded,
// so a small discrepancy from 100 is accepted. CPU observation is best effort.
func parseDarwinCPU(output []byte) (*uint8, bool) {
	if len(output) > maxCommandOutput {
		return nil, false
	}
	var match []string
	for _, line := range strings.Split(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "CPU usage:") {
			// A malformed later sample invalidates an earlier valid one: only the
			// final CPU usage sample represents top's settled measurement.
			match = cpuUsageLine.FindStringSubmatch(line)
		}
	}
	if match == nil {
		return nil, false
	}
	values := make([]float64, 3)
	for i := range values {
		value, err := strconv.ParseFloat(match[i+1], 64)
		if err != nil || value < 0 || value > 100 || math.IsInf(value, 0) || math.IsNaN(value) {
			return nil, false
		}
		values[i] = value
	}
	if math.Abs(values[0]+values[1]+values[2]-100) > 0.2 {
		return nil, false
	}
	used := math.Round(values[0] + values[1])
	if used < 0 || used > 100 {
		return nil, false
	}
	result := uint8(used)
	return &result, true
}

var vmPageSizeLine = regexp.MustCompile(`^Mach Virtual Memory Statistics: \(page size of ([0-9]+) bytes\)$`)

func parseDarwinMemory(totalOutput, vmOutput []byte) (ResourceQuantity, error) {
	if len(totalOutput) > maxCommandOutput || len(vmOutput) > maxCommandOutput {
		return ResourceQuantity{}, errors.Join(ErrDarwinMemory, ErrAcceleratorOutput)
	}
	totalText := strings.TrimSpace(string(totalOutput))
	if totalText == "" || strings.ContainsAny(totalText, " \t\r\n+-") {
		return ResourceQuantity{}, ErrDarwinMemory
	}
	total, err := strconv.ParseUint(totalText, 10, 64)
	if err != nil || total == 0 {
		return ResourceQuantity{}, ErrDarwinMemory
	}
	var pageSize uint64
	counts := map[string]uint64{}
	seen := map[string]bool{}
	for _, raw := range strings.Split(strings.ReplaceAll(string(vmOutput), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if match := vmPageSizeLine.FindStringSubmatch(line); match != nil {
			if pageSize != 0 {
				return ResourceQuantity{}, ErrDarwinMemory
			}
			pageSize, err = strconv.ParseUint(match[1], 10, 64)
			if err != nil || pageSize == 0 {
				return ResourceQuantity{}, ErrDarwinMemory
			}
			continue
		}
		for _, key := range []string{"Pages free", "Pages inactive", "Pages speculative"} {
			prefix := key + ":"
			if !strings.HasPrefix(line, prefix) {
				continue
			}
			if seen[key] || !strings.HasSuffix(line, ".") {
				return ResourceQuantity{}, ErrDarwinMemory
			}
			text := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, prefix), "."))
			if text == "" || strings.ContainsAny(text, " \t+-") {
				return ResourceQuantity{}, ErrDarwinMemory
			}
			value, parseErr := strconv.ParseUint(text, 10, 64)
			if parseErr != nil {
				return ResourceQuantity{}, ErrDarwinMemory
			}
			counts[key], seen[key] = value, true
		}
	}
	if pageSize == 0 || !seen["Pages free"] || !seen["Pages inactive"] || !seen["Pages speculative"] {
		return ResourceQuantity{}, ErrDarwinMemory
	}
	pages, overflow := add3(counts["Pages free"], counts["Pages inactive"], counts["Pages speculative"])
	if overflow {
		return ResourceQuantity{}, ErrDarwinMemory
	}
	available, overflow := multiply(pages, pageSize)
	if overflow || available > total {
		return ResourceQuantity{}, ErrDarwinMemory
	}
	result := ResourceQuantity{TotalBytes: ByteAmount(total), UsedBytes: ByteAmount(total - available), AvailableBytes: ByteAmount(available)}
	if result.Validate() != nil {
		return ResourceQuantity{}, ErrDarwinMemory
	}
	return result, nil
}

type darwinGPUItem map[string]json.RawMessage

type darwinGPUEnvelope struct {
	Items    json.RawMessage `json:"_items"`
	Displays json.RawMessage `json:"SPDisplaysDataType"`
}

func parseDarwinGPUs(output []byte) ([]AcceleratorObservation, error) {
	if len(output) > maxCommandOutput {
		return nil, errors.Join(ErrDarwinGPU, ErrAcceleratorOutput)
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	var envelope darwinGPUEnvelope
	if err := decoder.Decode(&envelope); err != nil || ensureJSONEnd(decoder) != nil {
		return nil, ErrDarwinGPU
	}
	raw := envelope.Items
	if len(raw) == 0 {
		raw = envelope.Displays
	}
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return make([]AcceleratorObservation, 0), nil
	}
	items, err := decodeDarwinGPUItems(raw)
	if err != nil {
		return nil, ErrDarwinGPU
	}
	result := make([]AcceleratorObservation, 0, len(items))
	seen := make(map[string]struct{})
	for index, item := range items {
		// system_profiler nests connected displays under a GPU's `_items`.
		// The parent contains the chipset/vendor identity and must not be skipped.
		value, apple, parseErr := darwinGPUFromItem(item, index)
		if parseErr != nil {
			return nil, parseErr
		}
		if apple {
			result = append(result, value)
		}
	}
	if len(result) > 32 {
		return nil, ErrDarwinGPU
	}
	for _, value := range result {
		if _, exists := seen[value.ID]; exists {
			return nil, ErrDuplicateID
		}
		seen[value.ID] = struct{}{}
	}
	return result, nil
}

func decodeDarwinGPUItems(raw json.RawMessage) ([]darwinGPUItem, error) {
	var items []darwinGPUItem
	if json.Unmarshal(raw, &items) == nil {
		return items, nil
	}
	var envelope struct {
		Items []darwinGPUItem `json:"_items"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil || envelope.Items == nil {
		return nil, ErrDarwinGPU
	}
	return envelope.Items, nil
}

func darwinGPUFromItem(item darwinGPUItem, index int) (AcceleratorObservation, bool, error) {
	name := firstJSONString(item, "name", "sppci_model", "spdisplays_chipset-model", "_name")
	vendor := strings.ToLower(firstJSONString(item, "vendor", "spdisplays_vendor", "sppci_vendor"))
	apple := strings.Contains(vendor, "apple") || strings.HasPrefix(strings.ToLower(name), "apple ")
	if !apple {
		return AcceleratorObservation{}, false, nil
	}
	if !validName(name) {
		return AcceleratorObservation{}, false, ErrDarwinGPU
	}
	id := firstJSONString(item, "id", "_id", "spdisplays_device-id")
	if id == "" {
		id = "apple-" + strconv.Itoa(index)
	}
	if !validID(id) {
		return AcceleratorObservation{}, false, ErrDarwinGPU
	}
	value := AcceleratorObservation{ID: id, Name: name, Kind: AcceleratorApple, Memory: ResourceQuantity{}, UtilizationPercent: nil}
	if value.Validate() != nil {
		return AcceleratorObservation{}, false, ErrDarwinGPU
	}
	return value, true, nil
}

func firstJSONString(item darwinGPUItem, keys ...string) string {
	for _, key := range keys {
		raw, ok := item[key]
		if !ok {
			continue
		}
		var value string
		if json.Unmarshal(raw, &value) == nil {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
