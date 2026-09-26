//go:build linux

package observation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type AMDObserver struct {
	path      string
	runner    CommandRunner
	available bool
}

func NewAMDObserver() (*AMDObserver, error) {
	path, err := exec.LookPath("rocm-smi")
	if errors.Is(err, exec.ErrNotFound) {
		return &AMDObserver{runner: execRunner{}}, nil
	}
	if err != nil {
		return nil, ErrAcceleratorProbe
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, ErrAcceleratorProbe
	}
	return &AMDObserver{path: absolute, runner: execRunner{}, available: true}, nil
}
func NewAMDObserverWithRunner(runner CommandRunner) (*AMDObserver, error) {
	if runner == nil {
		return nil, ErrAcceleratorProbe
	}
	return &AMDObserver{path: "/usr/bin/rocm-smi", runner: runner, available: true}, nil
}

var amdArgs = []string{"--showuniqueid", "--showproductname", "--showmeminfo", "vram", "--showuse", "--json"}

func (o *AMDObserver) ObserveAccelerators(ctx context.Context) ([]AcceleratorObservation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !o.available {
		return make([]AcceleratorObservation, 0), nil
	}
	output, err := o.runner.Run(ctx, o.path, append([]string(nil), amdArgs...))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if errors.Is(err, ErrAcceleratorOutput) {
			return nil, ErrAcceleratorOutput
		}
		if noAMDDevices(output) {
			return make([]AcceleratorObservation, 0), nil
		}
		return nil, ErrAcceleratorProbe
	}
	if len(output) > maxCommandOutput {
		return nil, ErrAcceleratorOutput
	}
	if len(bytes.TrimSpace(output)) == 0 || noAMDDevices(output) {
		return make([]AcceleratorObservation, 0), nil
	}
	return parseAMDJSON(output)
}
func noAMDDevices(output []byte) bool {
	text := strings.ToLower(string(bytes.TrimSpace(output)))
	return strings.Contains(text, "no supported adapters") || strings.Contains(text, "no devices found") || strings.Contains(text, "no amd gpus")
}

type amdObject map[string]json.RawMessage

func parseAMDJSON(output []byte) ([]AcceleratorObservation, error) {
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.UseNumber()
	var root amdObject
	if err := decoder.Decode(&root); err != nil {
		return nil, ErrAcceleratorProbe
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return nil, ErrAcceleratorProbe
	}
	if len(root) == 0 {
		return make([]AcceleratorObservation, 0), nil
	}
	keys := make([]string, 0, len(root))
	for key := range root {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	observations := make([]AcceleratorObservation, 0, len(keys))
	seen := make(map[string]struct{})
	for _, key := range keys {
		if len(observations) >= 32 {
			return nil, ErrAcceleratorProbe
		}
		var card amdObject
		if err := json.Unmarshal(root[key], &card); err != nil {
			return nil, ErrAcceleratorProbe
		}
		index, ok := amdCardIndex(key)
		if !ok {
			return nil, ErrAcceleratorProbe
		}
		value, err := parseAMDCard(index, card)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[value.ID]; duplicate {
			return nil, ErrDuplicateID
		}
		seen[value.ID] = struct{}{}
		observations = append(observations, value)
	}
	return observations, nil
}
func ensureJSONEnd(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	}
	return ErrAcceleratorProbe
}
func amdCardIndex(key string) (string, bool) {
	lower := strings.ToLower(strings.TrimSpace(key))
	lower = strings.TrimPrefix(lower, "card")
	if strings.HasPrefix(lower, "gpu") {
		lower = strings.TrimPrefix(lower, "gpu")
	}
	lower = strings.TrimSpace(lower)
	return lower, digits(lower)
}

func parseAMDCard(index string, card amdObject) (AcceleratorObservation, error) {
	id := firstAMDString(card, "Unique ID", "Unique ID (Hex)")
	if !validID(id) {
		id = "amd-" + index
	}
	name := firstAMDString(card, "Card series", "Card model", "Product Name", "Device Name")
	if !validID(id) || !validName(name) {
		return AcceleratorObservation{}, ErrAcceleratorProbe
	}
	total, totalFound, totalAmbiguous := amdMemoryValue(card, "VRAM Total Memory")
	used, usedFound, usedAmbiguous := amdMemoryValue(card, "VRAM Total Used Memory")
	if !totalFound || !usedFound || totalAmbiguous || usedAmbiguous || used > total {
		return AcceleratorObservation{}, ErrAcceleratorProbe
	}
	utilization, ok := amdPercent(card, "GPU use (%)", "GPU use")
	if !ok {
		return AcceleratorObservation{}, ErrAcceleratorProbe
	}
	value := AcceleratorObservation{ID: id, Name: name, Kind: AcceleratorAMD, Memory: ResourceQuantity{TotalBytes: ByteAmount(total), UsedBytes: ByteAmount(used), AvailableBytes: ByteAmount(total - used)}, UtilizationPercent: utilization}
	if err := value.Validate(); err != nil {
		return AcceleratorObservation{}, ErrAcceleratorProbe
	}
	return value, nil
}
func firstAMDString(card amdObject, keys ...string) string {
	for _, key := range keys {
		raw, exists := card[key]
		if !exists {
			continue
		}
		var value string
		if json.Unmarshal(raw, &value) == nil {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
func amdMemoryValue(card amdObject, prefix string) (uint64, bool, bool) {
	var value uint64
	found := false
	for key, raw := range card {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		unit := ""
		switch {
		case strings.HasSuffix(key, "(B)"):
			unit = "B"
		case strings.HasSuffix(key, "(MiB)"):
			unit = "MiB"
		default:
			return 0, false, true
		}
		parsed, ok := rawUint(raw)
		if !ok || found {
			return 0, false, true
		}
		if unit == "MiB" {
			var overflow bool
			parsed, overflow = mibToBytes(parsed)
			if overflow {
				return 0, false, true
			}
		}
		value, found = parsed, true
	}
	return value, found, false
}
func rawUint(raw json.RawMessage) (uint64, bool) {
	var number json.Number
	if json.Unmarshal(raw, &number) == nil {
		value, err := strconv.ParseUint(string(number), 10, 64)
		if err == nil {
			return value, true
		}
	}
	var text string
	if json.Unmarshal(raw, &text) != nil {
		return 0, false
	}
	return strictUint(text)
}
func amdPercent(card amdObject, keys ...string) (*uint8, bool) {
	for _, key := range keys {
		raw, exists := card[key]
		if !exists {
			continue
		}
		value, ok := rawUint(raw)
		if !ok || value > 100 {
			return nil, false
		}
		result := uint8(value)
		return &result, true
	}
	return nil, false
}

func (o AMDObserver) String() string { return fmt.Sprintf("AMDObserver(%t)", o.available) }
