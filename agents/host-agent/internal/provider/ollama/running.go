package ollama

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
)

const (
	MaximumRunningBodySize = 1024 * 1024
	MaximumRunningModels   = 10000
	MaximumContextLength   = 10_000_000
)

var (
	ErrRunningFailed           = errors.New("ollama running-model request failed")
	ErrRunningHTTPStatus       = errors.New("ollama running-model request returned unexpected status")
	ErrRunningResponseTooLarge = errors.New("ollama running-model response too large")
	ErrInvalidRunningResponse  = errors.New("invalid ollama running-model response")
)

// ListRunning fetches and strictly validates Ollama's loaded-model observation.
func (client *Client) ListRunning(ctx context.Context) ([]provider.RunningModel, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	requestContext, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, client.endpoint+"/api/ps", nil)
	if err != nil {
		return nil, ErrRunningFailed
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.doer.Do(request)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil {
		if contextErr := requestContext.Err(); contextErr != nil {
			return nil, contextErr
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, ErrRunningFailed
	}
	if response == nil || response.Body == nil {
		return nil, ErrRunningFailed
	}
	if response.StatusCode != http.StatusOK {
		return nil, ErrRunningHTTPStatus
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, MaximumRunningBodySize+1))
	if err != nil {
		if contextErr := requestContext.Err(); contextErr != nil {
			return nil, contextErr
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, ErrInvalidRunningResponse
	}
	if len(body) > MaximumRunningBodySize {
		return nil, ErrRunningResponseTooLarge
	}
	observedAt := formatTimestamp(client.clock.Now())
	models, err := decodeRunningModels(body, client.providerID, observedAt)
	if err != nil {
		return nil, ErrInvalidRunningResponse
	}
	return models, nil
}

type runningModel struct {
	name, model, digest, expiresAt string
	size, sizeVRAM, contextLength  uint64
	details                        tagDetails
}

func decodeRunningModels(body []byte, providerID, observedAt string) ([]provider.RunningModel, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, ErrInvalidRunningResponse
	}
	seenModels := false
	rawModels := make([]runningModel, 0)
	for decoder.More() {
		key, err := stringToken(decoder)
		if err != nil || key != "models" || seenModels {
			return nil, ErrInvalidRunningResponse
		}
		seenModels = true
		if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
			return nil, ErrInvalidRunningResponse
		}
		for decoder.More() {
			if len(rawModels) >= MaximumRunningModels {
				return nil, ErrInvalidRunningResponse
			}
			model, err := decodeRunningModel(decoder)
			if err != nil {
				return nil, err
			}
			rawModels = append(rawModels, model)
		}
		if token, err := decoder.Token(); err != nil || token != json.Delim(']') {
			return nil, ErrInvalidRunningResponse
		}
	}
	if !seenModels {
		return nil, ErrInvalidRunningResponse
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrInvalidRunningResponse
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidRunningResponse
	}

	models := make([]provider.RunningModel, 0, len(rawModels))
	canonicalSeen := make(map[string]struct{}, len(rawModels))
	for _, raw := range rawModels {
		model, err := normalizeRunningModel(raw, providerID, observedAt)
		if err != nil {
			return nil, err
		}
		if _, exists := canonicalSeen[model.CanonicalName]; exists {
			return nil, ErrInvalidRunningResponse
		}
		canonicalSeen[model.CanonicalName] = struct{}{}
		models = append(models, model)
	}
	sort.Slice(models, func(i, j int) bool {
		if models[i].CanonicalName != models[j].CanonicalName {
			return models[i].CanonicalName < models[j].CanonicalName
		}
		return models[i].Digest < models[j].Digest
	})
	return models, nil
}

func decodeRunningModel(decoder *json.Decoder) (runningModel, error) {
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return runningModel{}, ErrInvalidRunningResponse
	}
	var model runningModel
	seen := make(map[string]bool, 8)
	for decoder.More() {
		key, err := stringToken(decoder)
		if err != nil || seen[key] {
			return runningModel{}, ErrInvalidRunningResponse
		}
		seen[key] = true
		switch key {
		case "name":
			err = decoder.Decode(&model.name)
		case "model":
			err = decoder.Decode(&model.model)
		case "size":
			model.size, err = decodeUint64(decoder)
		case "digest":
			err = decoder.Decode(&model.digest)
		case "details":
			model.details, err = decodeTagDetails(decoder)
		case "expires_at":
			err = decoder.Decode(&model.expiresAt)
		case "size_vram":
			model.sizeVRAM, err = decodeUint64(decoder)
		case "context_length":
			model.contextLength, err = decodeUint64(decoder)
		default:
			return runningModel{}, ErrInvalidRunningResponse
		}
		if err != nil {
			return runningModel{}, ErrInvalidRunningResponse
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || len(seen) != 8 {
		return runningModel{}, ErrInvalidRunningResponse
	}
	for _, key := range []string{"name", "model", "size", "digest", "details", "expires_at", "size_vram", "context_length"} {
		if !seen[key] {
			return runningModel{}, ErrInvalidRunningResponse
		}
	}
	return model, nil
}

func decodeUint64(decoder *json.Decoder) (uint64, error) {
	var number json.Number
	if err := decoder.Decode(&number); err != nil {
		return 0, err
	}
	return strconv.ParseUint(string(number), 10, 64)
}

// normalizeResidency reports how the model's tensors are distributed across
// device memory from size and size_vram only. It never inspects the family,
// name, or reported capabilities. size_vram greater than size is treated as an
// inconsistent/authoritative-unconfirmed value and rejected; size_vram equal to
// size (with size > 0) is fully-GPU; 0 < size_vram < size is split; size_vram
// of 0 is CPU-only.
func normalizeResidency(size, sizeVRAM uint64) (provider.Residency, error) {
	switch {
	case sizeVRAM == 0:
		return provider.ResidencyCPU, nil
	case sizeVRAM > size:
		return provider.Residency(""), ErrInvalidRunningResponse
	case sizeVRAM == size:
		return provider.ResidencyGPU, nil
	default: // 0 < size_vram < size
		return provider.ResidencySplit, nil
	}
}

// normalizeRunningModel normalizes one running-model observation. It reuses the
// shared installed-path helpers (canonicalModelName, normalizeMetadata,
// normalizeFamilies, and formatTimestamp) so installed and running agree on every
// rule; the caller-supplied sentinel (ErrInvalidRunningResponse) is threaded
// through so the strict-response assertion stays provider-specific. Family (the
// singular) is stored as reported; Families (the list) is canonicalized
// (lowercased) and de-duplicated case-insensitively via normalizeFamilies,
// matching the installed path exactly.
func normalizeRunningModel(raw runningModel, providerID, observedAt string) (provider.RunningModel, error) {
	canonicalName, ok := canonicalModelName(raw.model)
	if !ok {
		return provider.RunningModel{}, ErrInvalidRunningResponse
	}
	displayCanonical, ok := canonicalModelName(raw.name)
	if !ok || displayCanonical != canonicalName || !digestPattern.MatchString(raw.digest) {
		return provider.RunningModel{}, ErrInvalidRunningResponse
	}
	digest := strings.ToLower(raw.digest)
	expires, err := time.Parse(time.RFC3339Nano, raw.expiresAt)
	if err != nil || raw.contextLength < 1 || raw.contextLength > MaximumContextLength {
		return provider.RunningModel{}, ErrInvalidRunningResponse
	}
	parent := ""
	if raw.details.parentModel != "" {
		parent, ok = canonicalModelName(raw.details.parentModel)
		if !ok {
			return provider.RunningModel{}, ErrInvalidRunningResponse
		}
	}
	if err := normalizeMetadata(raw.details, ErrInvalidRunningResponse); err != nil {
		return provider.RunningModel{}, err
	}
	families, err := normalizeFamilies(raw.details.families, ErrInvalidRunningResponse)
	if err != nil {
		return provider.RunningModel{}, err
	}
	residency, err := normalizeResidency(raw.size, raw.sizeVRAM)
	if err != nil {
		return provider.RunningModel{}, err
	}
	runtimeID := sha256.Sum256([]byte(providerID + "\x00" + canonicalName + "\x00" + digest))
	return provider.RunningModel{
		RuntimeID:     "ollama-runtime-" + hex.EncodeToString(runtimeID[:]),
		ProviderID:    providerID,
		CanonicalName: canonicalName,
		DisplayName:   raw.name,
		Digest:        digest,
		SizeBytes:     raw.size,
		SizeVRAMBytes: raw.sizeVRAM,
		ExpiresAt:     formatTimestamp(expires),
		ContextLength: raw.contextLength,
		ParentModel:   parent,
		Format:        raw.details.format,
		Family:        raw.details.family,
		Families:      families,
		ParameterSize: raw.details.parameter,
		Quantization:  raw.details.quantization,
		Capabilities:  []string{},
		Residency:     residency,
		Modalities:    []string{},
		ObservedAt:    observedAt,
	}, nil
}
