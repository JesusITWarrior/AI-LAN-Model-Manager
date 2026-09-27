package lmstudio

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
)

const (
	MaximumListBodySize    = 1024 * 1024
	MaximumAvailableModels = MaximumModels
)

var (
	ErrListFailed           = errors.New("lmstudio available-model request failed")
	ErrListHTTPStatus       = errors.New("lmstudio available-model request returned unexpected status")
	ErrListResponseTooLarge = errors.New("lmstudio available-model response too large")
	ErrInvalidListResponse  = errors.New("invalid lmstudio available-model response")
)

// ListAvailableModels fetches the OpenAI-compatible model inventory. LM Studio
// does not expose artifact metadata or trustworthy capability and modality
// claims at this endpoint, so none is inferred.
func (client *Client) ListAvailableModels(ctx context.Context) ([]provider.AvailableModel, error) {
	body, err := client.doJSON(ctx, "/v1/models", MaximumListBodySize, jsonResponseErrors{
		failed: ErrListFailed,
		status: ErrListHTTPStatus,
		large:  ErrListResponseTooLarge,
	})
	if err != nil {
		return nil, err
	}
	models, err := decodeAvailableModels(body, client.providerID)
	if err != nil {
		return nil, ErrInvalidListResponse
	}
	return models, nil
}

type inventoryEntry struct {
	id           string
	owner        string
	ownerKnown   bool
	created      int64
	createdKnown bool
}

func decodeAvailableModels(body []byte, providerID string) ([]provider.AvailableModel, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, ErrInvalidListResponse
	}
	seen := make(map[string]bool, 2)
	entries := make([]inventoryEntry, 0)
	for decoder.More() {
		key, err := inventoryStringToken(decoder)
		if err != nil || seen[key] {
			return nil, ErrInvalidListResponse
		}
		seen[key] = true
		switch key {
		case "object":
			var value string
			if err := decoder.Decode(&value); err != nil || value != modelsObjectLabel {
				return nil, ErrInvalidListResponse
			}
		case "data":
			entries, err = decodeInventoryData(decoder)
			if err != nil {
				return nil, err
			}
		default:
			return nil, ErrInvalidListResponse
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || !seen["object"] || !seen["data"] {
		return nil, ErrInvalidListResponse
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidListResponse
	}

	models := make([]provider.AvailableModel, 0, len(entries))
	for _, entry := range entries {
		identifier := sha256.Sum256([]byte(providerID + "\x00" + entry.id))
		model := provider.AvailableModel{
			ModelID:        "lmstudio-" + hex.EncodeToString(identifier[:]),
			ProviderID:     providerID,
			CanonicalName:  entry.id,
			DisplayName:    entry.id,
			State:          provider.AvailableModelStateAvailable,
			Owner:          entry.owner,
			OwnerKnown:     entry.ownerKnown,
			CreatedAtKnown: entry.createdKnown,
			Capabilities:   make([]string, 0),
			Modalities:     make([]string, 0),
		}
		if entry.createdKnown {
			model.CreatedAt = time.Unix(entry.created, 0).UTC().Format("2006-01-02T15:04:05.000Z")
		}
		models = append(models, model)
	}
	sort.Slice(models, func(i, j int) bool {
		left, right := strings.ToLower(models[i].CanonicalName), strings.ToLower(models[j].CanonicalName)
		if left != right {
			return left < right
		}
		return models[i].CanonicalName < models[j].CanonicalName
	})
	return models, nil
}

func decodeInventoryData(decoder *json.Decoder) ([]inventoryEntry, error) {
	if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
		return nil, ErrInvalidListResponse
	}
	entries := make([]inventoryEntry, 0)
	ids := make(map[string]struct{})
	for decoder.More() {
		if len(entries) == MaximumAvailableModels {
			return nil, ErrInvalidListResponse
		}
		entry, err := decodeInventoryEntry(decoder)
		if err != nil {
			return nil, err
		}
		if _, duplicate := ids[entry.id]; duplicate {
			return nil, ErrInvalidListResponse
		}
		ids[entry.id] = struct{}{}
		entries = append(entries, entry)
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim(']') {
		return nil, ErrInvalidListResponse
	}
	return entries, nil
}

func decodeInventoryEntry(decoder *json.Decoder) (inventoryEntry, error) {
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return inventoryEntry{}, ErrInvalidListResponse
	}
	seen := make(map[string]bool, 4)
	var entry inventoryEntry
	for decoder.More() {
		key, err := inventoryStringToken(decoder)
		if err != nil || seen[key] {
			return inventoryEntry{}, ErrInvalidListResponse
		}
		seen[key] = true
		switch key {
		case "id":
			if err := decoder.Decode(&entry.id); err != nil || !validInventoryModelID(entry.id) {
				return inventoryEntry{}, ErrInvalidListResponse
			}
		case "object":
			var value string
			if err := decoder.Decode(&value); err != nil || value != modelsEntryObjectLabel {
				return inventoryEntry{}, ErrInvalidListResponse
			}
		case "created":
			token, err := decoder.Token()
			number, ok := token.(json.Number)
			if err != nil || !ok {
				return inventoryEntry{}, ErrInvalidListResponse
			}
			entry.created, err = strconv.ParseInt(number.String(), 10, 64)
			if err != nil || entry.created < 0 || entry.created > 253402300799 {
				return inventoryEntry{}, ErrInvalidListResponse
			}
			entry.createdKnown = true
		case "owned_by":
			if err := decoder.Decode(&entry.owner); err != nil || !ownerPattern.MatchString(entry.owner) {
				return inventoryEntry{}, ErrInvalidListResponse
			}
			entry.ownerKnown = true
		default:
			return inventoryEntry{}, ErrInvalidListResponse
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || !seen["id"] {
		return inventoryEntry{}, ErrInvalidListResponse
	}
	return entry, nil
}

func validInventoryModelID(id string) bool {
	if !modelIDPattern.MatchString(id) {
		return false
	}
	for _, segment := range strings.Split(id, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func inventoryStringToken(decoder *json.Decoder) (string, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", err
	}
	value, ok := token.(string)
	if !ok {
		return "", ErrInvalidListResponse
	}
	return value, nil
}
