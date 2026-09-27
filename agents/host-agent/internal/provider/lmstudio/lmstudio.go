// Package lmstudio implements a health-only LM Studio provider adapter.
package lmstudio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
)

const (
	MaximumBodySize = 64 * 1024
	MaximumModels   = 10000

	modelsObjectLabel      = "list"
	modelsEntryObjectLabel = "model"
)

var (
	ErrInvalidConfig    = errors.New("invalid lmstudio configuration")
	ErrInvalidTimeout   = errors.New("invalid lmstudio timeout")
	ErrResponseFailed   = errors.New("lmstudio probe request failed")
	ErrResponseStatus   = errors.New("lmstudio probe returned unexpected status")
	ErrResponseTooLarge = errors.New("lmstudio probe response too large")
	ErrResponseInvalid  = errors.New("lmstudio probe response malformed")

	// Model ids are validated only as a health sanity check and are never
	// returned. This permits common namespace/name ids while rejecting control,
	// whitespace, URL-query, traversal-leading, and overlong values.
	modelIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$`)
	ownerPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/+ -]{0,255}$`)
)

const (
	DefaultTimeout = provider.DefaultTimeout
	MinimumTimeout = provider.MinimumTimeout
	MaximumTimeout = provider.MaximumTimeout
)

type HTTPDoer = provider.HTTPDoer
type Clock = provider.Clock

// Config contains the complete configuration for one LM Studio adapter.
type Config struct {
	ProviderID string
	Endpoint   string
	Timeout    time.Duration
}

// Client probes one normalized LM Studio endpoint.
type Client struct {
	providerID string
	endpoint   string
	timeout    time.Duration
	doer       provider.HTTPDoer
	clock      provider.Clock
}

// New creates a production client that rejects redirects. The configured
// timeout is enforced by the request context in Probe.
func New(config Config) (*Client, error) {
	return NewWithDependencies(config, provider.NoRedirectDoer(), provider.SystemClock{})
}

// NewWithDependencies creates a client with injected transport and clock.
func NewWithDependencies(config Config, doer provider.HTTPDoer, clock provider.Clock) (*Client, error) {
	if !provider.ValidateProviderID(config.ProviderID) {
		return nil, errors.Join(ErrInvalidConfig, provider.ErrInvalidProviderID)
	}
	endpoint, err := provider.NormalizeEndpoint(config.Endpoint)
	if err != nil {
		return nil, errors.Join(ErrInvalidConfig, provider.ErrInvalidEndpoint)
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = provider.DefaultTimeout
	}
	if timeout < provider.MinimumTimeout || timeout > provider.MaximumTimeout {
		return nil, errors.Join(ErrInvalidConfig, ErrInvalidTimeout)
	}
	if doer == nil || clock == nil {
		return nil, ErrInvalidConfig
	}
	return &Client{
		providerID: config.ProviderID,
		endpoint:   endpoint,
		timeout:    timeout,
		doer:       doer,
		clock:      clock,
	}, nil
}

// NormalizeEndpoint exposes the provider-wide origin validation contract.
func NormalizeEndpoint(raw string) (string, error) {
	return provider.NormalizeEndpoint(raw)
}

// Probe requests GET /v1/models and validates only enough of the response to
// establish health. It does not expose model ids and does not guess a version
// from response headers, so every successful LM Studio probe has an explicitly
// unknown (zero) version.
func (client *Client) Probe(ctx context.Context) (provider.ProviderProbe, error) {
	if err := ctx.Err(); err != nil {
		return provider.ProviderProbe{}, err
	}
	probeContext, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	request, err := http.NewRequestWithContext(probeContext, http.MethodGet, client.endpoint+"/v1/models", nil)
	if err != nil {
		return provider.ProviderProbe{}, ErrResponseFailed
	}
	request.Header.Set("Accept", "application/json")

	response, err := client.doer.Do(request)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil {
		if contextErr := probeContext.Err(); contextErr != nil {
			return provider.ProviderProbe{}, contextErr
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return provider.ProviderProbe{}, err
		}
		return provider.ProviderProbe{}, ErrResponseFailed
	}
	if response == nil || response.Body == nil {
		return provider.ProviderProbe{}, ErrResponseFailed
	}
	if response.StatusCode != http.StatusOK {
		return provider.ProviderProbe{}, ErrResponseStatus
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, MaximumBodySize+1))
	if err != nil {
		if contextErr := probeContext.Err(); contextErr != nil {
			return provider.ProviderProbe{}, contextErr
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return provider.ProviderProbe{}, err
		}
		return provider.ProviderProbe{}, ErrResponseFailed
	}
	if len(body) > MaximumBodySize {
		return provider.ProviderProbe{}, ErrResponseTooLarge
	}
	if err := validateModels(body); err != nil {
		return provider.ProviderProbe{}, ErrResponseInvalid
	}

	return provider.ProviderProbe{
		ProviderID:   client.providerID,
		Kind:         provider.KindLMStudio,
		Endpoint:     client.endpoint,
		Health:       provider.HealthReady,
		Version:      provider.UnknownVersion(),
		VersionKnown: false,
		ObservedAt:   client.clock.Now().UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z"),
	}, nil
}

// validateModels accepts exactly the OpenAI-compatible list envelope: root keys
// "object" and "data", with object equal to "list". Entry keys are limited to
// id, object, created, and owned_by. id is required; object is optional because
// LM Studio versions have emitted both forms, but when present it must be
// "model". created and owned_by are optional and strictly typed. Duplicate keys,
// duplicate ids, unknown keys, malformed values, and trailing JSON are rejected.
func validateModels(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return ErrResponseInvalid
	}
	seen := make(map[string]bool, 2)
	for decoder.More() {
		key, err := stringToken(decoder)
		if err != nil || seen[key] {
			return ErrResponseInvalid
		}
		seen[key] = true
		switch key {
		case "object":
			var value string
			if err := decoder.Decode(&value); err != nil || value != modelsObjectLabel {
				return ErrResponseInvalid
			}
		case "data":
			if err := validateData(decoder); err != nil {
				return err
			}
		default:
			return ErrResponseInvalid
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || !seen["object"] || !seen["data"] {
		return ErrResponseInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrResponseInvalid
	}
	return nil
}

func validateData(decoder *json.Decoder) error {
	if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
		return ErrResponseInvalid
	}
	ids := make(map[string]struct{})
	count := 0
	for decoder.More() {
		if count == MaximumModels {
			return ErrResponseInvalid
		}
		id, err := validateEntry(decoder)
		if err != nil {
			return err
		}
		if _, duplicate := ids[id]; duplicate {
			return ErrResponseInvalid
		}
		ids[id] = struct{}{}
		count++
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim(']') {
		return ErrResponseInvalid
	}
	return nil
}

func validateEntry(decoder *json.Decoder) (string, error) {
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return "", ErrResponseInvalid
	}
	seen := make(map[string]bool, 4)
	var id string
	for decoder.More() {
		key, err := stringToken(decoder)
		if err != nil || seen[key] {
			return "", ErrResponseInvalid
		}
		seen[key] = true
		switch key {
		case "id":
			if err := decoder.Decode(&id); err != nil || !modelIDPattern.MatchString(id) {
				return "", ErrResponseInvalid
			}
		case "object":
			var value string
			if err := decoder.Decode(&value); err != nil || value != modelsEntryObjectLabel {
				return "", ErrResponseInvalid
			}
		case "created":
			token, err := decoder.Token()
			value, ok := token.(json.Number)
			if err != nil || !ok {
				return "", ErrResponseInvalid
			}
			created, err := strconv.ParseInt(value.String(), 10, 64)
			if err != nil || created < 0 {
				return "", ErrResponseInvalid
			}
		case "owned_by":
			var value string
			if err := decoder.Decode(&value); err != nil || !ownerPattern.MatchString(value) {
				return "", ErrResponseInvalid
			}
		default:
			return "", ErrResponseInvalid
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || !seen["id"] {
		return "", ErrResponseInvalid
	}
	return id, nil
}

func stringToken(decoder *json.Decoder) (string, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", err
	}
	value, ok := token.(string)
	if !ok {
		return "", ErrResponseInvalid
	}
	return value, nil
}
