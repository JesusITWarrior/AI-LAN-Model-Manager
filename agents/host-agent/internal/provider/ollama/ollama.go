package ollama

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
)

const (
	DefaultTimeout          = 5 * time.Second
	MinimumTimeout          = 100 * time.Millisecond
	MaximumTimeout          = 30 * time.Second
	MaximumBodySize         = 64 * 1024
	MaximumListBodySize     = 1024 * 1024
	MaximumInstalledModels  = 10000
	maximumProviderIDLength = 128
	maximumModelNameLength  = 256
	maximumMetadataLength   = 128
	maximumVersionLength    = 128
	maximumVersion          = 65535
)

var (
	ErrInvalidConfig   = errors.New("invalid ollama configuration")
	ErrInvalidID       = errors.New("invalid ollama provider id")
	ErrInvalidEndpoint = errors.New("invalid ollama endpoint")
	ErrInvalidTimeout  = errors.New("invalid ollama timeout")
	ErrProbeFailed     = errors.New("ollama probe failed")
	ErrHTTPStatus      = errors.New("ollama probe returned unexpected status")
	ErrInvalidResponse = errors.New("invalid ollama version response")
	ErrInvalidVersion  = errors.New("invalid ollama version")

	ErrListFailed           = errors.New("ollama installed-model request failed")
	ErrListHTTPStatus       = errors.New("ollama installed-model request returned unexpected status")
	ErrListResponseTooLarge = errors.New("ollama installed-model response too large")
	ErrInvalidListResponse  = errors.New("invalid ollama installed-model response")

	providerIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	versionPattern    = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)
	digestPattern     = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	metadataPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._+:/()-]*$`)
)

// Config contains the complete configuration for one Ollama adapter.
type Config struct {
	// ProviderID is an opaque 1..128 byte ASCII identifier. It starts with an
	// alphanumeric byte; later bytes may also be '.', '_', ':', or '-'.
	ProviderID string
	Endpoint   string
	Timeout    time.Duration
}

// HTTPDoer permits deterministic tests without a network listener.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Clock permits deterministic observation timestamps.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// Client probes one normalized Ollama endpoint.
type Client struct {
	providerID string
	endpoint   string
	timeout    time.Duration
	doer       HTTPDoer
	clock      Clock
}

// New creates a production client whose HTTP transport never follows redirects.
func New(config Config) (*Client, error) {
	doer := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return NewWithDependencies(config, doer, systemClock{})
}

// NewWithDependencies creates a client with injected HTTP and time dependencies.
func NewWithDependencies(config Config, doer HTTPDoer, clock Clock) (*Client, error) {
	if len(config.ProviderID) < 1 || len(config.ProviderID) > maximumProviderIDLength || !providerIDPattern.MatchString(config.ProviderID) {
		return nil, errors.Join(ErrInvalidConfig, ErrInvalidID)
	}
	endpoint, err := NormalizeEndpoint(config.Endpoint)
	if err != nil {
		return nil, errors.Join(ErrInvalidConfig, err)
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout < MinimumTimeout || timeout > MaximumTimeout {
		return nil, errors.Join(ErrInvalidConfig, ErrInvalidTimeout)
	}
	if doer == nil || clock == nil {
		return nil, ErrInvalidConfig
	}
	return &Client{providerID: config.ProviderID, endpoint: endpoint, timeout: timeout, doer: doer, clock: clock}, nil
}

// NormalizeEndpoint validates an HTTP(S) origin and removes its optional root slash.
func NormalizeEndpoint(raw string) (string, error) {
	if raw == "" || len(raw) > 2048 || strings.TrimSpace(raw) != raw || strings.Contains(raw, "#") {
		return "", ErrInvalidEndpoint
	}
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.Hostname() == "" {
		return "", ErrInvalidEndpoint
	}
	if !validPort(parsed.Host) {
		return "", ErrInvalidEndpoint
	}
	if parsed.Opaque != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawFragment != "" {
		return "", ErrInvalidEndpoint
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", ErrInvalidEndpoint
	}
	if parsed.RawPath != "" {
		return "", ErrInvalidEndpoint
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

func validPort(host string) bool {
	if strings.HasPrefix(host, "[") {
		closingBracket := strings.LastIndexByte(host, ']')
		if closingBracket < 0 {
			return false
		}
		if closingBracket == len(host)-1 {
			return true
		}
		if host[closingBracket+1] != ':' {
			return false
		}
		return portInRange(host[closingBracket+2:])
	}

	firstColon := strings.IndexByte(host, ':')
	if firstColon < 0 {
		return true
	}
	if firstColon != strings.LastIndexByte(host, ':') {
		return false
	}
	return portInRange(host[firstColon+1:])
}

func portInRange(port string) bool {
	value, err := strconv.ParseUint(port, 10, 16)
	return err == nil && value > 0
}

// ParseVersion accepts Ollama's optional v prefix and a SemVer-style prerelease.
func ParseVersion(raw string) (provider.VersionInfo, error) {
	if len(raw) < 1 || len(raw) > maximumVersionLength {
		return provider.VersionInfo{}, ErrInvalidVersion
	}
	matches := versionPattern.FindStringSubmatch(raw)
	if matches == nil {
		return provider.VersionInfo{}, ErrInvalidVersion
	}
	components := [3]uint16{}
	for index, text := range matches[1:4] {
		value, err := strconv.ParseUint(text, 10, 16)
		if err != nil || value > maximumVersion {
			return provider.VersionInfo{}, ErrInvalidVersion
		}
		components[index] = uint16(value)
	}
	prerelease := matches[4]
	for _, identifier := range strings.Split(prerelease, ".") {
		if prerelease != "" && len(identifier) > 1 && identifier[0] == '0' {
			if _, err := strconv.ParseUint(identifier, 10, 64); err == nil {
				return provider.VersionInfo{}, ErrInvalidVersion
			}
		}
	}
	normalized := fmt.Sprintf("%d.%d.%d", components[0], components[1], components[2])
	if prerelease != "" {
		normalized += "-" + prerelease
	}
	if len(normalized) > maximumVersionLength {
		return provider.VersionInfo{}, ErrInvalidVersion
	}
	return provider.VersionInfo{Raw: normalized, Major: components[0], Minor: components[1], Patch: components[2], Prerelease: prerelease}, nil
}

// Probe fetches and strictly validates /api/version.
func (client *Client) Probe(ctx context.Context) (provider.ProviderProbe, error) {
	if err := ctx.Err(); err != nil {
		return provider.ProviderProbe{}, err
	}
	probeContext, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	request, err := http.NewRequestWithContext(probeContext, http.MethodGet, client.endpoint+"/api/version", nil)
	if err != nil {
		return provider.ProviderProbe{}, ErrProbeFailed
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
		return provider.ProviderProbe{}, ErrProbeFailed
	}
	if response == nil || response.Body == nil {
		return provider.ProviderProbe{}, ErrProbeFailed
	}
	if response.StatusCode != http.StatusOK {
		return provider.ProviderProbe{}, ErrHTTPStatus
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, MaximumBodySize+1))
	if err != nil {
		if contextErr := probeContext.Err(); contextErr != nil {
			return provider.ProviderProbe{}, contextErr
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return provider.ProviderProbe{}, err
		}
		return provider.ProviderProbe{}, ErrInvalidResponse
	}
	if len(body) > MaximumBodySize {
		return provider.ProviderProbe{}, ErrInvalidResponse
	}
	versionText, err := decodeVersion(body)
	if err != nil {
		return provider.ProviderProbe{}, ErrInvalidResponse
	}
	version, err := ParseVersion(versionText)
	if err != nil {
		return provider.ProviderProbe{}, ErrInvalidResponse
	}
	observedAt := client.clock.Now().UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
	return provider.ProviderProbe{
		ProviderID: client.providerID,
		Kind:       provider.KindOllama,
		Endpoint:   client.endpoint,
		Health:     provider.HealthReady,
		Version:    version,
		ObservedAt: observedAt,
	}, nil
}

func decodeVersion(body []byte) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return "", ErrInvalidResponse
	}
	if !decoder.More() {
		return "", ErrInvalidResponse
	}
	key, err := decoder.Token()
	if err != nil || key != "version" {
		return "", ErrInvalidResponse
	}
	var version string
	if err := decoder.Decode(&version); err != nil {
		return "", ErrInvalidResponse
	}
	if decoder.More() {
		return "", ErrInvalidResponse
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return "", ErrInvalidResponse
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", ErrInvalidResponse
	}
	return version, nil
}

// ListInstalled fetches and strictly validates the installed-model inventory.
func (client *Client) ListInstalled(ctx context.Context) ([]provider.InstalledModel, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	requestContext, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, client.endpoint+"/api/tags", nil)
	if err != nil {
		return nil, ErrListFailed
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
		return nil, ErrListFailed
	}
	if response == nil || response.Body == nil {
		return nil, ErrListFailed
	}
	if response.StatusCode != http.StatusOK {
		return nil, ErrListHTTPStatus
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaximumListBodySize+1))
	if err != nil {
		if contextErr := requestContext.Err(); contextErr != nil {
			return nil, contextErr
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, ErrInvalidListResponse
	}
	if len(body) > MaximumListBodySize {
		return nil, ErrListResponseTooLarge
	}
	models, err := decodeInstalledModels(body, client.providerID)
	if err != nil {
		return nil, ErrInvalidListResponse
	}
	return models, nil
}

type tagModel struct {
	name, model, modifiedAt, digest string
	size                            uint64
	details                         tagDetails
}
type tagDetails struct {
	parentModel, format, family string
	families                    []string
	parameter, quantization     string
}

func decodeInstalledModels(body []byte, providerID string) ([]provider.InstalledModel, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, ErrInvalidListResponse
	}
	seenRoot := false
	var rawModels []tagModel
	for decoder.More() {
		key, err := stringToken(decoder)
		if err != nil || key != "models" || seenRoot {
			return nil, ErrInvalidListResponse
		}
		seenRoot = true
		if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
			return nil, ErrInvalidListResponse
		}
		for decoder.More() {
			if len(rawModels) >= MaximumInstalledModels {
				return nil, ErrInvalidListResponse
			}
			model, err := decodeTagModel(decoder)
			if err != nil {
				return nil, err
			}
			rawModels = append(rawModels, model)
		}
		if token, err := decoder.Token(); err != nil || token != json.Delim(']') {
			return nil, ErrInvalidListResponse
		}
	}
	if !seenRoot {
		return nil, ErrInvalidListResponse
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrInvalidListResponse
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidListResponse
	}
	models := make([]provider.InstalledModel, 0, len(rawModels))
	canonicalSeen := make(map[string]struct{}, len(rawModels))
	for _, raw := range rawModels {
		model, err := normalizeTagModel(raw, providerID)
		if err != nil {
			return nil, err
		}
		if _, exists := canonicalSeen[model.CanonicalName]; exists {
			return nil, ErrInvalidListResponse
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

func decodeTagModel(decoder *json.Decoder) (tagModel, error) {
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return tagModel{}, ErrInvalidListResponse
	}
	var model tagModel
	seen := make(map[string]bool, 6)
	for decoder.More() {
		key, err := stringToken(decoder)
		if err != nil || seen[key] {
			return tagModel{}, ErrInvalidListResponse
		}
		seen[key] = true
		switch key {
		case "name":
			err = decoder.Decode(&model.name)
		case "model":
			err = decoder.Decode(&model.model)
		case "modified_at":
			err = decoder.Decode(&model.modifiedAt)
		case "size":
			var number json.Number
			if err = decoder.Decode(&number); err == nil {
				model.size, err = strconv.ParseUint(string(number), 10, 64)
			}
		case "digest":
			err = decoder.Decode(&model.digest)
		case "details":
			model.details, err = decodeTagDetails(decoder)
		default:
			return tagModel{}, ErrInvalidListResponse
		}
		if err != nil {
			return tagModel{}, ErrInvalidListResponse
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || len(seen) != 6 {
		return tagModel{}, ErrInvalidListResponse
	}
	for _, key := range []string{"name", "model", "modified_at", "size", "digest", "details"} {
		if !seen[key] {
			return tagModel{}, ErrInvalidListResponse
		}
	}
	return model, nil
}

func decodeTagDetails(decoder *json.Decoder) (tagDetails, error) {
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return tagDetails{}, ErrInvalidListResponse
	}
	var details tagDetails
	seen := make(map[string]bool, 6)
	for decoder.More() {
		key, err := stringToken(decoder)
		if err != nil || seen[key] {
			return tagDetails{}, ErrInvalidListResponse
		}
		seen[key] = true
		switch key {
		case "parent_model":
			err = decoder.Decode(&details.parentModel)
		case "format":
			err = decoder.Decode(&details.format)
		case "family":
			err = decoder.Decode(&details.family)
		case "families":
			details.families, err = decodeFamilies(decoder)
		case "parameter_size":
			err = decoder.Decode(&details.parameter)
		case "quantization_level":
			err = decoder.Decode(&details.quantization)
		default:
			return tagDetails{}, ErrInvalidListResponse
		}
		if err != nil {
			return tagDetails{}, ErrInvalidListResponse
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || len(seen) != 6 {
		return tagDetails{}, ErrInvalidListResponse
	}
	for _, key := range []string{"parent_model", "format", "family", "families", "parameter_size", "quantization_level"} {
		if !seen[key] {
			return tagDetails{}, ErrInvalidListResponse
		}
	}
	return details, nil
}

func decodeFamilies(decoder *json.Decoder) ([]string, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if token == nil {
		return []string{}, nil
	}
	if token != json.Delim('[') {
		return nil, ErrInvalidListResponse
	}
	families := make([]string, 0)
	for decoder.More() {
		if len(families) >= 32 {
			return nil, ErrInvalidListResponse
		}
		value, err := stringToken(decoder)
		if err != nil {
			return nil, err
		}
		families = append(families, value)
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim(']') {
		return nil, ErrInvalidListResponse
	}
	return families, nil
}

func stringToken(decoder *json.Decoder) (string, error) {
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

func normalizeTagModel(raw tagModel, providerID string) (provider.InstalledModel, error) {
	canonicalName, ok := canonicalModelName(raw.model)
	if !ok {
		return provider.InstalledModel{}, ErrInvalidListResponse
	}
	displayCanonical, ok := canonicalModelName(raw.name)
	if !ok || displayCanonical != canonicalName {
		return provider.InstalledModel{}, ErrInvalidListResponse
	}
	if !digestPattern.MatchString(raw.digest) {
		return provider.InstalledModel{}, ErrInvalidListResponse
	}
	digest := strings.ToLower(raw.digest)
	modified, err := time.Parse(time.RFC3339Nano, raw.modifiedAt)
	if err != nil {
		return provider.InstalledModel{}, ErrInvalidListResponse
	}
	parent := ""
	if raw.details.parentModel != "" {
		parent, ok = canonicalModelName(raw.details.parentModel)
		if !ok {
			return provider.InstalledModel{}, ErrInvalidListResponse
		}
	}
	if err := normalizeMetadata(raw.details, ErrInvalidListResponse); err != nil {
		return provider.InstalledModel{}, err
	}
	families, err := normalizeFamilies(raw.details.families, ErrInvalidListResponse)
	if err != nil {
		return provider.InstalledModel{}, err
	}
	runtimeID := sha256.Sum256([]byte(providerID + "\x00" + canonicalName + "\x00" + digest))
	return provider.InstalledModel{
		ModelID:       "ollama-" + hex.EncodeToString(runtimeID[:]),
		ProviderID:    providerID,
		CanonicalName: canonicalName,
		DisplayName:   raw.name,
		Digest:        digest,
		SizeBytes:     raw.size,
		ModifiedAt:    formatTimestamp(modified),
		ParentModel:   parent,
		Format:        raw.details.format,
		Family:        raw.details.family,
		Families:      families,
		ParameterSize: raw.details.parameter,
		Quantization:  raw.details.quantization,
	}, nil
}

func canonicalModelName(value string) (string, bool) {
	if len(value) < 1 || len(value) > maximumModelNameLength || strings.TrimSpace(value) != value {
		return "", false
	}
	for _, character := range value {
		if character > 0x7e || character < 0x21 || strings.ContainsRune("?#\\%", character) || !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._-/:@", character)) {
			return "", false
		}
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." || strings.HasPrefix(segment, ".") || strings.HasSuffix(segment, ".") {
			return "", false
		}
	}
	if strings.Count(value, "@") > 1 {
		return "", false
	}
	if at := strings.IndexByte(value, '@'); at >= 0 {
		if at == 0 || !strings.HasPrefix(strings.ToLower(value[at+1:]), "sha256:") || !digestPattern.MatchString(value[at+8:]) {
			return "", false
		}
	}
	return strings.ToLower(value), true
}
func validMetadata(value string) bool {
	return len(value) >= 1 && len(value) <= maximumMetadataLength && strings.TrimSpace(value) == value && metadataPattern.MatchString(value)
}

// normalizeMetadata validates the provider-neutral metadata strings shared by
// installed and running responses: format, family, parameter size, and
// quantization. Both decoders apply this single rule; the sentinel differs by
// caller so strict-response assertions stay provider-specific.
func normalizeMetadata(detail tagDetails, errResponse error) error {
	for _, value := range []string{detail.format, detail.family, detail.parameter, detail.quantization} {
		if !validMetadata(value) {
			return errResponse
		}
	}
	return nil
}

// normalizeFamilies canonicalizes (lowercases) every family, rejects invalid
// values, and de-duplicates the list case-insensitively. The returned list is
// already canonicalized, so installed and running store identical families.
func normalizeFamilies(families []string, errResponse error) ([]string, error) {
	normalized := make([]string, len(families))
	seen := make(map[string]struct{}, len(families))
	for index, value := range families {
		if !validMetadata(value) {
			return nil, errResponse
		}
		normalized[index] = strings.ToLower(value)
		if _, exists := seen[normalized[index]]; exists {
			return nil, errResponse
		}
		seen[normalized[index]] = struct{}{}
	}
	return normalized, nil
}

// formatTimestamp renders an observation time in the canonical UTC form shared
// by installed and running responses.
func formatTimestamp(value time.Time) string {
	return value.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
}
