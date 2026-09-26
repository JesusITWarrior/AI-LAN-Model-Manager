package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
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
	maximumProviderIDLength = 128
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

	providerIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	versionPattern    = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)
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
