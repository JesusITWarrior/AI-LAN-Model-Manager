// Package provider holds the provider-neutral types and helpers shared by every
// model runtime adapter (Ollama, LM Studio). It exposes no transport of its own;
// each adapter builds its own client against these shared contracts.
package provider

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// KindLMStudio identifies the LM Studio (OpenAI-compatible) adapter.
const KindLMStudio Kind = "lmstudio"

// MaximumProviderIDLength bounds the provider identifier length.
const MaximumProviderIDLength = 128

// providerIDPattern is the shared provider id grammar: a 1..128 byte ASCII
// identifier that starts with an alphanumeric byte; later bytes may also be
// '.', '_', ':', or '-'.
var providerIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// DefaultTimeout is the production client timeout when a config omits one. It
// lies within the shared 100ms..30s bounds.
const DefaultTimeout = 5 * time.Second

// MinimumTimeout and MaximumTimeout bound a configured timeout.
const (
	MinimumTimeout = 100 * time.Millisecond
	MaximumTimeout = 30 * time.Second
)

// ErrInvalidProviderID is returned when a provider id violates the grammar.
var ErrInvalidProviderID = errors.New("invalid provider id")

// ErrInvalidEndpoint is returned when an endpoint is not a normalized HTTP(S) origin.
var ErrInvalidEndpoint = errors.New("invalid endpoint")

// ValidateProviderID reports whether raw follows the shared provider id grammar:
// a 1..128 byte ASCII string that starts with an alphanumeric byte and whose
// later bytes are limited to '_', '.', ':', and '-'.
func ValidateProviderID(raw string) bool {
	return len(raw) > 0 && len(raw) <= MaximumProviderIDLength && providerIDPattern.MatchString(raw)
}

// HTTPDoer permits deterministic tests without a network listener.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Clock permits deterministic observation timestamps.
type Clock interface {
	Now() time.Time
}

// SystemClock is the production clock.
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }

// NoRedirectDoer returns an HTTP client transport that never follows redirects,
// so a 3xx response is reported as the terminal status instead of being followed.
func NoRedirectDoer() HTTPDoer {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// NormalizeEndpoint validates an HTTP(S) origin and returns it with any optional
// root slash removed. It rejects a non-empty input longer than 2048 bytes, any
// authentication, query, fragment, or non-root path, and any invalid port (0,
// negative, >65535, non-numeric, or a malformed IPv6 bracket).
func NormalizeEndpoint(raw string) (string, error) {
	if raw == "" || len(raw) > 2048 || strings.TrimSpace(raw) != raw || strings.Contains(raw, "#") {
		return "", ErrInvalidEndpoint
	}
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.Hostname() == "" {
		return "", ErrInvalidEndpoint
	}
	if !validHost(parsed.Host, parsed.Hostname()) || !validPort(parsed.Host) {
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

func validHost(host, hostname string) bool {
	if strings.HasPrefix(host, "[") {
		address := net.ParseIP(hostname)
		return address != nil && strings.Contains(hostname, ":")
	}
	if address := net.ParseIP(hostname); address != nil {
		return address.To4() != nil
	}
	// A dotted all-numeric value is an IPv4 literal, not a DNS hostname.
	if strings.IndexFunc(hostname, func(r rune) bool { return (r < '0' || r > '9') && r != '.' }) < 0 {
		return false
	}
	if len(hostname) == 0 || len(hostname) > 253 || strings.HasSuffix(hostname, ".") {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'A' || char > 'Z') && (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
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
