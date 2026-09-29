// Package enrollment implements the agent's bounded outbound enrollment flow.
//
// This slice authenticates a controller challenge with the existing pairing
// transcript and persists only controller-issued public material. It does not
// generate or persist a private key; CSR/private-key integration belongs to the
// certificate-issuance slice.
package enrollment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/pairing"
)

var (
	ErrInvalidConfig = errors.New("invalid enrollment configuration")
	ErrUnavailable   = errors.New("enrollment unavailable")
	ErrFailed        = errors.New("enrollment failed")
)

const (
	StatusLocalOnly = "local-only"
	StatusPending   = "pending"
	StatusEnrolled  = "enrolled"
	StatusDegraded  = "degraded"
)

var (
	idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	hex64     = regexp.MustCompile(`^[a-f0-9]{64}$`)
	codeRE    = regexp.MustCompile(`^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{8}$`)
)

// Config is the complete, strict trust and candidate binding for one client.
type Config struct {
	ControllerURL             string
	PinnedCAFingerprintSHA256 string
	CandidateID               string
	Address                   string
	Port                      uint16
	ProtocolMajor             uint16
	ProtocolMinor             uint16
	CertDir                   string
}

func (c Config) binding() (pairing.Binding, error) {
	if !validControllerURL(c.ControllerURL) || !hex64.MatchString(c.PinnedCAFingerprintSHA256) || !idPattern.MatchString(c.CandidateID) {
		return pairing.Binding{}, ErrInvalidConfig
	}
	ip := net.ParseIP(c.Address)
	if ip == nil || strings.Contains(c.Address, "%") || ip.String() != c.Address || c.Port == 0 || c.ProtocolMajor != 1 || strings.TrimSpace(c.CertDir) != c.CertDir || c.CertDir == "" || !filepath.IsAbs(c.CertDir) || filepath.Clean(c.CertDir) != c.CertDir || strings.Contains(c.CertDir, "..") {
		return pairing.Binding{}, ErrInvalidConfig
	}
	return pairing.Binding{CandidateID: c.CandidateID, Address: c.Address, Port: c.Port, ProtocolMajor: c.ProtocolMajor, ProtocolMinor: c.ProtocolMinor}, nil
}

func validControllerURL(raw string) bool {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || u.Path != "" {
		return false
	}
	if u.Hostname() == "" || strings.ToLower(u.Host) != u.Host || strings.HasSuffix(u.Host, ".") {
		return false
	}
	return u.String() == raw
}

// Challenge extends the shared pairing challenge with the controller trust
// binding and the one-time operator code. OperatorCode is consumed by Client
// and is blank in the value passed to Complete.
type Challenge struct {
	Pairing                   pairing.Challenge
	ControllerURL             string
	PinnedCAFingerprintSHA256 string
	OperatorCode              string
}

// Result is the public controller-issued enrollment record. CertificatePEM and
// CAPEM may contain certificates only, never private keys.
type Result struct {
	ControllerURL             string          `json:"controllerUrl"`
	PinnedCAFingerprintSHA256 string          `json:"pinnedCaFingerprintSha256"`
	ChallengeID               string          `json:"challengeId"`
	Binding                   pairing.Binding `json:"binding"`
	CertificatePEM            string          `json:"certificatePem,omitempty"`
	CAPEM                     string          `json:"caPem,omitempty"`
	EnrolledAt                time.Time       `json:"enrolledAt"`
}

// Outcome contains the stable status and, only on the successful network run,
// the one-time operator code. The code is never included in Result or Store.
type Outcome struct {
	Status       string
	OperatorCode string
	Result       Result
}

// Transport is the sole outbound network boundary.
type Transport interface {
	Begin(context.Context, pairing.Binding) (Challenge, error)
	Complete(context.Context, Challenge, pairing.Proof) (Result, error)
}

// Store persists public enrollment state atomically.
type Store interface {
	Load(context.Context) (Result, error)
	Save(context.Context, Result) error
}

type Client struct {
	mu        sync.Mutex
	cfg       Config
	binding   pairing.Binding
	transport Transport
	store     Store
	now       func() time.Time
	enrolled  *Result
	consumed  bool
	pending   *Challenge
	session   *pairing.Session
}

func New(cfg Config, transport Transport, store Store) (*Client, error) {
	binding, err := cfg.binding()
	if err != nil {
		return nil, ErrInvalidConfig
	}
	if store == nil {
		store = FileStore{CertDir: cfg.CertDir}
	}
	c := &Client{cfg: cfg, binding: binding, transport: transport, store: store, now: time.Now}
	result, loadErr := store.Load(context.Background())
	switch {
	case loadErr == nil:
		if !c.validResult(result, "") {
			return nil, ErrUnavailable
		}
		c.enrolled = &result
	case errors.Is(loadErr, ErrNotFound), errors.Is(loadErr, ErrCorrupt):
		if transport == nil {
			return nil, ErrInvalidConfig
		}
	default:
		return nil, ErrUnavailable
	}
	return c, nil
}

// Status reports durable enrollment without making a network request.
func (c *Client) Status() Outcome {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.enrolled == nil {
		return Outcome{Status: StatusPending}
	}
	return Outcome{Status: StatusEnrolled, Result: *c.enrolled}
}

// Begin requests and validates one challenge and returns its operator code.
// The code can be obtained only once and is retained only inside the in-memory
// pairing session until Complete consumes it.
func (c *Client) Begin(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.enrolled != nil || c.consumed || c.pending != nil || ctx.Err() != nil {
		return "", ErrUnavailable
	}
	c.consumed = true
	challenge, err := c.transport.Begin(ctx, c.binding)
	if err != nil || ctx.Err() != nil || !c.validChallenge(challenge) {
		return "", ErrFailed
	}
	session, err := pairing.NewSession(challenge.Pairing, []byte(challenge.OperatorCode), func(string) error { return nil })
	if err != nil {
		return "", ErrFailed
	}
	code := challenge.OperatorCode
	challenge.OperatorCode = ""
	c.pending = &challenge
	c.session = session
	return code, nil
}

// Complete consumes the pending challenge. Cancellation, expiry, transport
// failure, and replay all leave the client unable to reuse that challenge.
func (c *Client) Complete(ctx context.Context) (Outcome, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.enrolled != nil {
		return Outcome{Status: StatusEnrolled, Result: *c.enrolled}, nil
	}
	if c.pending == nil || c.session == nil || ctx.Err() != nil {
		c.pending, c.session = nil, nil
		return Outcome{Status: StatusDegraded}, ErrUnavailable
	}
	challenge, session := *c.pending, c.session
	c.pending, c.session = nil, nil
	proof, err := session.BuildProof(c.now())
	if err != nil || ctx.Err() != nil {
		return Outcome{Status: StatusDegraded}, ErrFailed
	}
	result, err := c.transport.Complete(ctx, challenge, proof)
	if err != nil || ctx.Err() != nil || !c.validResult(result, challenge.Pairing.ChallengeID) {
		return Outcome{Status: StatusDegraded}, ErrFailed
	}
	if err := c.store.Save(ctx, result); err != nil {
		return Outcome{Status: StatusDegraded}, ErrFailed
	}
	c.enrolled = &result
	return Outcome{Status: StatusEnrolled, Result: result}, nil
}

// Enroll is the service integration's run-once convenience operation. Callers
// that need an operator pause use Begin and Complete directly.
func (c *Client) Enroll(ctx context.Context) (Outcome, error) {
	if status := c.Status(); status.Status == StatusEnrolled {
		return status, nil
	}
	code, err := c.Begin(ctx)
	if err != nil {
		return Outcome{Status: StatusDegraded}, err
	}
	outcome, err := c.Complete(ctx)
	if err == nil {
		outcome.OperatorCode = code
	}
	return outcome, err
}

func (c *Client) validChallenge(ch Challenge) bool {
	return ch.ControllerURL == c.cfg.ControllerURL && ch.PinnedCAFingerprintSHA256 == c.cfg.PinnedCAFingerprintSHA256 && ch.Pairing.Binding == c.binding && codeRE.MatchString(ch.OperatorCode) && c.now().Before(ch.Pairing.ExpiresAt)
}

func (c *Client) validResult(r Result, challengeID string) bool {
	return validStoredResult(r) && r.ControllerURL == c.cfg.ControllerURL && r.PinnedCAFingerprintSHA256 == c.cfg.PinnedCAFingerprintSHA256 && r.Binding == c.binding && (challengeID == "" || r.ChallengeID == challengeID)
}

func validStoredResult(r Result) bool {
	ip := net.ParseIP(r.Binding.Address)
	return validControllerURL(r.ControllerURL) && hex64.MatchString(r.PinnedCAFingerprintSHA256) && hex64.MatchString(r.ChallengeID) && idPattern.MatchString(r.Binding.CandidateID) && ip != nil && !strings.Contains(r.Binding.Address, "%") && ip.String() == r.Binding.Address && r.Binding.Port > 0 && r.Binding.ProtocolMajor == 1 && !r.EnrolledAt.IsZero() && publicPEM(r.CertificatePEM) && publicPEM(r.CAPEM) && caMatchesPin(r.CAPEM, r.PinnedCAFingerprintSHA256)
}

func caMatchesPin(value, pin string) bool {
	if value == "" {
		return true
	}
	block, _ := pem.Decode([]byte(value))
	return block != nil && FingerprintSHA256(block.Bytes) == pin
}

func publicPEM(value string) bool {
	if value == "" {
		return true
	}
	rest := []byte(value)
	seen := false
	for len(rest) > 0 {
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return false
		}
		seen = true
		rest = next
	}
	return seen
}

// FingerprintSHA256 returns the normalized pin for DER certificate bytes.
func FingerprintSHA256(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
