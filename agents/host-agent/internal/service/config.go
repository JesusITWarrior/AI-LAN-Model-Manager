// Package service implements a bounded, persistent local host-service lifecycle
// with no network surface. The service owns a canonical absolute state tree
// (state/cert/cache/runtime), drives an injectable observer/provider registry,
// performs an initial observation followed by a cancellable periodic loop, and
// reports only safe, redacted startup/shutdown summaries.
//
// It intentionally performs no discovery, opens no listener, connects to no
// controller, and executes no arbitrary commands. Platform-specific behavior
// (canonical default paths and permission handling) is confined to build-tagged
// files so the platform-neutral logic here stays identical everywhere.
package service

import (
	"context"
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/observation"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/snapshot"
)

var (
	// ErrInvalidConfig is the stable redacted sentinel returned when any
	// configuration value is missing, duplicated, out of range, or otherwise
	// violates the allowlist. Callers must never surface internals; the value
	// alone is sufficient to diagnose a configuration problem.
	ErrInvalidConfig = errors.New("invalid service configuration")

	// ErrStateContainment is the stable redacted sentinel returned when the
	// canonical state path escapes the permitted root, resolves through a
	// symlink, or cannot be created under the required permissions.
	ErrStateContainment = errors.New("state path failed containment")
)

// PollIntervalDefault is applied when Config.PollInterval is unset. The
// configured interval is bounded to [PollIntervalMin, PollIntervalMax].
const (
	PollIntervalDefault = 30 * time.Second
	PollIntervalMin     = 10 * time.Millisecond
	PollIntervalMax     = 30 * time.Minute
)

// Config is the strict allowlist of values the service accepts. Every field is
// validated; New applies the defaults (a bounded PollInterval, and CertDir and
// CacheDir derived beneath the canonical absolute StateDir). HostID must follow
// the shared host id grammar. StateDir resolves to the platform canonical path
// (or an explicitly allowed, contained absolute path). Registry must contain at
// least one observer.
type Config struct {
	HostID             string
	StateDir           string
	CertDir            string
	CacheDir           string
	Registry           ProviderRegistry
	PollInterval       time.Duration
	Observations       int
	InitialObservation *bool
	Output             chan ObservationRecord
	Log                OutputLogger
	SnapshotStore      SnapshotStore
}

// SnapshotStore is the injected durable-state boundary. Implementations must
// preserve the previous committed state when Save fails before its commit.
type SnapshotStore interface {
	Load(context.Context) (snapshot.State, error)
	Save(context.Context, snapshot.State) error
}

// ProviderRegistry is an injectable collection of observation sources and local
// runtime providers. The service never opens a network listener or connects to
// a controller; it only drives these sources and records local observations.
type ProviderRegistry struct {
	Observers []observation.Observer
	Runtime   []LocalProvider
}

// LocalProvider is a provider whose state may be probed without a network
// listener. Implementations must not start a listener or initiate a controller
// connection.
type LocalProvider interface {
	Kind() provider.Kind
	Health(context.Context) (provider.Health, error)
}

// ObservationRecord is the normalized, service-local summary of one observation
// pass. Err carries the underlying cause (it may contain provider internals);
// SafeErr is the stable, redacted representation written to logs and persisted.
type ObservationRecord struct {
	HostID        string
	Platform      string
	NAccelerators int
	ObservedAt    string
	Err           error
	SafeErr       string

	ProvidersHealthy int
	ProvidersFailed  int
}

// OutputLogger writes a single safe/redacted log entry. Implementations decide
// where to write (stdout, a file); the service only ever emits safe data.
type OutputLogger func(LogEntry)

// LogEntry is one safe/redacted runtime telemetry record. Fields never contain
// provider internals, secrets, or filesystem internals.
type LogEntry struct {
	Level   string
	Message string
	Fields  map[string]any
}

// Logf is a convenience OutputLogger that formats a message and fields into a
// LogEntry and writes it. A nil logger is a no-op.
func Logf(message string, fields map[string]any) LogEntry {
	return LogEntry{Level: "info", Message: message, Fields: fields}
}

// resolved is the validated, default-applied configuration produced by sanitize.
type resolved struct {
	HostID             string
	StateDir           string
	CertDir            string
	CacheDir           string
	RuntimeDir         string
	Registry           ProviderRegistry
	PollInterval       time.Duration
	Observations       int
	InitialObservation bool
	Output             chan ObservationRecord
	Log                OutputLogger
	SnapshotStore      SnapshotStore
}

// New validates and sanitizes cfg, resolving a canonical absolute state tree
// (state/cert/cache/runtime) under StateDir with restrictive permissions where
// supported and rejecting any symlink escape. It returns ErrInvalidConfig or
// ErrStateContainment on the first problem.
func New(cfg Config) (*Service, error) {
	normalized, err := cfg.sanitize()
	if err != nil {
		return nil, err
	}
	if err := ensureContainment(normalized.StateDir); err != nil {
		return nil, ErrStateContainment
	}
	if err := ensureContainment(normalized.CertDir); err != nil {
		return nil, ErrStateContainment
	}
	if err := ensureContainment(normalized.CacheDir); err != nil {
		return nil, ErrStateContainment
	}
	if err := ensureContainment(normalized.RuntimeDir); err != nil {
		return nil, ErrStateContainment
	}
	service := &Service{cfg: normalized}
	loaded, loadErr := normalized.SnapshotStore.Load(context.Background())
	switch {
	case loadErr == nil && loaded.Valid():
		loaded.Fresh = false
		service.latest = loaded
		service.hasLatest = true
	case loadErr == nil:
		return nil, ErrInvalidConfig
	case errors.Is(loadErr, snapshot.ErrNotFound), errors.Is(loadErr, snapshot.ErrCorrupt):
		// First start and quarantined corruption both continue without replay.
	default:
		return nil, ErrInvalidConfig
	}
	return service, nil
}

// sanitize validates and defaults every Config field, resolving platform
// canonical paths. It never performs filesystem side effects.
func (c Config) sanitize() (resolved, error) {
	var out resolved
	if !validHostID(c.HostID) {
		return out, ErrInvalidConfig
	}
	out.HostID = c.HostID

	if len(c.Registry.Observers) < 1 {
		return out, ErrInvalidConfig
	}
	for _, observer := range c.Registry.Observers {
		if observer == nil {
			return out, ErrInvalidConfig
		}
	}
	out.Registry = c.Registry

	stateRoot, err := resolveStateRoot(c.StateDir)
	if err != nil {
		return out, err
	}
	out.StateDir = stateRoot

	if c.CertDir != "" {
		certDir, err := containedPath(stateRoot, c.CertDir)
		if err != nil {
			return out, err
		}
		out.CertDir = certDir
	} else {
		out.CertDir = filepath.Join(stateRoot, "cert")
	}

	if c.CacheDir != "" {
		cacheDir, err := containedPath(stateRoot, c.CacheDir)
		if err != nil {
			return out, err
		}
		out.CacheDir = cacheDir
	} else {
		out.CacheDir = filepath.Join(stateRoot, "cache")
	}

	out.RuntimeDir = filepath.Join(stateRoot, "state")
	if c.SnapshotStore != nil {
		out.SnapshotStore = c.SnapshotStore
	} else {
		out.SnapshotStore = snapshot.FileStore{Dir: filepath.Join(out.RuntimeDir, "snapshot")}
	}

	switch {
	case c.PollInterval == 0:
		out.PollInterval = PollIntervalDefault
	case c.PollInterval < 0:
		return out, ErrInvalidConfig
	case c.PollInterval < PollIntervalMin || c.PollInterval > PollIntervalMax:
		return out, ErrInvalidConfig
	default:
		out.PollInterval = c.PollInterval
	}

	if c.Observations < 0 {
		return out, ErrInvalidConfig
	} else {
		out.Observations = c.Observations
	}

	if c.InitialObservation != nil {
		out.InitialObservation = *c.InitialObservation
	} else {
		out.InitialObservation = true
	}

	out.Output = c.Output
	if c.Log != nil {
		out.Log = c.Log
	}

	return out, nil
}

// resolveStateRoot returns the platform canonical absolute state directory when
// StateDir is empty, otherwise validates the explicit absolute path.
func validHostID(value string) bool {
	return hostIDPattern.MatchString(value)
}

func withinRoot(root, p string) bool {
	if p == root {
		return true
	}
	return strings.HasPrefix(p, root+string(filepath.Separator))
}

var hostIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func resolveStateRoot(explicit string) (string, error) {
	if explicit == "" {
		return platformDefaultStateDir(), nil
	}
	return canonicalize(explicit)
}

// canonicalize requires an absolute, already-canonical path with no ".." and
// rejects whitespace-padded input.
func canonicalize(explicit string) (string, error) {
	if strings.TrimSpace(explicit) != explicit || strings.Contains(explicit, "..") || !filepath.IsAbs(explicit) || filepath.Clean(explicit) != explicit {
		return "", ErrInvalidConfig
	}
	abs, err := filepath.Abs(explicit)
	if err != nil {
		return "", ErrInvalidConfig
	}
	clean := filepath.Clean(abs)
	if !filepath.IsAbs(clean) || strings.Contains(clean, "..") {
		return "", ErrInvalidConfig
	}
	return clean, nil
}

// containedPath requires that p is an absolute path that does not escape root.
func containedPath(root, p string) (string, error) {
	if strings.TrimSpace(p) != p || strings.Contains(p, "..") {
		return "", ErrInvalidConfig
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", ErrInvalidConfig
	}
	if !withinRoot(root, abs) {
		return "", ErrInvalidConfig
	}
	return abs, nil
}

// HostID returns the validated, canonical host identifier bound to this
// service.
func (s *Service) HostID() string { return s.cfg.HostID }

// StateDirs returns the resolved canonical absolute sub-paths the service owns.
func (s *Service) StateDirs() (state, cert, cache, runtime string) {
	return s.cfg.StateDir, s.cfg.CertDir, s.cfg.CacheDir, s.cfg.RuntimeDir
}
