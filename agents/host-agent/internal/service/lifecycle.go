package service

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/enrollment"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/observation"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/snapshot"
)

// Service owns the bounded, persistent host-service lifecycle. It opens no
// listener; its only optional network action is one injected, bounded outbound enrollment flow.
//
// Its StateDir tree (canonical absolute, restrictive permissions where
// supported, symlink escapes rejected) contains:
//
//	state/cert    -> X509 identities and CA material (mode 0700 where possible)
//	state/cache   -> provider cache (mode 0700 where possible)
//	state/state   -> runtime state (mode 0700 where possible)
//
// A log file (host-service.log, mode 0600 where possible) records only
// safe/redacted runtime telemetry. No discovery, listener, or controller
// connection is performed; nothing leaves the host.
type Service struct {
	cfg resolved

	// mu guards the closed lifecycle state so Start/Stop/Close cannot race.
	mu        sync.Mutex
	cancel    context.CancelFunc
	done      chan struct{}
	started   bool
	closed    bool
	latest    snapshot.State
	hasLatest bool
}

// Start performs an initial observation (unless InitialObservation is false),
// records a safe/redacted summary, and then runs a cancellable periodic loop
// bounded by the configured interval until ctx is cancelled.
//
// Start returns nil once the initial pass has been recorded; the loop runs on
// a background goroutine and stops only when ctx is cancelled. It does not wait
// for the loop to exit. Because signal handling lives in main, the caller owns
// cancellation and the lifecycle.
//
// A run may not restart: a second Start call after the first has returned
// returns ErrInvalidConfig. See Close for permanent termination semantics.
func (s *Service) Start(ctx context.Context) error {
	// A run already started cannot restart.
	if !s.begin() {
		return ErrInvalidConfig
	}

	// An already-cancelled ctx is not a valid start.
	if err := ctx.Err(); err != nil {
		s.fail()
		return sanitize(err)
	}

	loopCtx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.cancel = cancel
	s.done = make(chan struct{})
	s.mu.Unlock()

	if s.cfg.Enroller != nil {
		outcome, err := s.cfg.Enroller.Enroll(loopCtx)
		if s.cfg.Log != nil {
			s.cfg.Log(EnrollmentSummary(outcome, err))
		}
	}

	if s.cfg.InitialObservation {
		record, err := s.runObservation(loopCtx)
		if s.cfg.Log != nil {
			s.cfg.Log(StartupSummary(record, err))
		}
		s.emit(loopCtx, record)
	}

	go s.loop(loopCtx)
	return nil
}

// Stop cancels the periodic loop and any in-flight observation pass, then waits
// for the loop goroutine to finish. It is idempotent: subsequent calls return
// nil and never block past the first cancellation. Stop does not release
// filesystem state.
func (s *Service) Stop(ctx context.Context) error {
	return s.Close(ctx)
}

// Close synchronously terminates the loop, waits for the in-flight pass to
// observe cancellation, and releases resources. After Close returns, the
// service is permanently terminated and cannot be restarted; subsequent
// Start calls return ErrInvalidConfig (Start re-validates the context, so a
// fresh, non-cancelled context is required for a new run).
func (s *Service) Close(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	cancel := s.cancel
	s.cancel = nil
	s.closed = true
	done := s.done
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// begin records that a run has started. It returns true on the first call;
// subsequent calls return false, preventing a run from restarting.
func (s *Service) begin() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.started {
		return false
	}
	s.started = true
	return true
}

// fail marks the current run as terminated (used when Start is rejected by an
// already-cancelled context).
func (s *Service) fail() {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	s.closed = true
	s.mu.Unlock()
}

// runObservation performs one observation pass, counting local provider health
// and recording the first successful observation. It never panics.
func (s *Service) runObservation(ctx context.Context) (ObservationRecord, error) {
	record := ObservationRecord{HostID: s.cfg.HostID}

	var firstErr error
	for _, observer := range s.cfg.Registry.Observers {
		if err := ctx.Err(); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			if s.cfg.Log != nil {
				s.cfg.Log(ObservationFailureSummary(observer, err))
			}
			continue
		}
		data, err := observer.Observe(ctx)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			if s.cfg.Log != nil {
				s.cfg.Log(ObservationFailureSummary(observer, err))
			}
			continue
		}
		if s.cfg.Log != nil {
			s.cfg.Log(ObservationSummary(data))
		}
		if record.NAccelerators == 0 {
			record.Platform = string(data.Platform)
			record.NAccelerators = len(data.Accelerators)
			record.ObservedAt = data.ObservedAt
		}
	}

	for _, localProvider := range s.cfg.Registry.Runtime {
		if err := ctx.Err(); err != nil {
			record.ProvidersFailed++
			if s.cfg.Log != nil {
				s.cfg.Log(LocalProviderFailureSummary(localProvider, err))
			}
			continue
		}
		health, err := localProvider.Health(ctx)
		if err != nil {
			record.ProvidersFailed++
			if s.cfg.Log != nil {
				s.cfg.Log(LocalProviderFailureSummary(localProvider, err))
			}
			continue
		}
		record.ProvidersHealthy++
		if s.cfg.Log != nil {
			s.cfg.Log(LocalProviderHealthSummary(localProvider, health))
		}
	}

	if record.SafeErr == "" {
		record.SafeErr = sanitizeStr(firstErr)
	}

	// Persist only a complete host observation. Provider failures are represented
	// solely by public counts; endpoints and provider-specific data never cross
	// the SnapshotStore boundary.
	if record.ObservedAt != "" && ctx.Err() == nil {
		state, stateErr := snapshot.New(snapshot.Record{
			HostID:           record.HostID,
			Platform:         record.Platform,
			NAccelerators:    record.NAccelerators,
			ObservedAt:       record.ObservedAt,
			SafeErr:          record.SafeErr,
			ProvidersHealthy: record.ProvidersHealthy,
			ProvidersFailed:  record.ProvidersFailed,
		}, time.Now())
		if stateErr == nil {
			stateErr = s.cfg.SnapshotStore.Save(ctx, state)
		}
		if stateErr == nil {
			s.mu.Lock()
			s.latest = state
			s.hasLatest = true
			s.mu.Unlock()
		} else if firstErr == nil {
			firstErr = stateErr
			record.SafeErr = sanitizeStr(stateErr)
		}
	}

	record.Err = firstErr
	return record, sanitize(firstErr)
}

// LatestSnapshot returns an isolated copy of the latest validated snapshot.
// A state loaded during New has Fresh=false; one saved by this process has
// Fresh=true. The boolean is false when no trustworthy state exists.
func (s *Service) LatestSnapshot() (snapshot.State, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.hasLatest {
		return snapshot.State{}, false
	}
	return s.latest, true
}

// loop performs repeated observation passes until the loop context is cancelled.
// It exits cleanly when the context is done and never blocks cancellation.
func (s *Service) loop(ctx context.Context) {
	defer close(s.done)
	timer := time.NewTimer(s.cfg.PollInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			record, err := s.runObservation(ctx)
			s.emit(ctx, record)
			if s.cfg.Log != nil {
				s.cfg.Log(LoopSummary(record, err))
			}
			timer.Reset(s.cfg.PollInterval)
		}
	}
}

func (s *Service) emit(ctx context.Context, record ObservationRecord) {
	if s.cfg.Output == nil {
		return
	}
	select {
	case s.cfg.Output <- record:
	case <-ctx.Done():
	default:
	}
}

// EnrollmentSummary reports only a stable allowlisted status. In particular it
// never emits the operator code, controller address, certificate, or error.
func EnrollmentSummary(outcome enrollment.Outcome, err error) LogEntry {
	status := enrollment.StatusDegraded
	if err == nil && outcome.Status == enrollment.StatusEnrolled {
		status = enrollment.StatusEnrolled
	}
	return LogEntry{
		Level:   "info",
		Message: "host service enrollment complete",
		Fields:  map[string]any{"status": status},
	}
}

// StartupSummary is the safe/redacted summary recorded on Start. It never
// contains provider internals, secrets, or filesystem internals.
func StartupSummary(record ObservationRecord, _ error) LogEntry {
	return LogEntry{
		Level:   "info",
		Message: "host service started",
		Fields: map[string]any{
			"hostID":           record.HostID,
			"safeErr":          firstSafe(record.SafeErr),
			"accelerators":     record.NAccelerators,
			"providersHealthy": record.ProvidersHealthy,
			"providersFailed":  record.ProvidersFailed,
		},
	}
}

// LoopSummary is the safe/redacted summary recorded on each periodic pass.
func LoopSummary(record ObservationRecord, _ error) LogEntry {
	return LogEntry{
		Level:   "info",
		Message: "host service loop complete",
		Fields: map[string]any{
			"hostID":           record.HostID,
			"safeErr":          firstSafe(record.SafeErr),
			"accelerators":     record.NAccelerators,
			"providersHealthy": record.ProvidersHealthy,
			"providersFailed":  record.ProvidersFailed,
		},
	}
}

// ShutdownSummary is the safe/redacted summary recorded on Close.
func ShutdownSummary(record ObservationRecord) LogEntry {
	return LogEntry{
		Level:   "info",
		Message: "host service shutting down",
		Fields: map[string]any{
			"hostID": record.HostID,
		},
	}
}

// Summary is the safe/redacted summary recorded for one observation pass.
func Summary(record ObservationRecord) LogEntry {
	return LogEntry{
		Level:   "info",
		Message: "host service observation complete",
		Fields: map[string]any{
			"hostID":           record.HostID,
			"safeErr":          firstSafe(record.SafeErr),
			"accelerators":     record.NAccelerators,
			"providersHealthy": record.ProvidersHealthy,
			"providersFailed":  record.ProvidersFailed,
		},
	}
}

// ObservationFailureSummary is the safe/redacted summary for an observer failure.
func ObservationFailureSummary(observer observation.Observer, err error) LogEntry {
	return LogEntry{
		Level:   "warn",
		Message: "host service observation failed",
		Fields: map[string]any{
			"safeErr": sanitizeStr(err),
		},
	}
}

// LocalProviderFailureSummary is the safe/redacted summary for a provider health
// probe failure.
func LocalProviderFailureSummary(localProvider LocalProvider, err error) LogEntry {
	return LogEntry{
		Level:   "warn",
		Message: "host service local provider probe failed",
		Fields: map[string]any{
			"safeErr": sanitizeStr(err),
		},
	}
}

// LocalProviderHealthSummary is the safe/redacted summary for a successful
// provider health probe.
func LocalProviderHealthSummary(localProvider LocalProvider, health provider.Health) LogEntry {
	return LogEntry{
		Level:   "info",
		Message: "host service local provider healthy",
		Fields: map[string]any{
			"provider": string(localProvider.Kind()),
			"health":   string(health),
		},
	}
}

// ObservationSummary is the safe/redacted summary for a successful observation.
func ObservationSummary(data observation.HostResourceObservation) LogEntry {
	return LogEntry{
		Level:   "info",
		Message: "host service observation",
		Fields: map[string]any{
			"hostID":       data.HostID,
			"platform":     string(data.Platform),
			"accelerators": len(data.Accelerators),
		},
	}
}

// firstSafe reports the recorded safe error, or "no error" when the pass had
// none.
func firstSafe(value string) string {
	if value == "" {
		return "no error"
	}
	return value
}

// sanitize maps a lifecycle context error to a stable redacted sentinel while
// leaving provider-specific internals intact as their own wrapped cause.
func sanitize(value error) error {
	if value == nil {
		return nil
	}
	return sanitizeError(value)
}

// sanitizeStr returns the stable redacted string for a lifecycle error, or
// "no error" when value is nil. Provider internals are never surfaced.
func sanitizeStr(value error) string {
	if value == nil {
		return "no error"
	}
	switch value {
	case context.Canceled:
		return "request cancelled"
	case context.DeadlineExceeded:
		return "operation timed out"
	default:
		return "internal error"
	}
}

// sanitizeError maps a lifecycle context error to a stable redacted sentinel
// while leaving provider-specific internals (which must never be surfaced)
// intact as their own wrapped cause.
func sanitizeError(value error) error {
	switch value {
	case context.Canceled:
		return ErrInvalidConfig
	case context.DeadlineExceeded:
		return ErrStateContainment
	default:
		return value
	}
}

// platformDefaultStateDir returns the platform canonical absolute state directory.
func platformDefaultStateDir() string {
	switch runtime.GOOS {
	case "windows":
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, "LAN-Model-Manager", "host-agent", "state")
		}
		return filepath.Join(os.Getenv("USERPROFILE"), ".lan-model-manager", "host-agent", "state")
	case "darwin":
		if home := os.Getenv("HOME"); home != "" {
			return filepath.Join(home, "Library", "Application Support", "LAN-Model-Manager", "state")
		}
		return filepath.Join("~", "Library", "Application Support", "LAN-Model-Manager", "state")
	default:
		if xdgState := os.Getenv("XDG_STATE_HOME"); xdgState != "" {
			return filepath.Join(xdgState, "lan-model-manager", "state")
		}
		if home := os.Getenv("HOME"); home != "" {
			return filepath.Join(home, ".local", "state", "lan-model-manager", "state")
		}
		return filepath.Join(".", "data")
	}
}
