package main

import (
	"encoding/json"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/fleet"
)

type commandPhase struct {
	Stage      fleet.CommandStage `json:"stage"`
	HTTPStatus int                `json:"httpStatus"`
	At         string             `json:"at"`
	Stream     bool               `json:"stream"`
}
type commandExecution struct {
	commandPhase
	Outcome    fleet.CommandOutcome    `json:"outcome"`
	ErrorClass fleet.CommandErrorClass `json:"errorClass"`
}
type commandPending struct {
	Present             bool   `json:"present"`
	InFlight            bool   `json:"inFlight"`
	CompletionAvailable bool   `json:"completionAvailable"`
	Expired             bool   `json:"expired"`
	Uncertain           bool   `json:"uncertain"`
	Stream              bool   `json:"stream"`
	HoldReason          string `json:"holdReason"`
}
type commandDelivery struct {
	commandPhase
	Attempts uint64 `json:"attempts"`
}
type commandStatus struct {
	SchemaVersion            int                      `json:"schemaVersion"`
	ObservedAt               string                   `json:"observedAt"`
	Session                  fleet.CommandStage       `json:"session"`
	Poll                     commandPhase             `json:"poll"`
	Execution                commandExecution         `json:"execution"`
	Pending                  commandPending           `json:"pending"`
	Persistence              fleet.CommandPersistence `json:"persistence"`
	Delivery                 commandDelivery          `json:"delivery"`
	LastResultFailure        commandPhase             `json:"lastResultFailure"`
	LastResultAcknowledgedAt string                   `json:"lastResultAcknowledgedAt"`
}

// One lifetime reporter, independent of session clients and authoritative runner
// state. No status file is ever read. Failed saves retain only the latest state.
type commandReporter struct {
	mu                              sync.Mutex
	stateDir                        string
	now                             func() time.Time
	save                            func(string, string, []byte) error
	warn                            func(string)
	status                          commandStatus
	initialized, dirty, unavailable bool
	lastNow, lastWrite              time.Time
}

func newCommandReporter(stateDir string) *commandReporter {
	r := &commandReporter{stateDir: stateDir}
	// Replace stale prior-lifetime diagnostics before starting workers.
	_ = r.record(fleet.CommandEvent{Domain: fleet.DomainSession, Stage: fleet.StagePaused})
	return r
}

func boundedCommandTime(t time.Time) time.Time {
	t = t.UTC()
	if t.Year() < 2000 {
		return time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	if t.Year() > 9999 {
		return time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	}
	return t
}
func commandFailure(s fleet.CommandStage) bool {
	switch s {
	case fleet.StageSequence, fleet.StageEnvelope, fleet.StageTransport, fleet.StageHTTP, fleet.StageCodec, fleet.StageACKInvalid, fleet.StageStreamFailed:
		return true
	}
	return false
}
func (r *commandReporter) record(event fleet.CommandEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := event.Sanitize()
	clock := r.now
	if clock == nil {
		clock = time.Now
	}
	now := boundedCommandTime(clock())
	if now.Before(r.lastNow) {
		now = r.lastNow
	}
	r.lastNow = now
	at := now.Format(time.RFC3339Nano)
	if !r.initialized {
		r.status = commandStatus{SchemaVersion: 1, Session: fleet.StageUnknown, Persistence: fleet.PersistenceNotObserved, Poll: commandPhase{Stage: fleet.StageUnknown}, Delivery: commandDelivery{commandPhase: commandPhase{Stage: fleet.StageUnknown}}, LastResultFailure: commandPhase{Stage: fleet.StageUnknown}, Pending: commandPending{HoldReason: "none"}, Execution: commandExecution{commandPhase: commandPhase{Stage: fleet.StageUnknown}, Outcome: fleet.OutcomeUnknown, ErrorClass: fleet.ErrorNone}}
		r.initialized, r.dirty = true, true
	}
	phase := commandPhase{Stage: e.Stage, HTTPStatus: e.HTTPStatus, At: at, Stream: e.Stream}
	changed := false
	switch e.Domain {
	case fleet.DomainSession:
		changed = r.status.Session != e.Stage
		r.status.Session = e.Stage
	case fleet.DomainPoll:
		changed = r.status.Poll.Stage != e.Stage || r.status.Poll.HTTPStatus != e.HTTPStatus
		r.status.Poll = phase
	case fleet.DomainExecution:
		changed = true
		r.status.Execution = commandExecution{commandPhase: phase, Outcome: e.Outcome, ErrorClass: e.ErrorClass}
		if e.Stage == fleet.StageEntered {
			r.status.Execution.Outcome = fleet.OutcomeRunning
			r.status.Pending = commandPending{InFlight: true, Stream: e.Stream, HoldReason: "execution"}
		} else if e.Stage == fleet.StageCompleted {
			if e.Persistence == fleet.PersistenceUncertain {
				r.status.Persistence = fleet.PersistenceUncertain
			} else if r.status.Persistence != fleet.PersistenceUncertain {
				r.status.Persistence = e.Persistence
			}
		}
	case fleet.DomainPending:
		changed = true
		p := &r.status.Pending
		switch e.Stage {
		case fleet.StageCaptured:
			p.Present, p.InFlight, p.CompletionAvailable, p.Stream, p.HoldReason = true, false, true, e.Stream, "awaiting_ack"
		case fleet.StageExpired:
			p.Expired = true
		case fleet.StageUncertain:
			p.Uncertain, p.HoldReason, r.status.Persistence = true, "persistence_uncertain", fleet.PersistenceUncertain
		case fleet.StageReleased:
			*p = commandPending{HoldReason: "none"}
			if e.Acknowledged {
				r.status.LastResultAcknowledgedAt = at
			}
		default:
			changed = false
		}
	case fleet.DomainDelivery:
		r.status.Delivery.commandPhase = phase
		if e.Stage == fleet.StageSendStarted {
			if r.status.Delivery.Attempts < math.MaxUint64 {
				r.status.Delivery.Attempts++
			}
			n := r.status.Delivery.Attempts
			changed = n == 1 || n&(n-1) == 0
		} else if commandFailure(e.Stage) {
			prior := r.status.LastResultFailure
			changed = prior.Stage != e.Stage || prior.HTTPStatus != e.HTTPStatus || prior.Stream != e.Stream
			r.status.LastResultFailure = phase
		} else if e.Stage == fleet.StageACKValidated {
			changed = true
		}
	}
	r.status.ObservedAt = at
	// Even throttled events refresh the latest in-memory snapshot; a due
	// write must not lose the non-milestone terminal stage behind send_started.
	r.dirty = true
	// Retry failed storage at most once/minute, even for critical events. Healthy
	// unchanged state is also bounded to one latest snapshot/minute, not per poll.
	due := r.lastWrite.IsZero() || now.Sub(r.lastWrite) >= time.Minute
	if !r.dirty || (r.unavailable && !due) || (!changed && !due) {
		return nil
	}
	raw, err := json.Marshal(r.status)
	save := r.save
	if save == nil {
		save = saveDiagnostic
	}
	r.lastWrite = now
	if err == nil {
		err = save(r.stateDir, "command-status.json", raw)
	}
	warn := r.warn
	if warn == nil {
		warn = func(message string) { slog.Warn(message) }
	}
	if err != nil {
		if !r.unavailable {
			warn("host service command diagnostic unavailable")
		}
		r.unavailable = true
		return nil // Diagnostic availability never affects command semantics.
	}
	if r.unavailable {
		warn("host service command diagnostic recovered")
	}
	r.unavailable, r.dirty = false, false
	return nil
}
