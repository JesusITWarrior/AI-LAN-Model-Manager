package fleet

// Command diagnostics carry only fixed classifications, never command or wire
// data. Install sinks before starting workers; do not mutate them while running.
type CommandDomain string
type CommandStage string
type CommandOutcome string
type CommandErrorClass string
type CommandPersistence string

const (
	DomainSession   CommandDomain = "session"
	DomainPoll      CommandDomain = "poll"
	DomainExecution CommandDomain = "execution"
	DomainPending   CommandDomain = "pending"
	DomainDelivery  CommandDomain = "delivery"

	StageUnknown            CommandStage = "unknown"
	StageStarted            CommandStage = "started"
	StagePaused             CommandStage = "paused"
	StageHandoffWaiting     CommandStage = "handoff_waiting"
	StageUnavailable        CommandStage = "executor_unavailable"
	StageSequence           CommandStage = "sequence_failed"
	StageEnvelope           CommandStage = "envelope_failed"
	StageTransport          CommandStage = "transport_failed"
	StageHTTP               CommandStage = "http_rejected"
	StageCodec              CommandStage = "codec_failed"
	StageCertificate        CommandStage = "certificate_failed"
	StageSignature          CommandStage = "signature_failed"
	StageClock              CommandStage = "clock_failed"
	StagePayload            CommandStage = "payload_failed"
	StageControllerSequence CommandStage = "controller_sequence_failed"
	StageVerified           CommandStage = "verified"
	StageEntered            CommandStage = "entered"
	StageCompleted          CommandStage = "completed"
	StageCaptured           CommandStage = "captured"
	StageExpired            CommandStage = "expired"
	StageUncertain          CommandStage = "uncertain"
	StageReleased           CommandStage = "released"
	StageSendStarted        CommandStage = "send_started"
	StageACKInvalid         CommandStage = "ack_invalid"
	StageStreamFailed       CommandStage = "stream_send_failed"
	StageACKValidated       CommandStage = "ack_validated"

	OutcomeUnknown         CommandOutcome     = "unknown"
	OutcomeRunning         CommandOutcome     = "running"
	OutcomeSucceeded       CommandOutcome     = "succeeded"
	OutcomeFailed          CommandOutcome     = "failed"
	OutcomeCancelled       CommandOutcome     = "cancelled"
	ErrorNone              CommandErrorClass  = "none"
	ErrorAdapter           CommandErrorClass  = "adapter_failed"
	ErrorRejected          CommandErrorClass  = "command_rejected"
	ErrorIndeterminate     CommandErrorClass  = "indeterminate"
	ErrorOther             CommandErrorClass  = "other"
	PersistenceNotObserved CommandPersistence = "not_observed"
	PersistenceNoFailure   CommandPersistence = "no_failure_observed"
	PersistenceUncertain   CommandPersistence = "uncertain"
)

type CommandEvent struct {
	Domain      CommandDomain
	Stage       CommandStage
	HTTPStatus  int
	Outcome     CommandOutcome
	ErrorClass  CommandErrorClass
	Persistence CommandPersistence
	Stream      bool
	// Acknowledged is set only at the runner's existing successful release branch.
	Acknowledged bool
}

type CommandSink func(CommandEvent) error

// Sanitize also protects consumers from explicitly cast, untrusted enum values.
func (e CommandEvent) Sanitize() CommandEvent {
	switch e.Domain {
	case DomainSession, DomainPoll, DomainExecution, DomainPending, DomainDelivery:
	default:
		e.Domain = "unknown"
	}
	switch e.Stage {
	case StageStarted, StagePaused, StageHandoffWaiting, StageUnavailable, StageSequence, StageEnvelope, StageTransport, StageHTTP, StageCodec, StageCertificate, StageSignature, StageClock, StagePayload, StageControllerSequence, StageVerified, StageEntered, StageCompleted, StageCaptured, StageExpired, StageUncertain, StageReleased, StageSendStarted, StageACKInvalid, StageACKValidated, StageStreamFailed:
	default:
		e.Stage = StageUnknown
	}
	if e.HTTPStatus < 100 || e.HTTPStatus > 599 {
		e.HTTPStatus = 0
	}
	switch e.Outcome {
	case OutcomeRunning, OutcomeSucceeded, OutcomeFailed, OutcomeCancelled:
	default:
		e.Outcome = OutcomeUnknown
	}
	switch e.ErrorClass {
	case ErrorNone, ErrorAdapter, ErrorRejected, ErrorIndeterminate:
	default:
		e.ErrorClass = ErrorOther
	}
	switch e.Persistence {
	case PersistenceNoFailure, PersistenceUncertain:
	default:
		e.Persistence = PersistenceNotObserved
	}
	if e.Domain != DomainPending || e.Stage != StageReleased {
		e.Acknowledged = false
	}
	return e
}

// Diagnostics cannot change admission, result or release semantics, even when a
// custom sink fails or panics. No client/executor lock is held during emission.
func EmitCommandEvent(sink CommandSink, e CommandEvent) {
	if sink == nil {
		return
	}
	defer func() { _ = recover() }()
	_ = sink(e.Sanitize())
}

func (c *HTTPSClient) SetCommandSink(sink CommandSink) { c.commandSink = sink }
func (c *HTTPSClient) commandEvent(domain CommandDomain, stage CommandStage, status int) {
	EmitCommandEvent(c.commandSink, CommandEvent{Domain: domain, Stage: stage, HTTPStatus: status})
}
func (r *CommandRunner) SetCommandSink(sink CommandSink) { r.commandSink = sink }
func (r *CommandRunner) event(domain CommandDomain, stage CommandStage) {
	EmitCommandEvent(r.commandSink, CommandEvent{Domain: domain, Stage: stage, Stream: r.activeStream})
}
