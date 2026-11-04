package fleet

import (
	"context"
	"errors"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/command"
)

type commandCompletion struct {
	response             command.Response
	persistenceUncertain bool
}

// CommandRunner owns the executor and the full in-process command outbox across
// session clients. Run and Quiesce require a single sequential caller; they must
// never overlap. It is not a durable outbox and must not be reconstructed to clear
// a pending result or persistence uncertainty.
type CommandRunner struct {
	commandSink            CommandSink
	executor               *command.Executor
	peerRelay              *command.PeerRelay
	activeJob              string
	activeDeadline         time.Time
	reportedExpiredPending bool
	cancelActive           context.CancelFunc
	done                   chan commandCompletion
	pending                *command.Response
	persistenceUncertain   bool
	activeStream           bool
	activeDigest           string
}

func NewCommandRunner(executor *command.Executor, peerRelays ...*command.PeerRelay) (*CommandRunner, error) {
	if executor == nil || len(peerRelays) > 1 {
		return nil, ErrHTTPClient
	}
	r := &CommandRunner{executor: executor}
	if len(peerRelays) == 1 {
		r.peerRelay = peerRelays[0]
	}
	return r, nil
}

func (r *CommandRunner) cancelExecution() {
	if r.cancelActive != nil {
		r.cancelActive()
	}
}

// Quiesce cancels and joins old-generation execution without sending or releasing
// its outcome. Call after Run returns and before rotating identity or constructing
// another client. A noncooperative adapter blocks replacement until serviceCtx
// cancels; cancellation never authorizes replacement or loss of the owner.
func (r *CommandRunner) Quiesce(serviceCtx context.Context) error {
	r.cancelExecution()
	if r.done != nil && r.pending == nil {
		select {
		case completed := <-r.done:
			r.capture(completed)
		case <-serviceCtx.Done():
			return serviceCtx.Err()
		}
	}
	return nil
}

// Run uses client only for this generation. Every exit cancels active execution,
// but retains its channel, full response and bindings for Quiesce/the next Run.
func (r *CommandRunner) Run(ctx context.Context, c *HTTPSClient) error {
	defer r.cancelExecution()
	if c == nil {
		return ErrHTTPClient
	}
	for {
		if r.done != nil && r.pending == nil {
			select {
			case completed := <-r.done:
				r.capture(completed)
			default:
			}
		}
		// Persistence failure may follow a real adapter mutation. Preserve the
		// local outcome and block admission: neither fabricated rejection nor a
		// normal success ACK conveys uncertainty safely. Expiry is not reconciliation.
		// This guard lasts only for this runner/executor instance, not across restart.
		if r.pending != nil && !r.reportedExpiredPending && !r.activeDeadline.IsZero() && !time.Now().Before(r.activeDeadline) {
			commandStage("PENDING_RESULT_EXPIRED", 0)
			r.event(DomainPending, StageExpired)
			r.reportedExpiredPending = true
		}
		if r.pending != nil && !r.persistenceUncertain {
			send := c.SendCommandResult
			if r.activeStream {
				send = func(ctx context.Context, result command.Response) error {
					r.event(DomainDelivery, StageSendStarted)
					return c.SendStreamResult(ctx, result, r.activeDigest)
				}
			}
			err := send(ctx, *r.pending)
			if r.activeStream {
				stage := StageACKValidated
				if err != nil {
					stage = StageStreamFailed
				}
				EmitCommandEvent(r.commandSink, CommandEvent{Domain: DomainDelivery, Stage: stage, Stream: true})
			}
			if err == nil || r.activeStream {
				EmitCommandEvent(r.commandSink, CommandEvent{Domain: DomainPending, Stage: StageReleased, Stream: r.activeStream, Acknowledged: err == nil})
				if r.cancelActive != nil {
					r.cancelActive()
				}
				r.activeJob, r.cancelActive, r.done, r.pending = "", nil, nil, nil
				r.activeDeadline, r.reportedExpiredPending = time.Time{}, false
			} else if ctx.Err() != nil {
				return nil
			}
		}
		work, err := c.pollCommandWork(ctx, time.Second)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
			continue
		}
		if work.PeerTransfer != nil && r.peerRelay != nil {
			result, relayErr := r.peerRelay.ExecuteDirective(ctx, *work.PeerTransfer)
			if relayErr == nil {
				_ = c.sendCommandPayload(ctx, result)
			}
		}
		request, cancelled := work.Command, work.CancelledJobIDs
		if work.stream != nil {
			request = work.stream
		}
		for _, jobID := range cancelled {
			if jobID == r.activeJob && r.cancelActive != nil {
				r.cancelActive()
			}
		}
		if request != nil && r.done == nil && r.pending == nil {
			runCtx, cancel := context.WithCancel(ctx)
			r.activeDeadline, _ = time.Parse(time.RFC3339Nano, request.Deadline)
			r.reportedExpiredPending = false
			r.activeStream = work.stream != nil
			r.activeDigest = request.Capability.RequestDigest
			r.activeJob, r.cancelActive, r.done = request.JobID, cancel, make(chan commandCompletion, 1)
			r.event(DomainExecution, StageEntered)
			go func(value command.Request, runCtx context.Context, client *HTTPSClient, executor *command.Executor, output chan<- commandCompletion) {
				commandStage("EXECUTION_ENTERED", 0)
				var result command.Response
				var runErr error
				if value.Operation == command.StreamOperation {
					result, runErr = executor.ExecuteStream(runCtx, value, client.SendStreamEvent)
				} else {
					result, runErr = executor.Execute(runCtx, value)
				}
				commandStage("EXECUTION_RETURNED", 0)
				if result.ErrorCode != nil && *result.ErrorCode == "ADAPTER_FAILED" {
					commandStage("EXECUTION_ADAPTER_FAILED", 0)
				}
				if errors.Is(runErr, command.ErrReplayPersistence) {
					commandStage("EXECUTION_PERSISTENCE_UNCERTAIN", 0)
					output <- commandCompletion{response: result, persistenceUncertain: true}
					return
				}
				if runErr != nil {
					commandStage("EXECUTION_REJECTED", 0)
					code := "COMMAND_REJECTED"
					result = command.Response{RequestID: value.RequestID, JobID: value.JobID, HostID: value.HostID, Sequence: value.Sequence, Status: "failed", ObservedAt: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), ErrorCode: &code}
				}
				output <- commandCompletion{response: result}
			}(*request, runCtx, c, r.executor, r.done)
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

// capture preserves the full authoritative response; only fixed classifications
// are copied into diagnostics. It is called by the sequential owner, never the adapter.
func (r *CommandRunner) capture(completed commandCompletion) {
	r.pending = &completed.response
	r.persistenceUncertain = completed.persistenceUncertain
	class := ErrorNone
	if completed.response.ErrorCode != nil {
		switch *completed.response.ErrorCode {
		case "ADAPTER_FAILED":
			class = ErrorAdapter
		case "COMMAND_REJECTED":
			class = ErrorRejected
		case "INDETERMINATE":
			class = ErrorIndeterminate
		default:
			class = ErrorOther
		}
	}
	persistence := PersistenceNoFailure
	if completed.persistenceUncertain {
		class = ErrorIndeterminate
		persistence = PersistenceUncertain
	}
	EmitCommandEvent(r.commandSink, CommandEvent{Domain: DomainExecution, Stage: StageCompleted, Outcome: CommandOutcome(completed.response.Status), ErrorClass: class, Persistence: persistence, Stream: r.activeStream})
	r.event(DomainPending, StageCaptured)
	if completed.persistenceUncertain {
		r.event(DomainPending, StageUncertain)
	}
}
