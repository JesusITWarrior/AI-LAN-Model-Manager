package fleet

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/command"
	agenttransport "github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/transport"
)

const commandPollPath = "/agent/v1/commands/poll"
const commandResultPath = "/agent/v1/commands/result"
const maxCommandPollBody = 768 << 10
const maxCommandEnvelopeBody = 768 << 10

// commandStage emits only allowlisted stage codes and bounded HTTP statuses to
// the normal host logger. Never pass wire data, identifiers or error text here.
func commandStage(code string, status int) {
	switch code {
	case "POLL_TRANSPORT", "POLL_HTTP", "POLL_CODEC", "POLL_CERTIFICATE", "POLL_SIGNATURE", "POLL_CLOCK", "POLL_PAYLOAD", "POLL_SEQUENCE", "PENDING_RESULT_EXPIRED", "EXECUTION_ENTERED", "EXECUTION_RETURNED", "EXECUTION_ADAPTER_FAILED", "EXECUTION_REJECTED", "EXECUTION_PERSISTENCE_UNCERTAIN", "RESULT_TRANSPORT", "RESULT_REJECTED", "RESULT_DELIVERED":
	default:
		code = "UNKNOWN_STAGE"
	}
	if status < 100 || status > 599 {
		status = 0
	}
	slog.Info("command-stage", "code", code, "httpStatus", status)
}

type commandPollPayload struct {
	WaitMS int64 `json:"waitMs"`
}
type commandPollResult struct {
	Command         *command.Request `json:"command"`
	CancelledJobIDs []string         `json:"cancelledJobIds"`
	StreamCommand   *json.RawMessage `json:"streamCommand,omitempty"`
	stream          *command.Request
	PeerTransfer    *json.RawMessage `json:"peerTransfer,omitempty"`
}

// PollCommand performs one bounded outbound poll and verifies that the response
// is signed by the exact controller TLS leaf used by this mTLS connection.
func (c *HTTPSClient) PollCommand(ctx context.Context, wait time.Duration) (*command.Request, []string, error) {
	result, err := c.pollCommandWork(ctx, wait)
	if err != nil {
		return nil, nil, err
	}
	if result.stream != nil {
		return nil, nil, ErrHTTPClient
	}
	return result.Command, result.CancelledJobIDs, nil
}

func (c *HTTPSClient) pollCommandWork(ctx context.Context, wait time.Duration) (commandPollResult, error) {
	if wait < 0 || wait > 30*time.Second {
		return commandPollResult{}, ErrHTTPClient
	}
	seq, err := c.next()
	if err != nil {
		c.commandEvent(DomainPoll, StageSequence, 0)
		return commandPollResult{}, err
	}
	env, err := c.agentEnvelope("agent.command.poll", seq, commandPollPayload{WaitMS: wait.Milliseconds()})
	if err != nil {
		c.commandEvent(DomainPoll, StageEnvelope, 0)
		return commandPollResult{}, err
	}
	pollCtx, cancel := context.WithTimeout(ctx, wait+5*time.Second)
	defer cancel()
	response, err := c.doEnvelope(pollCtx, commandPollPath, env)
	if err != nil {
		commandStage("POLL_TRANSPORT", 0)
		c.commandEvent(DomainPoll, StageTransport, 0)
		return commandPollResult{}, err
	}
	controller, err := verifyControllerEnvelopeWithSink(response, env, c.hostID, seq, c.commandSink)
	if err != nil {
		return commandPollResult{}, ErrHTTPClient
	}
	var result commandPollResult
	decoder := json.NewDecoder(bytes.NewReader(controller.Payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(&struct{}{}) != io.EOF || len(result.CancelledJobIDs) > 64 || result.Command != nil && result.PeerTransfer != nil {
		commandStage("POLL_PAYLOAD", 0)
		c.commandEvent(DomainPoll, StagePayload, 0)
		return commandPollResult{}, ErrHTTPClient
	}
	if result.Command != nil && (result.Command.HostID != c.hostID || result.Command.Sequence == 0 || result.Command.Operation == command.StreamOperation) {
		c.commandEvent(DomainPoll, StagePayload, 0)
		return commandPollResult{}, ErrHTTPClient
	}
	if result.PeerTransfer != nil && (len(*result.PeerTransfer) == 0 || len(*result.PeerTransfer) > maxCommandEnvelopeBody) {
		c.commandEvent(DomainPoll, StagePayload, 0)
		return commandPollResult{}, ErrHTTPClient
	}
	if result.StreamCommand != nil && string(*result.StreamCommand) != "null" {
		if result.Command != nil || result.PeerTransfer != nil && string(*result.PeerTransfer) != "null" {
			c.commandEvent(DomainPoll, StagePayload, 0)
			return commandPollResult{}, ErrHTTPClient
		}
		r, err := command.ParseStreamCommand(*result.StreamCommand)
		if err != nil || r.HostID != c.hostID {
			c.commandEvent(DomainPoll, StagePayload, 0)
			return commandPollResult{}, ErrHTTPClient
		}
		result.stream = &r
	}
	if c.reserveControllerSequence(controller.Sequence) != nil {
		commandStage("POLL_SEQUENCE", 0)
		c.commandEvent(DomainPoll, StageControllerSequence, 0)
		return commandPollResult{}, ErrHTTPClient
	}
	c.commandEvent(DomainPoll, StageVerified, 0)
	return result, nil
}
func (c *HTTPSClient) SendCommandResult(ctx context.Context, result command.Response) error {
	return c.sendCommandPayload(ctx, result)
}
func (c *HTTPSClient) sendCommandPayload(ctx context.Context, result any) error {
	c.commandEvent(DomainDelivery, StageSendStarted, 0)
	seq, err := c.next()
	if err != nil {
		c.commandEvent(DomainDelivery, StageSequence, 0)
		return err
	}
	env, err := c.agentEnvelope("agent.command.result", seq, result)
	if err != nil {
		c.commandEvent(DomainDelivery, StageEnvelope, 0)
		return err
	}
	response, err := c.doEnvelope(ctx, commandResultPath, env)
	if err != nil {
		commandStage("RESULT_TRANSPORT", 0)
		c.commandEvent(DomainDelivery, StageTransport, 0)
		return err
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, maxResponseBody+1))
	if e != nil || len(raw) > maxResponseBody || response.StatusCode != http.StatusOK || strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0])) != "application/json" || string(raw) != "{\"ok\":true}" {
		commandStage("RESULT_REJECTED", response.StatusCode)
		stage := StageACKInvalid
		if response.StatusCode != http.StatusOK {
			stage = StageHTTP
		} else if e != nil || len(raw) > maxResponseBody {
			stage = StageCodec
		}
		c.commandEvent(DomainDelivery, stage, response.StatusCode)
		return ErrHTTPClient
	}
	commandStage("RESULT_DELIVERED", response.StatusCode)
	c.commandEvent(DomainDelivery, StageACKValidated, response.StatusCode)
	return nil
}
func (c *HTTPSClient) agentEnvelope(message string, sequence uint64, payload any) (agenttransport.Envelope, error) {
	requestID, err := randomHex(16)
	if err != nil {
		return agenttransport.Envelope{}, ErrHTTPClient
	}
	nonce, err := randomHex(16)
	if err != nil {
		return agenttransport.Envelope{}, ErrHTTPClient
	}
	env, err := agenttransport.NewEnvelope(c.hostID, requestID, message, nonce, c.fingerprint, c.serial, sequence, c.now(), payload)
	if err != nil || agenttransport.Sign(&env, c.privateKey) != nil {
		return agenttransport.Envelope{}, ErrHTTPClient
	}
	return env, nil
}
func (c *HTTPSClient) doEnvelope(ctx context.Context, path string, env agenttransport.Envelope) (*http.Response, error) {
	body, err := json.Marshal(env)
	if err != nil || len(body) > maxCommandEnvelopeBody {
		return nil, ErrHTTPClient
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, ErrHTTPClient
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return nil, ErrHTTPClient
	}
	return response, nil
}
func verifyControllerEnvelope(response *http.Response, request agenttransport.Envelope, hostID string, sequence uint64) (agenttransport.Envelope, error) {
	return verifyControllerEnvelopeWithSink(response, request, hostID, sequence, nil)
}
func verifyControllerEnvelopeWithSink(response *http.Response, request agenttransport.Envelope, hostID string, sequence uint64, sink CommandSink) (agenttransport.Envelope, error) {
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxCommandPollBody+1))
	if err != nil || len(raw) > maxCommandPollBody || response.StatusCode != http.StatusOK || response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
		commandStage("POLL_HTTP", response.StatusCode)
		EmitCommandEvent(sink, CommandEvent{Domain: DomainPoll, Stage: StageHTTP, HTTPStatus: response.StatusCode})
		return agenttransport.Envelope{}, ErrHTTPClient
	}
	var env agenttransport.Envelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if command.DecodeStreamWireJSON(raw, &env) != nil || decoder.Decode(&env) != nil || decoder.Decode(&struct{}{}) != io.EOF || env.MessageType != "controller.command.poll" || env.HostID != hostID || env.RequestID != request.RequestID || env.Sequence != sequence {
		commandStage("POLL_CODEC", response.StatusCode)
		EmitCommandEvent(sink, CommandEvent{Domain: DomainPoll, Stage: StageCodec, HTTPStatus: response.StatusCode})
		return agenttransport.Envelope{}, ErrHTTPClient
	}
	leaf := response.TLS.PeerCertificates[0]
	fingerprint := sha256.Sum256(leaf.Raw)
	if env.CertFingerprint != hex.EncodeToString(fingerprint[:]) || !agenttransport.SameCertificateSerial(env.CertSerial, strings.ToUpper(leaf.SerialNumber.Text(16))) {
		commandStage("POLL_CERTIFICATE", response.StatusCode)
		EmitCommandEvent(sink, CommandEvent{Domain: DomainPoll, Stage: StageCertificate, HTTPStatus: response.StatusCode})
		return agenttransport.Envelope{}, ErrHTTPClient
	}
	public, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || agenttransport.Verify(env, public) != nil {
		commandStage("POLL_SIGNATURE", response.StatusCode)
		EmitCommandEvent(sink, CommandEvent{Domain: DomainPoll, Stage: StageSignature, HTTPStatus: response.StatusCode})
		return agenttransport.Envelope{}, ErrHTTPClient
	}
	sent, err := time.Parse(time.RFC3339Nano, env.SentAt)
	if err != nil || time.Since(sent) > 2*time.Minute || time.Until(sent) > 2*time.Minute {
		commandStage("POLL_CLOCK", response.StatusCode)
		EmitCommandEvent(sink, CommandEvent{Domain: DomainPoll, Stage: StageClock, HTTPStatus: response.StatusCode})
		return agenttransport.Envelope{}, ErrHTTPClient
	}
	return env, nil
}
func (c *HTTPSClient) reserveControllerSequence(sequence uint64) error {
	path := filepath.Join(c.store.CertDir, "controller-command-sequence")
	var prior uint64
	if raw, err := os.ReadFile(path); err == nil {
		if _, err = fmtSscanf(string(raw), &prior); err != nil {
			return ErrHTTPClient
		}
	} else if !os.IsNotExist(err) {
		return ErrHTTPClient
	}
	if sequence <= prior {
		return ErrHTTPClient
	}
	tmp, err := os.CreateTemp(c.store.CertDir, ".controller-command-")
	if err != nil {
		return ErrHTTPClient
	}
	name := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if tmp.Chmod(0o600) != nil {
		return ErrHTTPClient
	}
	if _, err = tmp.WriteString(uintString(sequence) + "\n"); err != nil || tmp.Sync() != nil || tmp.Close() != nil {
		return ErrHTTPClient
	}
	if os.Rename(name, path) != nil {
		return ErrHTTPClient
	}
	ok = true
	return nil
}

// small decimal helpers avoid accepting signs/whitespace in replay state.
func fmtSscanf(raw string, out *uint64) (int, error) {
	if !strings.HasSuffix(raw, "\n") || strings.TrimSuffix(raw, "\n") == "" {
		return 0, ErrHTTPClient
	}
	var n uint64
	for _, r := range strings.TrimSuffix(raw, "\n") {
		if r < '0' || r > '9' {
			return 0, ErrHTTPClient
		}
		n = n*10 + uint64(r-'0')
	}
	*out = n
	return 1, nil
}
func uintString(v uint64) string {
	if v == 0 {
		return "0"
	}
	b := make([]byte, 0, 20)
	for v > 0 {
		b = append(b, byte('0'+v%10))
		v /= 10
	}
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

// RunCommands is an invocation-lifetime compatibility wrapper. Service owners
// that replace session clients must retain a CommandRunner and Quiesce it before
// replacement; this wrapper alone does not retain state across invocations.
func (c *HTTPSClient) RunCommands(ctx context.Context, executor *command.Executor, peerRelays ...*command.PeerRelay) error {
	runner, err := NewCommandRunner(executor, peerRelays...)
	if err != nil {
		return err
	}
	runner.SetCommandSink(c.commandSink)
	return runner.Run(ctx, c)
}
