package fleet

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
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

type commandPollPayload struct {
	WaitMS int64 `json:"waitMs"`
}
type commandPollResult struct {
	Command         *command.Request `json:"command"`
	CancelledJobIDs []string         `json:"cancelledJobIds"`
	PeerTransfer    *json.RawMessage `json:"peerTransfer,omitempty"`
}

// PollCommand performs one bounded outbound poll and verifies that the response
// is signed by the exact controller TLS leaf used by this mTLS connection.
func (c *HTTPSClient) PollCommand(ctx context.Context, wait time.Duration) (*command.Request, []string, error) {
	result, err := c.pollCommandWork(ctx, wait)
	if err != nil {
		return nil, nil, err
	}
	return result.Command, result.CancelledJobIDs, nil
}

func (c *HTTPSClient) pollCommandWork(ctx context.Context, wait time.Duration) (commandPollResult, error) {
	if wait < 0 || wait > 30*time.Second {
		return commandPollResult{}, ErrHTTPClient
	}
	seq, err := c.next()
	if err != nil {
		return commandPollResult{}, err
	}
	env, err := c.agentEnvelope("agent.command.poll", seq, commandPollPayload{WaitMS: wait.Milliseconds()})
	if err != nil {
		return commandPollResult{}, err
	}
	pollCtx, cancel := context.WithTimeout(ctx, wait+5*time.Second)
	defer cancel()
	response, err := c.doEnvelope(pollCtx, commandPollPath, env)
	if err != nil {
		return commandPollResult{}, err
	}
	controller, err := verifyControllerEnvelope(response, env, c.hostID, seq)
	if err != nil {
		return commandPollResult{}, ErrHTTPClient
	}
	var result commandPollResult
	decoder := json.NewDecoder(bytes.NewReader(controller.Payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(&struct{}{}) != io.EOF || len(result.CancelledJobIDs) > 64 || result.Command != nil && result.PeerTransfer != nil {
		return commandPollResult{}, ErrHTTPClient
	}
	if result.Command != nil && (result.Command.HostID != c.hostID || result.Command.Sequence == 0) {
		return commandPollResult{}, ErrHTTPClient
	}
	if result.PeerTransfer != nil && (len(*result.PeerTransfer) == 0 || len(*result.PeerTransfer) > maxCommandEnvelopeBody) {
		return commandPollResult{}, ErrHTTPClient
	}
	if c.reserveControllerSequence(controller.Sequence) != nil {
		return commandPollResult{}, ErrHTTPClient
	}
	return result, nil
}
func (c *HTTPSClient) SendCommandResult(ctx context.Context, result command.Response) error {
	return c.sendCommandPayload(ctx, result)
}
func (c *HTTPSClient) sendCommandPayload(ctx context.Context, result any) error {
	seq, err := c.next()
	if err != nil {
		return err
	}
	env, err := c.agentEnvelope("agent.command.result", seq, result)
	if err != nil {
		return err
	}
	response, err := c.doEnvelope(ctx, commandResultPath, env)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, maxResponseBody+1))
	if e != nil || len(raw) > maxResponseBody || response.StatusCode != http.StatusOK || strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0])) != "application/json" || string(raw) != "{\"ok\":true}" {
		return ErrHTTPClient
	}
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
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxCommandPollBody+1))
	if err != nil || len(raw) > maxCommandPollBody || response.StatusCode != http.StatusOK || response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
		return agenttransport.Envelope{}, ErrHTTPClient
	}
	var env agenttransport.Envelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&env) != nil || decoder.Decode(&struct{}{}) != io.EOF || env.MessageType != "controller.command.poll" || env.HostID != hostID || env.RequestID != request.RequestID || env.Sequence != sequence {
		return agenttransport.Envelope{}, ErrHTTPClient
	}
	leaf := response.TLS.PeerCertificates[0]
	fingerprint := sha256.Sum256(leaf.Raw)
	if env.CertFingerprint != hex.EncodeToString(fingerprint[:]) || env.CertSerial != strings.ToUpper(leaf.SerialNumber.Text(16)) {
		return agenttransport.Envelope{}, ErrHTTPClient
	}
	public, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || agenttransport.Verify(env, public) != nil {
		return agenttransport.Envelope{}, ErrHTTPClient
	}
	sent, err := time.Parse(time.RFC3339Nano, env.SentAt)
	if err != nil || time.Since(sent) > 2*time.Minute || time.Until(sent) > 2*time.Minute {
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

// RunCommands is an explicitly injected command plane; constructing the fleet
// client alone never starts it. Execution is restricted to the command.Executor.
func (c *HTTPSClient) RunCommands(ctx context.Context, executor *command.Executor, peerRelays ...*command.PeerRelay) error {
	if executor == nil || len(peerRelays) > 1 {
		return ErrHTTPClient
	}
	var peerRelay *command.PeerRelay
	if len(peerRelays) == 1 {
		peerRelay = peerRelays[0]
	}
	type completion struct{ response command.Response }
	var activeJob string
	var cancelActive context.CancelFunc
	var done chan completion
	var pending *command.Response
	for {
		if done != nil && pending == nil {
			select {
			case completed := <-done:
				pending = &completed.response
			default:
			}
		}
		if pending != nil {
			if err := c.SendCommandResult(ctx, *pending); err == nil {
				activeJob, cancelActive, done, pending = "", nil, nil, nil
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
		if work.PeerTransfer != nil && peerRelay != nil {
			result, relayErr := peerRelay.ExecuteDirective(ctx, *work.PeerTransfer)
			if relayErr == nil {
				_ = c.sendCommandPayload(ctx, result)
			}
		}
		request, cancelled := work.Command, work.CancelledJobIDs
		for _, jobID := range cancelled {
			if jobID == activeJob && cancelActive != nil {
				cancelActive()
			}
		}
		if request != nil && done == nil && pending == nil {
			runCtx, cancel := context.WithCancel(ctx)
			activeJob, cancelActive, done = request.JobID, cancel, make(chan completion, 1)
			go func(value command.Request, output chan<- completion) {
				result, runErr := executor.Execute(runCtx, value)
				if runErr != nil {
					code := "COMMAND_REJECTED"
					result = command.Response{RequestID: value.RequestID, JobID: value.JobID, HostID: value.HostID, Sequence: value.Sequence, Status: "failed", ObservedAt: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), ErrorCode: &code}
				}
				output <- completion{response: result}
			}(*request, done)
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			if cancelActive != nil {
				cancelActive()
			}
			return nil
		case <-timer.C:
		}
	}
}
