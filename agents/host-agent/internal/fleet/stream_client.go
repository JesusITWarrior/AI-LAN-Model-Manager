package fleet

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/command"
)

// streamNext owns a separate durable sequence/replay lane. A blocked event POST
// cannot hold control polling, heartbeat sequencing, or cancellation hostage.
func (c *HTTPSClient) streamNext() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.streamSequence >= 9007199254740991 {
		return 0, ErrHTTPClient
	}
	next := c.streamSequence + 1
	if (SequenceStore{CertDir: c.store.CertDir, name: "stream-sequence-" + c.fingerprint}).Reserve(next) != nil {
		return 0, ErrHTTPClient
	}
	c.streamSequence = next
	return next, nil
}

// SendStreamEvent synchronously publishes borrowed raw public event bytes. There
// is no retry/queue/output replay. HTTP success means the sole consumer accepted
// this event, not merely that the controller buffered it. ctx bounds the wait.
func (c *HTTPSClient) SendStreamEvent(ctx context.Context, raw []byte) error {
	if len(raw) == 0 || len(raw) > 131072 {
		return ErrHTTPClient
	}
	return c.sendStreamPayload(ctx, "/agent/v1/streams/event", "agent.stream.event", struct {
		EventBase64 string `json:"eventBase64"`
	}{base64.StdEncoding.EncodeToString(raw)})
}
func (c *HTTPSClient) SendStreamResult(ctx context.Context, result command.Response, digest string) error {
	if result.Status != "succeeded" && result.Status != "failed" && result.Status != "cancelled" || result.Observation != nil {
		return ErrHTTPClient
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return c.sendStreamPayload(bounded, "/agent/v1/streams/result", "agent.stream.result", struct {
		CommandDigest string           `json:"commandDigest"`
		Result        command.Response `json:"result"`
	}{digest, result})
}
func (c *HTTPSClient) sendStreamPayload(ctx context.Context, path, message string, payload any) error {
	if c.streamHTTP == nil {
		return ErrHTTPClient
	}
	sequence, err := c.streamNext()
	if err != nil {
		return err
	}
	env, err := c.agentEnvelope(message, sequence, payload)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(env)
	if err != nil || len(raw) > 180224 {
		return ErrHTTPClient
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(raw))
	if err != nil {
		return ErrHTTPClient
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.streamHTTP.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrHTTPClient
	}
	defer response.Body.Close()
	ack, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBody+1))
	if err != nil || len(ack) > maxResponseBody || response.StatusCode != http.StatusOK || strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0])) != "application/json" || string(ack) != "{\"ok\":true}" {
		return ErrHTTPClient
	}
	return nil
}
