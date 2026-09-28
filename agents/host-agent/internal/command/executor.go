package command

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

var ErrCommand = errors.New("command rejected")

type Request struct {
	RequestID      string          `json:"requestId"`
	JobID          string          `json:"jobId"`
	HostID         string          `json:"hostId"`
	Operation      string          `json:"operation"`
	IdempotencyKey string          `json:"idempotencyKey"`
	Sequence       uint64          `json:"sequence"`
	Deadline       string          `json:"deadline"`
	Params         json.RawMessage `json:"params"`
}
type Response struct {
	RequestID   string  `json:"requestId"`
	JobID       string  `json:"jobId"`
	HostID      string  `json:"hostId"`
	Sequence    uint64  `json:"sequence"`
	Status      string  `json:"status"`
	Progress    *uint8  `json:"progress"`
	ObservedAt  string  `json:"observedAt"`
	Observation any     `json:"observation"`
	ErrorCode   *string `json:"errorCode"`
}
type Adapter interface {
	Execute(context.Context, string, json.RawMessage) (any, error)
}
type Executor struct {
	mu      sync.Mutex
	hostID  string
	adapter Adapter
	now     func() time.Time
	seen    map[string]entry
}
type entry struct {
	digest   string
	response Response
}

func New(hostID string, adapter Adapter, now func() time.Time) *Executor {
	if now == nil {
		now = time.Now
	}
	return &Executor{hostID: hostID, adapter: adapter, now: now, seen: map[string]entry{}}
}

var allowed = map[string]bool{"probe": true, "inventory": true, "estimate": true, "load": true, "set-options": true, "drain": true, "unload": true, "install": true, "remove-managed-artifact": true}

func (e *Executor) Execute(ctx context.Context, r Request) (Response, error) {
	if e == nil || e.adapter == nil || r.HostID != e.hostID || r.RequestID == "" || r.JobID == "" || r.Sequence == 0 || !allowed[r.Operation] {
		return Response{}, ErrCommand
	}
	deadline, err := time.Parse(time.RFC3339Nano, r.Deadline)
	if err != nil || !e.now().Before(deadline) || len(r.Params) > 32768 {
		return Response{}, ErrCommand
	}
	raw, _ := json.Marshal(r)
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	e.mu.Lock()
	if prior, ok := e.seen[r.IdempotencyKey]; ok {
		e.mu.Unlock()
		if prior.digest != digest {
			return Response{}, ErrCommand
		}
		return prior.response, nil
	}
	e.mu.Unlock()
	observation, runErr := e.adapter.Execute(ctx, r.Operation, r.Params)
	status := "succeeded"
	var code *string
	if runErr != nil {
		status = "failed"
		redacted := "ADAPTER_FAILED"
		code = &redacted
	}
	response := Response{RequestID: r.RequestID, JobID: r.JobID, HostID: r.HostID, Sequence: r.Sequence, Status: status, ObservedAt: e.now().UTC().Format("2006-01-02T15:04:05.000Z"), Observation: observation, ErrorCode: code}
	e.mu.Lock()
	defer e.mu.Unlock()
	if prior, ok := e.seen[r.IdempotencyKey]; ok {
		if prior.digest != digest {
			return Response{}, ErrCommand
		}
		return prior.response, nil
	}
	e.seen[r.IdempotencyKey] = entry{digest: digest, response: response}
	return response, nil
}
