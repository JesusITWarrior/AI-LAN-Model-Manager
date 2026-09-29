package command

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"
)

var ErrCommand = errors.New("command rejected")
var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Capability struct {
	Operation     string  `json:"operation"`
	TargetKind    string  `json:"targetKind"`
	TargetID      string  `json:"targetId"`
	HostID        string  `json:"hostId"`
	ModelID       *string `json:"modelId"`
	RequestDigest string  `json:"requestDigest"`
	ExpiresAt     string  `json:"expiresAt"`
}
type Request struct {
	RequestID      string          `json:"requestId"`
	JobID          string          `json:"jobId"`
	HostID         string          `json:"hostId"`
	Operation      string          `json:"operation"`
	IdempotencyKey string          `json:"idempotencyKey"`
	Sequence       uint64          `json:"sequence"`
	Deadline       string          `json:"deadline"`
	Capability     Capability      `json:"capability"`
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
type entry struct {
	Digest   string   `json:"digest"`
	Response Response `json:"response"`
}

const maxReplayEntries = 256
const maxReplayStoreBytes = 80 << 20

type Executor struct {
	mu      sync.Mutex
	hostID  string
	adapter Adapter
	now     func() time.Time
	seen    map[string]entry
	store   string
}

func New(hostID string, adapter Adapter, now func() time.Time) *Executor {
	if now == nil {
		now = time.Now
	}
	return &Executor{hostID: hostID, adapter: adapter, now: now, seen: map[string]entry{}}
}
func NewPersistent(hostID string, adapter Adapter, now func() time.Time, path string) (*Executor, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrCommand
	}
	e := New(hostID, adapter, now)
	e.store = path
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return e, nil
	}
	if err != nil || len(raw) > maxReplayStoreBytes || json.Unmarshal(raw, &e.seen) != nil || e.seen == nil || len(e.seen) > maxReplayEntries {
		return nil, ErrCommand
	}
	return e, nil
}

var allowed = map[string]string{"probe": "observe", "inventory": "provider-status", "estimate": "model-status", "load": "model-load", "set-options": "model-set-options", "drain": "model-drain", "unload": "model-unload", "install": "artifact-install", "remove-managed-artifact": "artifact-remove", "inference.chat": "model-inference"}

func normalizedJSON(raw json.RawMessage) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, ErrCommand
	}
	return normalizeNumbers(value)
}
func safeASCII(value string, empty bool) bool {
	if !empty && value == "" {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}
func normalizeNumbers(value any) (any, error) {
	switch v := value.(type) {
	case string:
		if !safeASCII(v, true) {
			return nil, ErrCommand
		}
	case json.Number:
		integer, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil || integer < -9007199254740991 || integer > 9007199254740991 {
			return nil, ErrCommand
		}
		return integer, nil
	case []any:
		for i := range v {
			n, e := normalizeNumbers(v[i])
			if e != nil {
				return nil, e
			}
			v[i] = n
		}
	case map[string]any:
		for k, item := range v {
			if !safeASCII(k, false) {
				return nil, ErrCommand
			}
			n, e := normalizeNumbers(item)
			if e != nil {
				return nil, e
			}
			v[k] = n
		}
	}
	return value, nil
}
func authorizationDigest(r Request) (string, error) {
	params, err := normalizedJSON(r.Params)
	if err != nil {
		return "", err
	}
	bound := map[string]any{"requestId": r.RequestID, "jobId": r.JobID, "hostId": r.HostID, "operation": r.Operation, "idempotencyKey": r.IdempotencyKey, "sequence": r.Sequence, "deadline": r.Deadline, "capability": map[string]any{"operation": r.Capability.Operation, "targetKind": r.Capability.TargetKind, "targetId": r.Capability.TargetID, "hostId": r.Capability.HostID, "modelId": r.Capability.ModelID, "expiresAt": r.Capability.ExpiresAt}, "params": params}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(bound); err != nil {
		return "", err
	}
	raw := bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func targetMatches(r Request) bool {
	if r.Capability.TargetKind == "host" && (r.Capability.TargetID != r.HostID || r.Capability.ModelID != nil) {
		return false
	}
	if r.Capability.TargetKind == "model" && (r.Capability.ModelID == nil || r.Capability.TargetID != *r.Capability.ModelID) {
		return false
	}
	var params map[string]any
	if json.Unmarshal(r.Params, &params) == nil {
		if value, ok := params["modelId"]; ok && (r.Capability.ModelID == nil || value != *r.Capability.ModelID) {
			return false
		}
		if value, ok := params["hostId"]; ok && value != r.HostID {
			return false
		}
	}
	return true
}

func (e *Executor) Execute(ctx context.Context, r Request) (Response, error) {
	policy, ok := allowed[r.Operation]
	if e == nil || e.adapter == nil || r.HostID != e.hostID || !identifier.MatchString(r.RequestID) || !identifier.MatchString(r.JobID) || !identifier.MatchString(r.IdempotencyKey) || r.Sequence == 0 || !ok {
		return Response{}, ErrCommand
	}
	deadline, err := time.Parse(time.RFC3339Nano, r.Deadline)
	expires, xerr := time.Parse(time.RFC3339Nano, r.Capability.ExpiresAt)
	digest, derr := authorizationDigest(r)
	maxParams := 32768
	if r.Operation == "inference.chat" {
		maxParams = 524288
	}
	if err != nil || xerr != nil || derr != nil || !e.now().Before(deadline) || !e.now().Before(expires) || r.Capability.Operation != policy || r.Capability.HostID != r.HostID || !identifier.MatchString(r.Capability.TargetKind) || !identifier.MatchString(r.Capability.TargetID) || !digestPattern.MatchString(r.Capability.RequestDigest) || r.Capability.RequestDigest != digest || !targetMatches(r) || len(r.Params) > maxParams {
		return Response{}, ErrCommand
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if prior, found := e.seen[r.IdempotencyKey]; found {
		if prior.Digest != digest {
			return Response{}, ErrCommand
		}
		if prior.Response.Status != "running" {
			return prior.Response, nil
		}
		if r.Operation == "inference.chat" {
			code := "INDETERMINATE"
			failed := Response{RequestID: r.RequestID, JobID: r.JobID, HostID: r.HostID, Sequence: r.Sequence, Status: "failed", ObservedAt: e.now().UTC().Format("2006-01-02T15:04:05.000Z"), ErrorCode: &code}
			e.seen[r.IdempotencyKey] = entry{Digest: digest, Response: failed}
			if e.persist() != nil {
				e.seen[r.IdempotencyKey] = prior
				return Response{}, ErrCommand
			}
			return failed, nil
		}
	}
	if r.Operation == "inference.chat" && e.store != "" {
		if len(e.seen) >= maxReplayEntries {
			return Response{}, ErrCommand
		}
		progress := uint8(1)
		running := Response{RequestID: r.RequestID, JobID: r.JobID, HostID: r.HostID, Sequence: r.Sequence, Status: "running", Progress: &progress, ObservedAt: e.now().UTC().Format("2006-01-02T15:04:05.000Z")}
		e.seen[r.IdempotencyKey] = entry{Digest: digest, Response: running}
		if e.persist() != nil {
			delete(e.seen, r.IdempotencyKey)
			return Response{}, ErrCommand
		}
	}
	runCtx, cancel := context.WithTimeout(ctx, deadline.Sub(e.now()))
	defer cancel()
	observation, runErr := e.adapter.Execute(runCtx, r.Operation, r.Params)
	status := "succeeded"
	complete := uint8(100)
	var progress *uint8 = &complete
	var code *string
	if errors.Is(runErr, ErrServingActive) {
		status = "running"
		v := uint8(50)
		progress = &v
	} else if errors.Is(runErr, context.DeadlineExceeded) || errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		status = "failed"
		progress = nil
		v := "TIMEOUT"
		code = &v
	} else if errors.Is(runErr, context.Canceled) || errors.Is(runCtx.Err(), context.Canceled) {
		status = "cancelled"
		progress = nil
		v := "CANCELLED"
		code = &v
	} else if runErr != nil {
		status = "failed"
		progress = nil
		v := "ADAPTER_FAILED"
		code = &v
	}
	response := Response{RequestID: r.RequestID, JobID: r.JobID, HostID: r.HostID, Sequence: r.Sequence, Status: status, Progress: progress, ObservedAt: e.now().UTC().Format("2006-01-02T15:04:05.000Z"), Observation: observation, ErrorCode: code}
	prior, existed := e.seen[r.IdempotencyKey]
	if !existed && len(e.seen) >= maxReplayEntries {
		return Response{}, ErrCommand
	}
	e.seen[r.IdempotencyKey] = entry{Digest: digest, Response: response}
	if e.persist() != nil {
		if existed {
			e.seen[r.IdempotencyKey] = prior
		} else {
			delete(e.seen, r.IdempotencyKey)
		}
		return Response{}, ErrCommand
	}
	return response, nil
}
func (e *Executor) persist() error {
	if e.store == "" {
		return nil
	}
	if os.MkdirAll(filepath.Dir(e.store), 0o700) != nil {
		return ErrCommand
	}
	raw, err := json.Marshal(e.seen)
	if err != nil || len(raw) > maxReplayStoreBytes {
		return ErrCommand
	}
	tmp, err := os.CreateTemp(filepath.Dir(e.store), ".command-replay-")
	if err != nil {
		return ErrCommand
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
		return ErrCommand
	}
	if _, err = tmp.Write(append(raw, '\n')); err != nil || tmp.Sync() != nil || tmp.Close() != nil {
		return ErrCommand
	}
	if os.Rename(name, e.store) != nil {
		return ErrCommand
	}
	dir, err := os.Open(filepath.Dir(e.store))
	if err != nil {
		return ErrCommand
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return ErrCommand
	}
	ok = true
	return nil
}
