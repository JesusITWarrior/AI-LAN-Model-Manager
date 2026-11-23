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
	"reflect"
	"regexp"
	"strconv"
	"sync"
	"time"
)

var ErrCommand = errors.New("command rejected")

// ErrReplayPersistence means replay storage is uncertain, not that execution
// was rejected before the adapter ran. A non-empty returned Response retains
// the known outcome, but must not be interpreted as durably persisted.
var ErrReplayPersistence = errors.New("command replay persistence uncertain")
var ErrReplayLookup = errors.New("invalid replay lookup")
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

// ReplayLookupState describes a side-effect-free replay lookup.
type ReplayLookupState string

const (
	ReplayMissing   ReplayLookupState = "missing"
	ReplayTerminal  ReplayLookupState = "terminal"
	ReplayRunning   ReplayLookupState = "running"
	ReplayDivergent ReplayLookupState = "divergent"
	ReplayUncertain ReplayLookupState = "persistence-uncertain"
)

type ReplayLookup struct {
	State          ReplayLookupState
	Digest         string
	Response       Response
	PersistenceErr error
}

type cloneVisit struct {
	typ reflect.Type
	ptr uintptr
}

func cloneReflect(v reflect.Value, seen map[cloneVisit]bool) (reflect.Value, error) {
	if !v.IsValid() {
		return reflect.Value{}, nil
	}
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return reflect.Zero(v.Type()), nil
		}
		x, err := cloneReflect(v.Elem(), seen)
		if err != nil {
			return reflect.Value{}, err
		}
		out := reflect.New(v.Type()).Elem()
		out.Set(x)
		return out, nil
	case reflect.Ptr:
		if v.IsNil() {
			return reflect.Zero(v.Type()), nil
		}
		key := cloneVisit{v.Type(), v.Pointer()}
		if seen[key] {
			return reflect.Value{}, ErrReplayLookup
		}
		seen[key] = true
		x, err := cloneReflect(v.Elem(), seen)
		if err != nil {
			return reflect.Value{}, err
		}
		out := reflect.New(v.Type().Elem())
		out.Elem().Set(x)
		return out, nil
	case reflect.Map:
		if v.IsNil() {
			return reflect.Zero(v.Type()), nil
		}
		key := cloneVisit{v.Type(), v.Pointer()}
		if seen[key] {
			return reflect.Value{}, ErrReplayLookup
		}
		seen[key] = true
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		it := v.MapRange()
		for it.Next() {
			k, err := cloneReflect(it.Key(), seen)
			if err != nil {
				return reflect.Value{}, err
			}
			x, err := cloneReflect(it.Value(), seen)
			if err != nil {
				return reflect.Value{}, err
			}
			out.SetMapIndex(k, x)
		}
		return out, nil
	case reflect.Slice:
		if v.IsNil() {
			return reflect.Zero(v.Type()), nil
		}
		key := cloneVisit{v.Type(), v.Pointer()}
		if seen[key] {
			return reflect.Value{}, ErrReplayLookup
		}
		seen[key] = true
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			x, err := cloneReflect(v.Index(i), seen)
			if err != nil {
				return reflect.Value{}, err
			}
			out.Index(i).Set(x)
		}
		return out, nil
	case reflect.Array:
		out := reflect.New(v.Type()).Elem()
		for i := 0; i < v.Len(); i++ {
			x, err := cloneReflect(v.Index(i), seen)
			if err != nil {
				return reflect.Value{}, err
			}
			out.Index(i).Set(x)
		}
		return out, nil
	case reflect.Struct:
		out := reflect.New(v.Type()).Elem()
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).PkgPath != "" {
				return reflect.Value{}, ErrReplayLookup
			}
			x, err := cloneReflect(v.Field(i), seen)
			if err != nil {
				return reflect.Value{}, err
			}
			out.Field(i).Set(x)
		}
		return out, nil
	case reflect.Func, reflect.Chan, reflect.UnsafePointer:
		return reflect.Value{}, ErrReplayLookup
	default:
		return v, nil
	}
}
func cloneValue(value any) (any, error) {
	x, err := cloneReflect(reflect.ValueOf(value), make(map[cloneVisit]bool))
	if err != nil {
		return nil, err
	}
	if !x.IsValid() {
		return nil, nil
	}
	return x.Interface(), nil
}
func detachedResponse(response Response) (Response, error) {
	out := response
	if response.Progress != nil {
		x := *response.Progress
		out.Progress = &x
	}
	if response.ErrorCode != nil {
		x := *response.ErrorCode
		out.ErrorCode = &x
	}
	var err error
	out.Observation, err = cloneValue(response.Observation)
	if err != nil {
		return Response{}, err
	}
	return out, nil
}

// LookupReplay returns a detached replay binding snapshot without executing or persisting.
func (e *Executor) LookupReplay(r Request) (ReplayLookup, error) {
	if e == nil || r.HostID != e.hostID || !validLookupRequest(r) {
		return ReplayLookup{}, ErrReplayLookup
	}
	digest, err := authorizationDigest(r)
	if err != nil || r.Capability.RequestDigest != digest {
		return ReplayLookup{}, ErrReplayLookup
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	prior, found := e.seen[r.IdempotencyKey]
	if !found {
		return ReplayLookup{State: ReplayMissing}, nil
	}
	if prior.Digest != digest {
		return ReplayLookup{State: ReplayDivergent, Digest: prior.Digest}, nil
	}
	response, err := detachedResponse(prior.Response)
	if err != nil {
		return ReplayLookup{}, err
	}
	result := ReplayLookup{Digest: prior.Digest, Response: response}
	if e.persistenceErr != nil {
		result.State, result.PersistenceErr = ReplayUncertain, e.persistenceErr
		return result, nil
	}
	if response.Status == "running" {
		result.State = ReplayRunning
	} else {
		result.State = ReplayTerminal
	}
	return result, nil
}
func validLookupRequest(r Request) bool {
	policy, ok := allowed[r.Operation]
	if r.Operation == StreamOperation {
		policy, ok = "model-inference", true
	}
	if !ok || r.HostID == "" || !identifier.MatchString(r.RequestID) || !identifier.MatchString(r.JobID) || !identifier.MatchString(r.IdempotencyKey) || r.Sequence == 0 || r.Sequence > maxSafeInteger || r.Capability.Operation != policy || r.Capability.HostID != r.HostID || !identifier.MatchString(r.Capability.TargetKind) || !identifier.MatchString(r.Capability.TargetID) || !digestPattern.MatchString(r.Capability.RequestDigest) || !targetMatches(r) {
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, r.Deadline); err != nil {
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, r.Capability.ExpiresAt); err != nil {
		return false
	}
	return true
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
	// persistenceErr is sticky for this executor: no adapter may run again
	// after a replay write fails, even when the retained outcome is running.
	persistenceErr error
	writeReplay    func(string, []byte) (bool, error)
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

var allowed = map[string]string{"probe": "observe", "inventory": "provider-status", "estimate": "model-status", "load": "model-load", "set-options": "model-set-options", "drain": "model-drain", "unload": "model-unload", "install": "artifact-install", "remove-managed-artifact": "artifact-remove", "inference.chat": "model-inference", PeerSourceOperation: "peer-transfer-source", PeerDestinationOperation: "peer-transfer-destination"}

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
	if r.Operation == StreamOperation {
		return Response{}, ErrCommand
	}
	return e.execute(ctx, r, nil)
}

// ExecuteStream is local-only. Buffered command transports cannot invoke it.
// A replay returns only the durable outcome; emitted output is never regenerated.
func (e *Executor) ExecuteStream(ctx context.Context, r Request, emit StreamEmitter) (Response, error) {
	r = snapshotStreamRequest(r)
	if r.Operation != StreamOperation || emit == nil {
		return Response{}, ErrCommand
	}
	return e.execute(ctx, r, emit)
}
func (e *Executor) execute(ctx context.Context, r Request, emit StreamEmitter) (Response, error) {
	policy, ok := allowed[r.Operation]
	if r.Operation == StreamOperation && emit != nil {
		policy, ok = "model-inference", true
	}
	if r.Operation == StreamOperation {
		raw, err := json.Marshal(r)
		if err != nil {
			return Response{}, ErrCommand
		}
		if _, err := ParseStreamCommand(raw); err != nil {
			return Response{}, ErrCommand
		}
	}
	if e == nil || e.adapter == nil || r.HostID != e.hostID || !identifier.MatchString(r.RequestID) || !identifier.MatchString(r.JobID) || !identifier.MatchString(r.IdempotencyKey) || r.Sequence == 0 || r.Sequence > maxSafeInteger || !ok {
		return Response{}, ErrCommand
	}
	deadline, err := time.Parse(time.RFC3339Nano, r.Deadline)
	expires, xerr := time.Parse(time.RFC3339Nano, r.Capability.ExpiresAt)
	digest, derr := authorizationDigest(r)
	maxParams := 32768
	if r.Operation == "inference.chat" || r.Operation == StreamOperation {
		maxParams = 524288
	}
	if r.Operation == StreamOperation {
		maxParams = 550000
	} // Typed params are bounded separately.
	if r.Operation == PeerSourceOperation || r.Operation == PeerDestinationOperation {
		maxParams = 768 << 10
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
		if e.persistenceErr != nil {
			return prior.Response, e.persistenceErr
		}
		if prior.Response.Status != "running" {
			return prior.Response, nil
		}
		if r.Operation == "inference.chat" || r.Operation == StreamOperation {
			code := "INDETERMINATE"
			failed := Response{RequestID: r.RequestID, JobID: r.JobID, HostID: r.HostID, Sequence: r.Sequence, Status: "failed", ObservedAt: e.now().UTC().Format("2006-01-02T15:04:05.000Z"), ErrorCode: &code}
			e.seen[r.IdempotencyKey] = entry{Digest: digest, Response: failed}
			if err := e.persist(); err != nil {
				return failed, err
			}
			return failed, nil
		}
	}
	if e.persistenceErr != nil {
		return Response{}, e.persistenceErr
	}
	if _, exists := e.seen[r.IdempotencyKey]; !exists && len(e.seen) >= maxReplayEntries {
		return Response{}, ErrCommand
	}
	if r.Operation == StreamOperation || (r.Operation == "inference.chat" && e.store != "") {
		progress := uint8(1)
		running := Response{RequestID: r.RequestID, JobID: r.JobID, HostID: r.HostID, Sequence: r.Sequence, Status: "running", Progress: &progress, ObservedAt: e.now().UTC().Format("2006-01-02T15:04:05.000Z")}
		e.seen[r.IdempotencyKey] = entry{Digest: digest, Response: running}
		if err := e.persist(); err != nil {
			// No adapter ran. Keep the marker in case replacement published it.
			return Response{}, err
		}
	}
	duration := deadline.Sub(e.now())
	if r.Operation == StreamOperation && expires.Sub(e.now()) < duration {
		duration = expires.Sub(e.now())
	}
	runCtx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	var observation any
	var runErr error
	if r.Operation == StreamOperation {
		adapter, ok := e.adapter.(StreamAdapter)
		if !ok {
			runErr = ErrUnsupported
		} else {
			validator, _ := NewStreamValidator(r)
			terminalKind := ""
			var publishErr error
			runErr = adapter.ExecuteStream(runCtx, r, func(ctx context.Context, raw []byte) error {
				if publishErr != nil {
					return publishErr
				}
				if err := ctx.Err(); err != nil {
					publishErr = err
					return err
				}
				event, err := validator.Accept(raw)
				if err != nil {
					publishErr = err
					return err
				}
				if err = emit(ctx, raw); err != nil {
					publishErr = err
					return err
				}
				if event.Kind != "chunk" {
					terminalKind = event.Kind
				}
				return nil
			})
			// Publication acceptance is the terminal linearization point. A later
			// cancellation must not contradict a successfully published completion.
			if terminalKind == "succeeded" {
				runErr = nil
			} else if publishErr != nil {
				runErr = publishErr
			} else if runErr == nil {
				runErr = ErrStream
			}
		}
	} else {
		observation, runErr = e.adapter.Execute(runCtx, r.Operation, r.Params)
	}
	status := "succeeded"
	complete := uint8(100)
	var progress *uint8 = &complete
	var code *string
	if errors.Is(runErr, ErrServingActive) && r.Operation != StreamOperation {
		status = "running"
		v := uint8(50)
		progress = &v
	} else if errors.Is(runErr, context.DeadlineExceeded) || (r.Operation != StreamOperation && errors.Is(runCtx.Err(), context.DeadlineExceeded)) {
		status = "failed"
		progress = nil
		v := "TIMEOUT"
		code = &v
	} else if errors.Is(runErr, context.Canceled) || (r.Operation != StreamOperation && errors.Is(runCtx.Err(), context.Canceled)) {
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
	e.seen[r.IdempotencyKey] = entry{Digest: digest, Response: response}
	if err := e.persist(); err != nil {
		// The adapter already ran. Never erase its outcome or restore a
		// running entry: either could permit a second mutation in this process.
		return response, err
	}
	return response, nil
}
