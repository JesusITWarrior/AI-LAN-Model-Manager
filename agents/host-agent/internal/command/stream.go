package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider/ollama"
)

const StreamOperation = "inference.chat.stream"
const maxSafeInteger uint64 = 9007199254740991

var ErrStream = errors.New("invalid or incomplete stream")

// StreamEmitter publishes exactly these serialized UTF-8 bytes synchronously.
// Blocking implementations MUST select on ctx.Done(). No queues or goroutines
// are owned by this interface. Returning an error ends execution, not a retry.
// Bytes are borrowed read-only for the call: retain only a bounded private copy,
// never mutate the supplied slice. Publishers must not reuse it concurrently.
type StreamEmitter func(context.Context, []byte) error

// StreamAdapter is a local execution interface, not a buffered transport API.
// Implementations retain admission ownership through synchronous publication.
type StreamAdapter interface {
	ExecuteStream(context.Context, Request, StreamEmitter) error
}

type StreamParams struct {
	SchemaVersion      uint64          `json:"schemaVersion"`
	Chat               json.RawMessage `json:"chat"`
	UpstreamFrameBytes uint64          `json:"upstreamFrameBytes"`
	MaxEventBytes      uint64          `json:"maxEventBytes"`
	MaxTotalEventBytes uint64          `json:"maxTotalEventBytes"`
	MaxEvents          uint64          `json:"maxEvents"`
}
type StreamEvent struct {
	SchemaVersion uint64            `json:"schemaVersion"`
	HostID        string            `json:"hostId"`
	JobID         string            `json:"jobId"`
	RequestID     string            `json:"requestId"`
	CommandDigest string            `json:"commandDigest"`
	Index         uint64            `json:"index"`
	Kind          string            `json:"kind"`
	Chunk         *ollama.ChatChunk `json:"chunk"`
	ErrorCode     *string           `json:"errorCode"`
}

// strictStreamJSON rejects duplicates, missing/unknown keys, null non-pointers,
// noncanonical integer tokens, invalid UTF-8, trailing data and excessive depth.
// RawMessage delegates its schema to the caller, but not duplicate detection.
func strictStreamJSON(raw []byte, target any) error {
	if bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) || !utf8.Valid(raw) || !validStreamEscapes(raw) {
		return ErrStream
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) (any, error)
	walk = func(depth int) (any, error) {
		if depth > 16 {
			return nil, ErrStream
		}
		t, e := d.Token()
		if e != nil {
			return nil, ErrStream
		}
		switch t {
		case json.Delim('{'):
			m := map[string]any{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return nil, ErrStream
				}
				s, ok := k.(string)
				if !ok {
					return nil, ErrStream
				}
				if _, ok = m[s]; ok {
					return nil, ErrStream
				}
				v, e := walk(depth + 1)
				if e != nil {
					return nil, e
				}
				m[s] = v
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return nil, ErrStream
			}
			return m, nil
		case json.Delim('['):
			a := []any{}
			for d.More() {
				v, e := walk(depth + 1)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return nil, ErrStream
			}
			return a, nil
		}
		return t, nil
	}
	value, err := walk(0)
	if err != nil {
		return err
	}
	if _, err = d.Token(); err != io.EOF {
		return ErrStream
	}
	var shape func(any, reflect.Type) bool
	shape = func(v any, t reflect.Type) bool {
		if t == reflect.TypeOf(json.RawMessage{}) {
			return v != nil
		}
		if t.Kind() == reflect.Pointer {
			if v == nil {
				return true
			}
			return shape(v, t.Elem())
		}
		if v == nil {
			return false
		}
		switch t.Kind() {
		case reflect.Struct:
			m, ok := v.(map[string]any)
			if !ok {
				return false
			}
			required := 0
			for i := 0; i < t.NumField(); i++ {
				f := t.Field(i)
				tag := strings.Split(f.Tag.Get("json"), ",")
				if tag[0] == "" || tag[0] == "-" {
					continue
				}
				item, exists := m[tag[0]]
				optional := len(tag) > 1 && tag[1] == "omitempty"
				if exists && optional && item == nil {
					return false
				}
				if !exists && optional {
					continue
				}
				required++
				if !exists || !shape(item, f.Type) {
					return false
				}
			}
			return len(m) == required
		case reflect.Slice:
			a, ok := v.([]any)
			if !ok {
				return false
			}
			for _, item := range a {
				if !shape(item, t.Elem()) {
					return false
				}
			}
			return true
		case reflect.Uint64, reflect.Int64:
			n, ok := v.(json.Number)
			if !ok {
				return false
			}
			text := string(n)
			return text != "" && text != "-0" && !strings.ContainsAny(text, ".eE+")
		}
		return true
	}
	if !shape(value, reflect.TypeOf(target).Elem()) {
		return ErrStream
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return ErrStream
	}
	return nil
}

func parseStreamParams(raw json.RawMessage, requestID string) (StreamParams, error) {
	var p StreamParams
	if len(raw) > 550000 || strictStreamJSON(raw, &p) != nil || p.SchemaVersion != 1 || p.UpstreamFrameBytes != ollama.MaximumChatStreamFrameSize || p.MaxEventBytes < 1024 || p.MaxEventBytes > 131072 || p.MaxTotalEventBytes < p.MaxEventBytes || p.MaxTotalEventBytes > 1048576 || p.MaxEvents < 1 || p.MaxEvents > 4096 {
		return p, ErrStream
	}
	// Require the existing full chat schema, not its permissive optional decoder.
	var chat struct {
		ProviderID       string `json:"providerId"`
		ModelID          string `json:"modelId"`
		Model            string `json:"model"`
		RequestID        string `json:"requestId"`
		MaxRequestBytes  int64  `json:"maxRequestBytes"`
		MaxResponseBytes int64  `json:"maxResponseBytes"`
		Messages         []struct {
			Role          string `json:"role"`
			ContentBase64 string `json:"contentBase64"`
		} `json:"messages"`
		TemperatureMilli *int64 `json:"temperatureMilli"`
		MaxTokens        *int64 `json:"maxTokens"`
	}
	if strictStreamJSON(p.Chat, &chat) != nil {
		return p, ErrStream
	}
	// Match TS's decoded typed-chat byte accounting, not whitespace/escape
	// spelling of an equivalent input JSON object.
	p.Chat, _ = json.Marshal(chat)
	encoded, err := json.Marshal(p)
	if err != nil || len(encoded) > 524288 {
		return p, ErrStream
	}
	c, err := parseInferenceChat(p.Chat)
	if err != nil || c.RequestID != requestID || c.Model != chat.Model || !streamModel.MatchString(c.Model) {
		return p, ErrStream
	}
	return p, nil
}

// StreamValidator is request-bound, ordered, bounded and fail-closed. Finish is
// mandatory: exhausted input is never evidence of provider completion. Like its
// synchronous emitter, this validator is single-consumer, not goroutine-safe.
type StreamValidator struct {
	request           Request
	params            StreamParams
	next, total       uint64
	terminal, invalid bool
}

func NewStreamValidator(r Request) (*StreamValidator, error) {
	r = snapshotStreamRequest(r)
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, ErrStream
	}
	if _, err = ParseStreamCommand(raw); err != nil {
		return nil, err
	}
	p, e := parseStreamParams(r.Params, r.RequestID)
	if e != nil || r.Operation != StreamOperation {
		return nil, ErrStream
	}
	digest, e := authorizationDigest(r)
	if e != nil || digest != r.Capability.RequestDigest {
		return nil, ErrStream
	}
	return &StreamValidator{request: r, params: p}, nil
}
func (v *StreamValidator) Accept(raw []byte) (event StreamEvent, err error) {
	if v == nil {
		return event, ErrStream
	}
	defer func() {
		if err != nil {
			v.invalid = true
		}
	}()
	if v.invalid || v.terminal || uint64(len(raw)) > v.params.MaxEventBytes || uint64(len(raw)) > v.params.MaxTotalEventBytes-v.total || v.next >= v.params.MaxEvents || strictStreamJSON(raw, &event) != nil {
		return event, ErrStream
	}
	r := v.request
	if event.SchemaVersion != 1 || event.HostID != r.HostID || event.JobID != r.JobID || event.RequestID != r.RequestID || event.CommandDigest != r.Capability.RequestDigest || event.Index != v.next {
		return event, ErrStream
	}
	switch event.Kind {
	case "chunk", "succeeded":
		c := event.Chunk
		chat, _ := parseInferenceChat(v.params.Chat)
		if event.ErrorCode != nil || c == nil || c.ID != r.RequestID || c.Object != "chat.completion.chunk" || c.Model != chat.Model || len(c.Choices) != 1 {
			return event, ErrStream
		}
		choice := c.Choices[0]
		if choice.Index != 0 || choice.Delta.Role != "assistant" || !utf8.ValidString(choice.Delta.Content) {
			return event, ErrStream
		}
		if event.Kind == "chunk" {
			if choice.FinishReason != nil || c.Usage != nil {
				return event, ErrStream
			}
		} else {
			u := c.Usage
			if choice.FinishReason == nil || (*choice.FinishReason != "stop" && *choice.FinishReason != "length") || u == nil || u.PromptTokens > maxSafeInteger || u.CompletionTokens > maxSafeInteger-u.PromptTokens || u.TotalTokens != u.PromptTokens+u.CompletionTokens {
				return event, ErrStream
			}
		}
	case "failed", "cancelled":
		want := "STREAM_FAILED"
		if event.Kind == "cancelled" {
			want = "CANCELLED"
		}
		if event.Chunk != nil || event.ErrorCode == nil || *event.ErrorCode != want {
			return event, ErrStream
		}
	default:
		return event, ErrStream
	}
	v.next++
	v.total += uint64(len(raw))
	v.terminal = event.Kind != "chunk"
	return event, nil
}
func (v *StreamValidator) Finish() error {
	if v == nil || v.invalid || !v.terminal {
		return ErrStream
	}
	return nil
}

// ExecuteStream is deliberately absent from Execute's operation grammar. Only
// the authenticated local executor may pass a request and context-aware emitter.
func (r *Registry) ExecuteStream(ctx context.Context, request Request, emit StreamEmitter) error {
	request = snapshotStreamRequest(request)
	if r == nil || emit == nil {
		return ErrStream
	}
	validator, err := NewStreamValidator(request)
	if err != nil {
		return err
	}
	params, _ := parseInferenceChat(validator.params.Chat)
	// The nested model identity must be the capability target (targetMatches only
	// understands ordinary flat command parameters).
	if request.Capability.TargetKind != "model" || request.Capability.ModelID == nil || *request.Capability.ModelID != params.ModelID || request.Capability.TargetID != params.ModelID {
		return ErrCommand
	}
	r.mu.Lock()
	adapter := r.clients[params.ProviderID]
	r.mu.Unlock()
	chat, ok := adapter.(interface {
		ChatStream(context.Context, ollama.ChatRequest, func(context.Context, ollama.ChatChunk) error) error
	})
	if !ok {
		return NoProvider
	}
	inventory, ok := adapter.(installedObserver)
	if !ok {
		return ErrOperationUnavailable
	}
	models, err := inventory.ListInstalled(ctx)
	if err != nil {
		return err
	}
	matched := false
	for _, m := range models {
		if m.ProviderID == params.ProviderID && m.ModelID == params.ModelID && m.CanonicalName == params.Model {
			matched = true
			break
		}
	}
	if !matched {
		return ErrRuntimeStateMismatch
	}
	running, ok := adapter.(runtimeObserver)
	if !ok {
		return ErrOperationUnavailable
	}
	loaded, err := running.ListRunning(ctx)
	if err != nil {
		return err
	}
	r.syncRunning(loaded)
	handle, err := r.Acquire(ctx, params.ProviderID, params.Model)
	if err != nil {
		return err
	}
	defer func() { _ = r.Complete(context.Background(), handle) }()
	serialize := func(kind string, chunk *ollama.ChatChunk, code *string) ([]byte, error) {
		event := StreamEvent{SchemaVersion: 1, HostID: request.HostID, JobID: request.JobID, RequestID: request.RequestID, CommandDigest: request.Capability.RequestDigest, Index: validator.next, Kind: kind, Chunk: chunk, ErrorCode: code}
		return json.Marshal(event)
	}
	send := func(publishContext context.Context, kind string, chunk *ollama.ChatChunk, code *string) error {
		if err := publishContext.Err(); err != nil {
			return err
		}
		raw, err := serialize(kind, chunk, code)
		if err != nil {
			return ErrStream
		}
		if _, err = validator.Accept(raw); err != nil {
			return err
		}
		return emit(publishContext, raw)
	}
	messages := make([]ollama.ChatMessage, len(params.Messages))
	for i, m := range params.Messages {
		messages[i] = ollama.ChatMessage{Role: m.Role, Content: m.Content}
	}
	var temperature *float64
	if params.TemperatureMilli != nil {
		v := float64(*params.TemperatureMilli) / 1000
		temperature = &v
	}
	var tokens *uint64
	if params.MaxTokens != nil {
		v := uint64(*params.MaxTokens)
		tokens = &v
	}
	var terminal *ollama.ChatChunk
	var publishErr error
	err = chat.ChatStream(ctx, ollama.ChatRequest{RequestID: params.RequestID, Model: params.Model, Messages: messages, Temperature: temperature, MaxTokens: tokens, MaxRequestBytes: uint64(params.MaxRequestBytes), MaxResponseBytes: uint64(params.MaxResponseBytes)}, func(c context.Context, chunk ollama.ChatChunk) error {
		if e := c.Err(); e != nil {
			return e
		}
		if terminal != nil {
			return ErrStream
		}
		if len(chunk.Choices) == 1 && chunk.Choices[0].FinishReason != nil {
			terminal = &chunk
			return nil
		}
		publishErr = send(c, "chunk", &chunk, nil)
		return publishErr
	})
	if publishErr != nil {
		return publishErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil && terminal != nil {
		// Preflight the provisional terminal before assigning terminal ownership.
		// Unsafe provider uint64 usage (or a terminal too large for the public
		// limits) is a failure, never an externally visible success attempt.
		raw, marshalErr := serialize("succeeded", terminal, nil)
		candidate := *validator
		if marshalErr == nil {
			_, marshalErr = candidate.Accept(raw)
		}
		if marshalErr == nil {
			return send(ctx, "succeeded", terminal, nil)
		}
		err = ErrStream
	}
	code := "STREAM_FAILED"
	kind := "failed"
	if errors.Is(err, context.Canceled) {
		kind = "cancelled"
		code = "CANCELLED"
	}
	if e := send(ctx, kind, nil, &code); e != nil {
		return e
	}
	if err == nil {
		return ErrStream
	}
	return err
}

var streamModel = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{0,255}$`)

func validStreamEscapes(raw []byte) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		n, e := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if e != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, e := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if e != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

// ParseStreamCommand is the separate local-only wire parser; legacy dispatch
// remains closed. Clock/capability expiry is checked by ExecuteStream.
func ParseStreamCommand(raw []byte) (Request, error) {
	var r Request
	if len(raw) > 550000 || strictStreamJSON(raw, &r) != nil || r.Operation != StreamOperation || r.Sequence < 1 || r.Sequence > maxSafeInteger || !identifier.MatchString(r.RequestID) || !identifier.MatchString(r.JobID) || !identifier.MatchString(r.HostID) || !identifier.MatchString(r.IdempotencyKey) {
		return r, ErrStream
	}
	p, e := parseStreamParams(r.Params, r.RequestID)
	if e != nil {
		return r, e
	}
	chat, _ := parseInferenceChat(p.Chat)
	c := r.Capability
	if c.Operation != "model-inference" || c.HostID != r.HostID || c.TargetKind != "model" || c.ModelID == nil || *c.ModelID != chat.ModelID || c.TargetID != chat.ModelID || !digestPattern.MatchString(c.RequestDigest) {
		return r, ErrStream
	}
	for _, stamp := range []string{r.Deadline, c.ExpiresAt} {
		t, e := time.Parse("2006-01-02T15:04:05.000Z", stamp)
		if e != nil || t.Format("2006-01-02T15:04:05.000Z") != stamp {
			return r, ErrStream
		}
	}
	digest, e := authorizationDigest(r)
	if e != nil || digest != c.RequestDigest {
		return r, ErrStream
	}
	return r, nil
}

// snapshotStreamRequest takes ownership of all caller-owned mutable fields.
// Callers must not mutate input concurrently with the entry snapshot itself;
// after entry, execution/validation never observes later caller mutations.
func snapshotStreamRequest(r Request) Request {
	r.Params = append(json.RawMessage(nil), r.Params...)
	if r.Capability.ModelID != nil {
		modelID := *r.Capability.ModelID
		r.Capability.ModelID = &modelID
	}
	return r
}

// DecodeStreamWireJSON preserves duplicate/BOM/UTF-8 evidence at authenticated relay envelopes.
// The caller supplies the exact typed envelope and an independent byte bound.
func DecodeStreamWireJSON(raw []byte, target any) error { return strictStreamJSON(raw, target) }
