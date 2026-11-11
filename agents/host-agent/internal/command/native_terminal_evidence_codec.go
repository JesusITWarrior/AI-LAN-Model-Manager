package command

// This package-private codec is an offline unsigned evidence foundation only.
// It is not imported by runtime code and carries no signer, trust, receipt,
// execution, or release authority.
import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var errNativeEvidence = errors.New("ERR_NATIVE_EVIDENCE_CODEC")

const (
	maxNativeEvidenceResponseBytes = 512 * 1024
	maxNativeEvidencePayloadBytes  = 768 * 1024
	maxNativeEvidenceDepth         = 16
	maxNativeEvidenceNodes         = 65536
	// The payload may carry base64 for a full 512 KiB response (~683 KiB).
	// Keep aggregate decoded-string budget at the enclosing payload cap so the
	// valid response cap remains round-trippable while parsing stays bounded.
	maxNativeEvidenceStringBytes  = maxNativeEvidencePayloadBytes
	nativeEvidenceResponseDomain  = "lanmm-native-response-bytes-v1\x00"
	nativeEvidenceTupleHashDomain = "lanmm-native-terminal-evidence-tuple-digest-v1\x00"
	nativeEvidenceTupleDomain     = "lanmm-native-terminal-evidence-v1"
	nativeEvidencePayloadDomain   = "lanmm-native-terminal-evidence-payload-v1"
	nativeEvidenceKind            = "agent.command.terminal-evidence"
	nativeEvidenceDisposition     = "evidence-only"
)

var nativeEvidenceID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var nativeEvidenceForbiddenParamKey = regexp.MustCompile(`^(endpoint|url|address|command|shell|header|option|path)$`)
var nativeEvidenceErrorCode = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// Snapshot contains only caller-supplied offline evidence. QueueDigest is checked
// against the explicit JS-produced QueueEncoding; it is never reconstructed from
// a Go map or struct. Raw byte slices are copied before use.
type nativeEvidenceSnapshot struct {
	StoredRequest        []byte
	QueueEncoding        []byte
	QueueDigest          string
	TerminalHostID       string
	TerminalJobID        string
	TerminalRequestID    string
	TerminalState        string
	TerminalRevision     string
	TerminalOccurredAt   string
	ResponseBytes        []byte
	AuthorizationDigest  string
	EvidenceSource       string
	RunnerHold           string
	TrustProvenance      string
	TrustHostID          string
	TrustBindingRevision string
}

type nativeEvidenceTuple struct {
	Domain                     string `json:"domain"`
	HostID                     string `json:"hostId"`
	JobID                      string `json:"jobId"`
	RequestID                  string `json:"requestId"`
	CommandSequence            uint64 `json:"commandSequence"`
	IdempotencyKey             string `json:"idempotencyKey"`
	AuthorizationRequestDigest string `json:"authorizationRequestDigest"`
	StoredQueueDigest          string `json:"storedQueueDigest"`
	TerminalState              string `json:"terminalState"`
	TerminalRevision           string `json:"terminalRevision"`
	ResponseDigest             string `json:"responseDigest"`
	ResponseByteLength         uint64 `json:"responseByteLength"`
	EvidenceKind               string `json:"evidenceKind"`
	HoldClass                  string `json:"holdClass"`
}

type nativeEvidencePayload struct {
	Domain         string              `json:"domain"`
	Kind           string              `json:"kind"`
	Version        uint64              `json:"version"`
	Disposition    string              `json:"disposition"`
	Tuple          nativeEvidenceTuple `json:"tuple"`
	ResponseBase64 string              `json:"responseBase64"`
	EvidenceSource string              `json:"evidenceSource"`
}

// NativeEvidenceResult is evidence-only. False fields are explicit non-authority
// markers, not permission decisions or verified claims.
type nativeEvidenceResult struct {
	PayloadBytes         []byte
	ResponseBytes        []byte
	Tuple                nativeEvidenceTuple
	TupleDigest          string
	CallerTrustAssertion string
	ReleasePermitted     bool
	ExecutionPermitted   bool
	ReceiptCommitted     bool
}

func evidenceDigest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func domainDigest(domain string, raw []byte) string {
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}

// strictEvidenceValue validates the complete JSON token stream before unmarshalling:
// duplicate decoded keys, invalid UTF-8/BOM/surrogates, unsafe/noninteger numbers,
// trailing bytes and resource limits fail closed. Values retain json.Number lexemes.
func strictEvidenceValue(raw []byte, maxBytes int) (any, error) {
	if len(raw) == 0 || len(raw) > maxBytes || bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) || !utf8.Valid(raw) || !wellFormedEvidenceStrings(raw) {
		return nil, errNativeEvidence
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes, stringBytes := 0, 0
	var walk func(int) (any, error)
	walk = func(depth int) (any, error) {
		if depth > maxNativeEvidenceDepth || nodes >= maxNativeEvidenceNodes {
			return nil, errNativeEvidence
		}
		nodes++
		t, err := d.Token()
		if err != nil {
			return nil, errNativeEvidence
		}
		switch x := t.(type) {
		case json.Delim:
			switch x {
			case '{':
				m := make(map[string]any)
				for d.More() {
					kt, e := d.Token()
					if e != nil {
						return nil, errNativeEvidence
					}
					k, ok := kt.(string)
					if !ok {
						return nil, errNativeEvidence
					}
					if _, exists := m[k]; exists {
						return nil, errNativeEvidence
					}
					stringBytes += len(k)
					if stringBytes > maxNativeEvidenceStringBytes {
						return nil, errNativeEvidence
					}
					v, e := walk(depth + 1)
					if e != nil {
						return nil, errNativeEvidence
					}
					m[k] = v
				}
				end, e := d.Token()
				if e != nil || end != json.Delim('}') {
					return nil, errNativeEvidence
				}
				return m, nil
			case '[':
				a := make([]any, 0)
				for d.More() {
					v, e := walk(depth + 1)
					if e != nil {
						return nil, errNativeEvidence
					}
					a = append(a, v)
				}
				end, e := d.Token()
				if e != nil || end != json.Delim(']') {
					return nil, errNativeEvidence
				}
				return a, nil
			default:
				return nil, errNativeEvidence
			}
		case string:
			stringBytes += len(x)
			if stringBytes > maxNativeEvidenceStringBytes {
				return nil, errNativeEvidence
			}
			return x, nil
		case json.Number:
			s := string(x)
			if s == "-0" || strings.ContainsAny(s, ".eE+") {
				return nil, errNativeEvidence
			}
			n, e := strconv.ParseInt(s, 10, 64)
			if e != nil || n < -int64(maxSafeInteger) || n > int64(maxSafeInteger) {
				return nil, errNativeEvidence
			}
			return x, nil
		case nil, bool:
			return x, nil
		default:
			return nil, errNativeEvidence
		}
	}
	v, err := walk(0)
	if err != nil {
		return nil, errNativeEvidence
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errNativeEvidence
	}
	return v, nil
}

func wellFormedEvidenceStrings(raw []byte) bool {
	// encoding/json replaces lone UTF-16 surrogates, so validate escapes before decoding.
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
		n, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if n >= 0xD800 && n <= 0xDBFF {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, e := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if e != nil || low < 0xDC00 || low > 0xDFFF {
				return false
			}
			i += 6
		} else if n >= 0xDC00 && n <= 0xDFFF {
			return false
		}
	}
	return true
}

func canonicalEvidenceDomain(v any) bool {
	switch x := v.(type) {
	case nil, bool, json.Number:
		return true
	case string:
		for _, r := range x {
			if r < 0x20 || r > 0x7e {
				return false
			}
		}
		return true
	case []any:
		for _, item := range x {
			if !canonicalEvidenceDomain(item) {
				return false
			}
		}
		return true
	case map[string]any:
		for key, item := range x {
			if key == "" || !canonicalEvidenceDomain(key) || nativeEvidenceForbiddenParamKey.MatchString(key) || !canonicalEvidenceDomain(item) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func evidenceObject(v any, keys ...string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != len(keys) {
		return nil, errNativeEvidence
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return nil, errNativeEvidence
		}
	}
	return m, nil
}
func evidenceString(m map[string]any, key string) (string, bool) {
	v, ok := m[key].(string)
	return v, ok
}
func evidenceUint(m map[string]any, key string) (uint64, bool) {
	n, ok := m[key].(json.Number)
	if !ok {
		return 0, false
	}
	v, e := strconv.ParseUint(string(n), 10, 64)
	return v, e == nil && v <= maxSafeInteger
}
func evidenceStamp(s string) bool {
	if len(s) != 24 {
		return false
	}
	t, err := time.Parse("2006-01-02T15:04:05.000Z", s)
	return err == nil && t.UTC().Format("2006-01-02T15:04:05.000Z") == s
}
func evidenceID(s string) bool { return nativeEvidenceID.MatchString(s) }
func evidenceHex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}

func parseNativeEvidenceStoredRequest(s nativeEvidenceSnapshot) (Request, error) {
	requestValue, err := strictEvidenceValue(s.StoredRequest, 550000)
	if err != nil {
		return Request{}, err
	}
	requestMap, err := evidenceObject(requestValue, "requestId", "jobId", "hostId", "operation", "idempotencyKey", "sequence", "deadline", "params", "capability")
	if err != nil {
		return Request{}, err
	}
	capMap, err := evidenceObject(requestMap["capability"], "operation", "targetKind", "targetId", "hostId", "modelId", "requestDigest", "expiresAt")
	if err != nil {
		return Request{}, err
	}
	for _, key := range []string{"requestId", "jobId", "hostId", "operation", "idempotencyKey", "deadline"} {
		x, ok := evidenceString(requestMap, key)
		if !ok || !evidenceID(x) && key != "deadline" {
			return Request{}, errNativeEvidence
		}
	}
	seq, ok := evidenceUint(requestMap, "sequence")
	if !ok || seq == 0 {
		return Request{}, errNativeEvidence
	}
	deadline, _ := evidenceString(requestMap, "deadline")
	if !evidenceStamp(deadline) {
		return Request{}, errNativeEvidence
	}
	for _, key := range []string{"operation", "targetKind", "targetId", "hostId", "requestDigest", "expiresAt"} {
		x, ok := evidenceString(capMap, key)
		if !ok {
			return Request{}, errNativeEvidence
		}
		if key == "expiresAt" {
			if !evidenceStamp(x) {
				return Request{}, errNativeEvidence
			}
		} else if key == "requestDigest" {
			if !evidenceHex(x) {
				return Request{}, errNativeEvidence
			}
		} else if !evidenceID(x) {
			return Request{}, errNativeEvidence
		}
	}
	if capMap["modelId"] != nil {
		x, ok := capMap["modelId"].(string)
		if !ok || !evidenceID(x) {
			return Request{}, errNativeEvidence
		}
	}
	var req Request
	if json.Unmarshal(s.StoredRequest, &req) != nil {
		return Request{}, errNativeEvidence
	}
	if req.Sequence != seq || req.Sequence > maxSafeInteger || !evidenceID(req.Capability.TargetID) || !evidenceID(req.Capability.TargetKind) || req.Capability.HostID != req.HostID || allowed[req.Operation] == "" || allowed[req.Operation] != req.Capability.Operation || !targetMatches(req) {
		return Request{}, errNativeEvidence
	}
	maxParams := 32768
	if req.Operation == "inference.chat" || req.Operation == StreamOperation {
		maxParams = 524288
	}
	if req.Operation == StreamOperation {
		maxParams = 550000
	}
	if req.Operation == PeerSourceOperation || req.Operation == PeerDestinationOperation {
		maxParams = 768 << 10
	}
	if len(req.Params) > maxParams {
		return Request{}, errNativeEvidence
	}
	stored, err := strictEvidenceValue(s.QueueEncoding, 32768)
	if err != nil {
		return Request{}, err
	}
	if !bytes.Equal(bytes.TrimSpace(s.QueueEncoding), s.QueueEncoding) {
		return Request{}, errNativeEvidence
	}
	if !evidenceHex(s.QueueDigest) || evidenceDigest(s.QueueEncoding) != s.QueueDigest {
		return Request{}, errNativeEvidence
	}
	if !canonicalEvidenceDomain(requestMap["params"]) || !reflect.DeepEqual(requestValue, stored) {
		return Request{}, errNativeEvidence
	}
	if req.Operation == "inference.chat" {
		if p, e := parseInferenceChat(req.Params); e != nil || p.RequestID != req.RequestID {
			return Request{}, errNativeEvidence
		}
	}
	if req.Operation == "install" {
		if _, e := ParseArtifactInstallParams(req.Params); e != nil {
			return Request{}, errNativeEvidence
		}
	}
	auth, err := authorizationDigest(req)
	if err != nil || auth != s.AuthorizationDigest || req.Capability.RequestDigest != auth {
		return Request{}, errNativeEvidence
	}
	return req, nil
}

func nativeEvidenceTupleFor(s nativeEvidenceSnapshot) (nativeEvidenceTuple, []byte, error) {
	req, err := parseNativeEvidenceStoredRequest(s)
	if err != nil {
		return nativeEvidenceTuple{}, nil, err
	}
	if !evidenceID(s.TerminalHostID) || !evidenceID(s.TerminalJobID) || !evidenceID(s.TerminalRequestID) || !evidenceID(s.TerminalRevision) || !evidenceStamp(s.TerminalOccurredAt) || !evidenceHex(s.QueueDigest) {
		return nativeEvidenceTuple{}, nil, errNativeEvidence
	}
	if s.TerminalHostID != req.HostID || s.TerminalJobID != req.JobID || s.TerminalRequestID != req.RequestID {
		return nativeEvidenceTuple{}, nil, errNativeEvidence
	}
	switch s.TerminalState {
	case "timed-out", "failed", "succeeded", "cancelled":
	default:
		return nativeEvidenceTuple{}, nil, errNativeEvidence
	}
	switch s.RunnerHold {
	case "unknown", "in_flight", "retained", "pending_uncertain":
	default:
		return nativeEvidenceTuple{}, nil, errNativeEvidence
	}
	switch s.EvidenceSource {
	case "retained_same_process", "explicit_snapshot", "synthetic":
	default:
		return nativeEvidenceTuple{}, nil, errNativeEvidence
	}
	switch s.TrustProvenance {
	case "unavailable":
		if s.TrustHostID != "" || s.TrustBindingRevision != "" {
			return nativeEvidenceTuple{}, nil, errNativeEvidence
		}
	case "unverified":
		if (s.TrustHostID != "" && !evidenceID(s.TrustHostID)) || (s.TrustBindingRevision != "" && !evidenceID(s.TrustBindingRevision)) {
			return nativeEvidenceTuple{}, nil, errNativeEvidence
		}
	case "verified_current":
		if !evidenceID(s.TrustHostID) || !evidenceID(s.TrustBindingRevision) || s.TrustHostID != req.HostID {
			return nativeEvidenceTuple{}, nil, errNativeEvidence
		}
	default:
		return nativeEvidenceTuple{}, nil, errNativeEvidence
	}
	if len(s.ResponseBytes) == 0 || len(s.ResponseBytes) > maxNativeEvidenceResponseBytes {
		return nativeEvidenceTuple{}, nil, errNativeEvidence
	}
	responseRaw := append([]byte(nil), s.ResponseBytes...)
	responseValue, err := strictEvidenceValue(responseRaw, maxNativeEvidenceResponseBytes)
	if err != nil {
		return nativeEvidenceTuple{}, nil, err
	}
	respMap, err := evidenceObject(responseValue, "requestId", "jobId", "hostId", "sequence", "status", "progress", "observedAt", "observation", "errorCode")
	if err != nil {
		return nativeEvidenceTuple{}, nil, err
	}
	for k, want := range map[string]string{"requestId": req.RequestID, "jobId": req.JobID, "hostId": req.HostID} {
		got, ok := evidenceString(respMap, k)
		if !ok || got != want {
			return nativeEvidenceTuple{}, nil, errNativeEvidence
		}
	}
	seq, ok := evidenceUint(respMap, "sequence")
	if !ok || seq != req.Sequence {
		return nativeEvidenceTuple{}, nil, errNativeEvidence
	}
	status, ok := evidenceString(respMap, "status")
	if !ok {
		return nativeEvidenceTuple{}, nil, errNativeEvidence
	}
	switch status {
	case "failed", "succeeded", "cancelled":
	default:
		return nativeEvidenceTuple{}, nil, errNativeEvidence
	}
	observed, ok := evidenceString(respMap, "observedAt")
	if !ok || !evidenceStamp(observed) {
		return nativeEvidenceTuple{}, nil, errNativeEvidence
	}
	if p := respMap["progress"]; p != nil {
		n, ok := p.(json.Number)
		if !ok {
			return nativeEvidenceTuple{}, nil, errNativeEvidence
		}
		v, e := strconv.ParseUint(string(n), 10, 8)
		if e != nil || v > 100 {
			return nativeEvidenceTuple{}, nil, errNativeEvidence
		}
	}
	if errCode := respMap["errorCode"]; errCode != nil {
		x, ok := errCode.(string)
		if !ok || !nativeEvidenceErrorCode.MatchString(x) {
			return nativeEvidenceTuple{}, nil, errNativeEvidence
		}
	}
	if status == "failed" && respMap["errorCode"] == nil || status != "failed" && respMap["errorCode"] != nil {
		return nativeEvidenceTuple{}, nil, errNativeEvidence
	}
	responseBytesDigest := domainDigest(nativeEvidenceResponseDomain, responseRaw)
	tuple := nativeEvidenceTuple{Domain: nativeEvidenceTupleDomain, HostID: req.HostID, JobID: req.JobID, RequestID: req.RequestID, CommandSequence: req.Sequence, IdempotencyKey: req.IdempotencyKey, AuthorizationRequestDigest: s.AuthorizationDigest, StoredQueueDigest: s.QueueDigest, TerminalState: s.TerminalState, TerminalRevision: s.TerminalRevision, ResponseDigest: responseBytesDigest, ResponseByteLength: uint64(len(responseRaw)), EvidenceKind: status, HoldClass: s.RunnerHold}
	return tuple, responseRaw, nil
}

func nativeTupleEncoding(t nativeEvidenceTuple) ([]byte, error) {
	values := []any{t.Domain, t.HostID, t.JobID, t.RequestID, t.CommandSequence, t.IdempotencyKey, t.AuthorizationRequestDigest, t.StoredQueueDigest, t.TerminalState, t.TerminalRevision, t.ResponseDigest, t.ResponseByteLength, t.EvidenceKind, t.HoldClass}
	return json.Marshal(values)
}
func nativeTupleDigest(t nativeEvidenceTuple) (string, error) {
	raw, err := nativeTupleEncoding(t)
	if err != nil {
		return "", err
	}
	return domainDigest(nativeEvidenceTupleHashDomain, raw), nil
}
func nativePayload(t nativeEvidenceTuple, response []byte, source string) nativeEvidencePayload {
	return nativeEvidencePayload{Domain: nativeEvidencePayloadDomain, Kind: nativeEvidenceKind, Version: 1, Disposition: nativeEvidenceDisposition, Tuple: t, ResponseBase64: base64.StdEncoding.EncodeToString(response), EvidenceSource: source}
}
func nativePayloadBytes(p nativeEvidencePayload) ([]byte, error) { return json.Marshal(p) }

func encodeNativeTerminalEvidence(s nativeEvidenceSnapshot) (nativeEvidenceResult, error) {
	t, response, err := nativeEvidenceTupleFor(s)
	if err != nil {
		return nativeEvidenceResult{}, errNativeEvidence
	}
	p := nativePayload(t, response, s.EvidenceSource)
	raw, err := nativePayloadBytes(p)
	if err != nil || len(raw) > maxNativeEvidencePayloadBytes {
		return nativeEvidenceResult{}, errNativeEvidence
	}
	digest, err := nativeTupleDigest(t)
	if err != nil {
		return nativeEvidenceResult{}, errNativeEvidence
	}
	return nativeEvidenceResult{PayloadBytes: append([]byte(nil), raw...), ResponseBytes: append([]byte(nil), response...), Tuple: t, TupleDigest: digest, CallerTrustAssertion: s.TrustProvenance}, nil
}

func decodeNativeTerminalEvidence(raw []byte, s nativeEvidenceSnapshot) (nativeEvidenceResult, error) {
	if len(raw) == 0 || len(raw) > maxNativeEvidencePayloadBytes {
		return nativeEvidenceResult{}, errNativeEvidence
	}
	owned := append([]byte(nil), raw...)
	value, err := strictEvidenceValue(owned, maxNativeEvidencePayloadBytes)
	if err != nil {
		return nativeEvidenceResult{}, errNativeEvidence
	}
	m, err := evidenceObject(value, "domain", "kind", "version", "disposition", "tuple", "responseBase64", "evidenceSource")
	if err != nil {
		return nativeEvidenceResult{}, errNativeEvidence
	}
	tm, err := evidenceObject(m["tuple"], "domain", "hostId", "jobId", "requestId", "commandSequence", "idempotencyKey", "authorizationRequestDigest", "storedQueueDigest", "terminalState", "terminalRevision", "responseDigest", "responseByteLength", "evidenceKind", "holdClass")
	if err != nil {
		return nativeEvidenceResult{}, errNativeEvidence
	}
	var p nativeEvidencePayload
	if json.Unmarshal(owned, &p) != nil || p.Domain != nativeEvidencePayloadDomain || p.Kind != nativeEvidenceKind || p.Version != 1 || p.Disposition != nativeEvidenceDisposition {
		return nativeEvidenceResult{}, errNativeEvidence
	}
	if p.EvidenceSource != "synthetic" && p.EvidenceSource != "retained_same_process" && p.EvidenceSource != "explicit_snapshot" {
		return nativeEvidenceResult{}, errNativeEvidence
	}
	if len(p.ResponseBase64) > 4*((maxNativeEvidenceResponseBytes+2)/3) {
		return nativeEvidenceResult{}, errNativeEvidence
	}
	encoded, err := base64.StdEncoding.Strict().DecodeString(p.ResponseBase64)
	if err != nil || base64.StdEncoding.EncodeToString(encoded) != p.ResponseBase64 || len(encoded) > maxNativeEvidenceResponseBytes || !bytes.Equal(encoded, s.ResponseBytes) {
		return nativeEvidenceResult{}, errNativeEvidence
	}
	if p.EvidenceSource != s.EvidenceSource {
		return nativeEvidenceResult{}, errNativeEvidence
	}
	expected := s
	t, response, err := nativeEvidenceTupleFor(expected)
	if err != nil {
		return nativeEvidenceResult{}, errNativeEvidence
	}
	want := nativePayload(t, response, p.EvidenceSource)
	wantMap, _ := strictEvidenceValue(mustNativePayloadBytes(want), maxNativeEvidencePayloadBytes)
	if !reflect.DeepEqual(value, wantMap) {
		return nativeEvidenceResult{}, errNativeEvidence
	}
	_ = tm
	digest, err := nativeTupleDigest(t)
	if err != nil {
		return nativeEvidenceResult{}, errNativeEvidence
	}
	return nativeEvidenceResult{PayloadBytes: owned, ResponseBytes: append([]byte(nil), response...), Tuple: t, TupleDigest: digest, CallerTrustAssertion: expected.TrustProvenance}, nil
}
func mustNativePayloadBytes(p nativeEvidencePayload) []byte { b, _ := nativePayloadBytes(p); return b }
