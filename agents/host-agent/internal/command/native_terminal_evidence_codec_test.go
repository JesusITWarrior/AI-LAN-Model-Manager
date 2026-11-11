package command

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const nativeEvidencePayloadGoldenBase64 = "eyJkb21haW4iOiJsYW5tbS1uYXRpdmUtdGVybWluYWwtZXZpZGVuY2UtcGF5bG9hZC12MSIsImtpbmQiOiJhZ2VudC5jb21tYW5kLnRlcm1pbmFsLWV2aWRlbmNlIiwidmVyc2lvbiI6MSwiZGlzcG9zaXRpb24iOiJldmlkZW5jZS1vbmx5IiwidHVwbGUiOnsiZG9tYWluIjoibGFubW0tbmF0aXZlLXRlcm1pbmFsLWV2aWRlbmNlLXYxIiwiaG9zdElkIjoiaG9zdC0xIiwiam9iSWQiOiJqb2ItMSIsInJlcXVlc3RJZCI6InJlcXVlc3QtMSIsImNvbW1hbmRTZXF1ZW5jZSI6NywiaWRlbXBvdGVuY3lLZXkiOiJpZGVtLTEiLCJhdXRob3JpemF0aW9uUmVxdWVzdERpZ2VzdCI6ImQ3YzNhNGQ3NWRkM2M3N2JjN2M0YjJiMDJhOWE5NjY2MGFiYjYwY2IzOGMwYzE2MTg3ZjdmNTYzYzViN2I2OTUiLCJzdG9yZWRRdWV1ZURpZ2VzdCI6ImFiNmMyNDcwNDYzZmVmZmQ2NTQyYWEyNGY0YjdjZGNjMzk5ZDkyN2Q5MzM4MDU4Y2MyNGMwNzM2YjViMmJhZjUiLCJ0ZXJtaW5hbFN0YXRlIjoidGltZWQtb3V0IiwidGVybWluYWxSZXZpc2lvbiI6Imhpc3RvcnktMSIsInJlc3BvbnNlRGlnZXN0IjoiYmJkNTFjNmE0NDZkODZjZjZmOWQxNWI0YmY5ZGU5N2FhYWU3YmZkNWE0OTZmNDIxMmEyZmVmYzM2Y2M3ZmUxNyIsInJlc3BvbnNlQnl0ZUxlbmd0aCI6MjU0LCJldmlkZW5jZUtpbmQiOiJmYWlsZWQiLCJob2xkQ2xhc3MiOiJyZXRhaW5lZCJ9LCJyZXNwb25zZUJhc2U2NCI6ImV5SnlaWEYxWlhOMFNXUWlPaUp5WlhGMVpYTjBMVEVpTENKcWIySkpaQ0k2SW1wdllpMHhJaXdpYUc5emRFbGtJam9pYUc5emRDMHhJaXdpYzJWeGRXVnVZMlVpT2pjc0luTjBZWFIxY3lJNkltWmhhV3hsWkNJc0luQnliMmR5WlhOeklqcHVkV3hzTENKdlluTmxjblpsWkVGMElqb2lNakF5TmkweE1TMHdORlF4TmpveE5UbzBNeTR3TURCYUlpd2liMkp6WlhKMllYUnBiMjRpT25zaWRHVjRkQ0k2SXNPcEwrbWJxaUlzSW1OdmRXNTBJam94TENKdVpYTjBaV1FpT25zaVkyRnVZWEo1SWpvaVVGSkpWa0ZVUlY5RFFVNUJVbGtpZlgwc0ltVnljbTl5UTI5a1pTSTZJa0ZFUVZCVVJWSmZSa0ZKVEVWRUluMD0iLCJldmlkZW5jZVNvdXJjZSI6InN5bnRoZXRpYyJ9"
const nativeEvidencePayloadGoldenSHA256 = "45043ea7f2b2822284acf6f00140b7e4e1c818c1d4d09ed876e861118c980e3e"
const nativeEvidencePayloadGoldenTupleDigest = "2b14043a942b44d41eafbb4562c94f533ef8225bdc36c3d9f56827b1f80a88d1"

func evidenceFixtureSnapshot(t *testing.T) (nativeEvidenceSnapshot, map[string]any) {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "apps", "controller", "src", "testdata", "native-terminal-evidence-codec-v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("fixture read failed")
	}
	v, err := strictEvidenceValue(raw, 65536)
	if err != nil {
		t.Fatal("fixture invalid")
	}
	m, err := evidenceObject(v, "version", "responseDigestPrefix", "tupleDigestPrefix", "authorizationRequestDigest", "storedQueueDigest", "storedQueueEncoding", "storedRequest", "vectors")
	if err != nil {
		t.Fatal("fixture schema invalid")
	}
	requestBytes, err := json.Marshal(m["storedRequest"])
	if err != nil {
		t.Fatal("request fixture invalid")
	}
	vectors, ok := m["vectors"].([]any)
	if !ok || len(vectors) != 4 {
		t.Fatal("vector fixture invalid")
	}
	first, err := evidenceObject(vectors[0], "name", "responseBase64", "responseByteLength", "responseDigest", "tupleEncoding", "tupleDigest")
	if err != nil {
		t.Fatal("response vector invalid")
	}
	responseText, ok := first["responseBase64"].(string)
	if !ok {
		t.Fatal("response base64 invalid")
	}
	response, err := base64.StdEncoding.Strict().DecodeString(responseText)
	if err != nil {
		t.Fatal("response bytes invalid")
	}
	str := func(key string) string {
		x, ok := m[key].(string)
		if !ok {
			t.Fatalf("fixture field %s invalid", key)
		}
		return x
	}
	s := nativeEvidenceSnapshot{StoredRequest: requestBytes, QueueEncoding: []byte(str("storedQueueEncoding")), QueueDigest: str("storedQueueDigest"),
		TerminalHostID: "host-1", TerminalJobID: "job-1", TerminalRequestID: "request-1", TerminalState: "timed-out", TerminalRevision: "history-1", TerminalOccurredAt: "2026-11-04T16:15:43.000Z",
		ResponseBytes: response, AuthorizationDigest: str("authorizationRequestDigest"), EvidenceSource: "synthetic", RunnerHold: "retained", TrustProvenance: "unverified", TrustHostID: "host-1", TrustBindingRevision: "binding-1"}
	return s, m
}

func TestNativeEvidencePayloadGoldenAndExactByteOwnership(t *testing.T) {
	s, _ := evidenceFixtureSnapshot(t)
	encoded, err := encodeNativeTerminalEvidence(s)
	if err != nil {
		t.Fatal("encode failed")
	}
	golden := nativeEvidencePayloadGoldenBase64
	if base64.StdEncoding.EncodeToString(encoded.PayloadBytes) != golden {
		t.Fatal("payload differs from TypeScript golden")
	}
	wantHash := nativeEvidencePayloadGoldenSHA256
	sum := sha256.Sum256(encoded.PayloadBytes)
	if hex.EncodeToString(sum[:]) != wantHash {
		t.Fatal("payload hash mismatch")
	}
	wantTuple := nativeEvidencePayloadGoldenTupleDigest
	if encoded.TupleDigest != wantTuple {
		t.Fatal("tuple digest mismatch")
	}
	if encoded.ReleasePermitted || encoded.ExecutionPermitted || encoded.ReceiptCommitted {
		t.Fatal("evidence codec must not confer authority")
	}
	decoded, err := decodeNativeTerminalEvidence(encoded.PayloadBytes, s)
	if err != nil {
		t.Fatal("decode failed")
	}
	if !bytes.Equal(decoded.PayloadBytes, encoded.PayloadBytes) || !bytes.Equal(decoded.ResponseBytes, s.ResponseBytes) || decoded.TupleDigest != encoded.TupleDigest {
		t.Fatal("exact bytes not preserved")
	}
	// Result owns copies; caller mutations after return cannot alter them.
	encoded.PayloadBytes[0] = 'x'
	encoded.ResponseBytes[0] = 'x'
	if bytes.Equal(decoded.PayloadBytes, encoded.PayloadBytes) || bytes.Equal(decoded.ResponseBytes, encoded.ResponseBytes) {
		t.Fatal("result aliases caller/result bytes")
	}
}

func TestNativeEvidenceStrictRejectsMalformedAndUnboundPayloads(t *testing.T) {
	s, _ := evidenceFixtureSnapshot(t)
	good, err := encodeNativeTerminalEvidence(s)
	if err != nil {
		t.Fatal("fixture encode failed")
	}
	base := append([]byte(nil), good.PayloadBytes...)
	cases := [][]byte{
		[]byte(string(base) + "{}"), []byte("\xef\xbb\xbf" + string(base)),
		[]byte(strings.Replace(string(base), "\"domain\":", "\"domain\":\"dup\",\"domain\":", 1)),
		[]byte(strings.Replace(string(base), "\"domain\":", "\"domain\":\"dup\",\"dom\\u0061in\":", 1)),
		[]byte(strings.Replace(string(base), "\"version\":1", "\"version\":1.0", 1)),
		[]byte(strings.Replace(string(base), "\"version\":1", "\"version\":1e0", 1)),
		[]byte(strings.Replace(string(base), "\"version\":1", "\"version\":-0", 1)),
		[]byte(strings.Replace(string(base), "\"version\":1", "\"version\":9007199254740992", 1)),
		[]byte(strings.Replace(string(base), "\"version\":1", "\"version\":1,\"canary\":\"SECRET_CANARY\"", 1)),
		append(append([]byte(nil), base...), 0xff),
	}
	tooDeep := []byte(strings.Repeat("[", maxNativeEvidenceDepth+2) + "0" + strings.Repeat("]", maxNativeEvidenceDepth+2))
	if _, e := strictEvidenceValue(tooDeep, 1024); !errors.Is(e, errNativeEvidence) {
		t.Fatal("excessive nesting accepted")
	}
	for i, raw := range cases {
		if _, e := decodeNativeTerminalEvidence(raw, s); !errors.Is(e, errNativeEvidence) {
			t.Fatalf("malformed case %d accepted or leaked error", i)
		}
	}
	for _, badResponse := range [][]byte{
		[]byte(`{"requestId":"request-1","jobId":"job-1","hostId":"host-1","sequence":7,"status":"failed","progress":null,"observedAt":"2026-11-04T16:15:43.000Z","observation":{"x":1,"x":2},"errorCode":"ADAPTER_FAILED"}`),
		[]byte(`{"requestId":"request-1","jobId":"job-1","hostId":"host-1","sequence":7,"status":"failed","progress":null,"observedAt":"2026-11-04T16:15:43.000Z","observation":{"x":1.0},"errorCode":"ADAPTER_FAILED"}`),
		[]byte(`{"requestId":"request-1","jobId":"job-1","hostId":"host-1","sequence":7,"status":"failed","progress":null,"observedAt":"2026-11-04T16:15:43.000Z","observation":{"x":9007199254740992},"errorCode":"ADAPTER_FAILED"}`),
		[]byte(`{"requestId":"request-1","jobId":"job-1","hostId":"host-1","sequence":7,"status":"failed","progress":null,"observedAt":"2026-11-04T16:15:43.000Z","observation":{"x":-0},"errorCode":"ADAPTER_FAILED"}`),
		[]byte(`{"requestId":"request-1","jobId":"job-1","hostId":"host-1","sequence":7,"status":"failed","progress":null,"observedAt":"2026-11-04T16:15:43.000Z","observation":{"x":1e0},"errorCode":"ADAPTER_FAILED"}`),
		[]byte(`{"requestId":"request-1","jobId":"job-1","hostId":"host-1","sequence":7,"status":"failed","progress":null,"observedAt":"2026-11-04T16:15:43.000Z","observation":{"nested":{"x":1,"x":2}},"errorCode":"ADAPTER_FAILED"}`),
		[]byte(`{"requestId":"request-1","jobId":"job-1","hostId":"host-1","sequence":7,"status":"failed","progress":null,"observedAt":"2026-11-04T16:15:43.000Z","observation":{"nested":{"x":1,"\u0078":2}},"errorCode":"ADAPTER_FAILED"}`),
		[]byte(`{"requestId":"request-1","jobId":"job-1","hostId":"host-1","sequence":7,"status":"failed","progress":null,"observedAt":"2026-11-04T16:15:43.000Z","observation":{"x":"\ud800"},"errorCode":"ADAPTER_FAILED"}`),
	} {
		x := s
		x.ResponseBytes = badResponse
		if _, e := encodeNativeTerminalEvidence(x); !errors.Is(e, errNativeEvidence) {
			t.Fatal("invalid nested response accepted")
		}
	}
	for _, mutate := range []func(*nativeEvidenceSnapshot){func(x *nativeEvidenceSnapshot) { x.QueueDigest = x.AuthorizationDigest }, func(x *nativeEvidenceSnapshot) { x.TerminalRevision = "" }, func(x *nativeEvidenceSnapshot) { x.TerminalHostID = "foreign" }, func(x *nativeEvidenceSnapshot) { x.RunnerHold = "released" }, func(x *nativeEvidenceSnapshot) { x.TrustProvenance = "verified_current"; x.TrustHostID = "foreign" }} {
		x := s
		mutate(&x)
		if _, e := encodeNativeTerminalEvidence(x); !errors.Is(e, errNativeEvidence) || e.Error() != "ERR_NATIVE_EVIDENCE_CODEC" {
			t.Fatal("mismatched snapshot accepted or error leaked details")
		}
	}
}

func TestNativeEvidenceBoundsBase64AndQueuePreimageAreStrict(t *testing.T) {
	s, _ := evidenceFixtureSnapshot(t)
	result, err := encodeNativeTerminalEvidence(s)
	if err != nil {
		t.Fatal("fixture encode failed")
	}
	badBase := strings.Replace(string(result.PayloadBytes), `"responseBase64":"`, `"responseBase64":"!`, 1)
	tooLongBase := strings.Replace(string(result.PayloadBytes), `"responseBase64":"`+base64.StdEncoding.EncodeToString(s.ResponseBytes)+`"`, `"responseBase64":"`+strings.Repeat("A", 699053)+`"`, 1)
	if _, e := decodeNativeTerminalEvidence([]byte(tooLongBase), s); !errors.Is(e, errNativeEvidence) {
		t.Fatal("oversized encoded response accepted")
	}
	if _, e := decodeNativeTerminalEvidence([]byte(badBase), s); !errors.Is(e, errNativeEvidence) {
		t.Fatal("malformed base64 accepted")
	}
	for _, change := range []func(*nativeEvidenceSnapshot){func(x *nativeEvidenceSnapshot) { x.QueueEncoding = append(x.QueueEncoding, 0) }, func(x *nativeEvidenceSnapshot) {
		x.StoredRequest = bytes.Replace(x.StoredRequest, []byte(`"host-1"`), []byte(`"foreign"`), 1)
	}, func(x *nativeEvidenceSnapshot) { x.ResponseBytes = make([]byte, maxNativeEvidenceResponseBytes+1) }} {
		x := s
		change(&x)
		if _, e := encodeNativeTerminalEvidence(x); !errors.Is(e, errNativeEvidence) {
			t.Fatal("overbound or mismatched input accepted")
		}
	}
	if _, e := decodeNativeTerminalEvidence(make([]byte, maxNativeEvidencePayloadBytes+1), s); !errors.Is(e, errNativeEvidence) {
		t.Fatal("oversized payload accepted")
	}
}

func TestNativeEvidenceCodecHasNoProductionImporter(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal("package listing unavailable")
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || entry.Name() == "native_terminal_evidence_codec.go" || entry.Name() == "native_terminal_evidence_codec_test.go" {
			continue
		}
		raw, e := os.ReadFile(entry.Name())
		if e != nil {
			t.Fatal("package source unreadable")
		}
		if bytes.Contains(raw, []byte("encodeNativeTerminalEvidence")) || bytes.Contains(raw, []byte("decodeNativeTerminalEvidence")) {
			t.Fatalf("unexpected production importer in %s", entry.Name())
		}
	}
}

func TestNativeEvidenceAllFrozenVectorsRoundTrip(t *testing.T) {
	s, fixture := evidenceFixtureSnapshot(t)
	vectors, ok := fixture["vectors"].([]any)
	if !ok || len(vectors) != 4 {
		t.Fatal("four frozen vectors required")
	}
	for _, item := range vectors {
		v, err := evidenceObject(item, "name", "responseBase64", "responseByteLength", "responseDigest", "tupleEncoding", "tupleDigest")
		if err != nil {
			t.Fatal("invalid vector schema")
		}
		name, _ := evidenceString(v, "name")
		encodedResponse, _ := evidenceString(v, "responseBase64")
		wantDigest, _ := evidenceString(v, "responseDigest")
		wantTupleEncoding, _ := evidenceString(v, "tupleEncoding")
		wantTupleDigest, _ := evidenceString(v, "tupleDigest")
		wantLength, _ := evidenceUint(v, "responseByteLength")
		response, err := base64.StdEncoding.Strict().DecodeString(encodedResponse)
		if err != nil || uint64(len(response)) != wantLength {
			t.Fatalf("%s: invalid frozen response bytes", name)
		}
		x := s
		x.ResponseBytes = response
		result, err := encodeNativeTerminalEvidence(x)
		if err != nil {
			t.Fatalf("%s: encode rejected frozen vector", name)
		}
		decoded, err := decodeNativeTerminalEvidence(result.PayloadBytes, x)
		if err != nil || !bytes.Equal(decoded.ResponseBytes, response) || !bytes.Equal(decoded.PayloadBytes, result.PayloadBytes) {
			t.Fatalf("%s: exact byte round trip failed", name)
		}
		if result.Tuple.ResponseDigest != wantDigest || result.TupleDigest != wantTupleDigest || base64.StdEncoding.EncodeToString(decoded.ResponseBytes) != encodedResponse {
			t.Fatalf("%s: frozen digest or response bytes changed", name)
		}
		tupleEncoding, err := nativeTupleEncoding(result.Tuple)
		if err != nil || string(tupleEncoding) != wantTupleEncoding {
			t.Fatalf("%s: frozen tuple encoding changed", name)
		}
	}
}

func TestNativeEvidenceEveryTupleBindingMismatchFailsClosed(t *testing.T) {
	s, _ := evidenceFixtureSnapshot(t)
	encoded, err := encodeNativeTerminalEvidence(s)
	if err != nil {
		t.Fatal("fixture encode failed")
	}
	fields := []string{"domain", "hostId", "jobId", "requestId", "commandSequence", "idempotencyKey", "authorizationRequestDigest", "storedQueueDigest", "terminalState", "terminalRevision", "responseDigest", "responseByteLength", "evidenceKind", "holdClass"}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			value, e := strictEvidenceValue(encoded.PayloadBytes, maxNativeEvidencePayloadBytes)
			if e != nil {
				t.Fatal("fixture payload parse failed")
			}
			payload, e := evidenceObject(value, "domain", "kind", "version", "disposition", "tuple", "responseBase64", "evidenceSource")
			if e != nil {
				t.Fatal("fixture payload shape failed")
			}
			tuple, e := evidenceObject(payload["tuple"], fields...)
			if e != nil {
				t.Fatal("fixture tuple shape failed")
			}
			if n, ok := tuple[field].(json.Number); ok {
				tuple[field] = json.Number(string(n) + "1")
			} else {
				tuple[field] = "foreign"
			}
			mutated, e := json.Marshal(payload)
			if e != nil {
				t.Fatal("mutated payload marshal failed")
			}
			if _, e = decodeNativeTerminalEvidence(mutated, s); !errors.Is(e, errNativeEvidence) || e.Error() != "ERR_NATIVE_EVIDENCE_CODEC" {
				t.Fatalf("tuple binding %s accepted or leaked error", field)
			}
		})
	}
}

func TestNativeEvidenceResponseAndPayloadCapsAreInclusive(t *testing.T) {
	s, _ := evidenceFixtureSnapshot(t)
	code := "ADAPTER_FAILED"
	response := Response{RequestID: "request-1", JobID: "job-1", HostID: "host-1", Sequence: 7, Status: "failed", ObservedAt: "2026-11-04T16:15:43.000Z", Observation: map[string]string{"padding": ""}, ErrorCode: &code}
	base, err := json.Marshal(response)
	if err != nil || len(base) >= maxNativeEvidenceResponseBytes {
		t.Fatal("response cap fixture invalid")
	}
	response.Observation = map[string]string{"padding": strings.Repeat("x", maxNativeEvidenceResponseBytes-len(base))}
	atCap, err := json.Marshal(response)
	if err != nil || len(atCap) != maxNativeEvidenceResponseBytes {
		t.Fatal("failed to construct exact response cap")
	}
	x := s
	x.ResponseBytes = atCap
	result, err := encodeNativeTerminalEvidence(x)
	if err != nil {
		t.Fatal("valid response cap rejected")
	}
	decoded, err := decodeNativeTerminalEvidence(result.PayloadBytes, x)
	if err != nil || len(decoded.ResponseBytes) != maxNativeEvidenceResponseBytes {
		t.Fatal("response cap did not round-trip")
	}
	x.ResponseBytes = append(append([]byte(nil), atCap...), ' ')
	if _, err = encodeNativeTerminalEvidence(x); !errors.Is(err, errNativeEvidence) {
		t.Fatal("response cap+1 accepted")
	}

	small, err := encodeNativeTerminalEvidence(s)
	if err != nil || len(small.PayloadBytes) > maxNativeEvidencePayloadBytes {
		t.Fatal("small payload fixture invalid")
	}
	payloadAtCap := append(append([]byte(nil), small.PayloadBytes...), bytes.Repeat([]byte{' '}, maxNativeEvidencePayloadBytes-len(small.PayloadBytes))...)
	if _, err = decodeNativeTerminalEvidence(payloadAtCap, s); err != nil {
		t.Fatal("valid payload cap rejected")
	}
	payloadOver := append(append([]byte(nil), payloadAtCap...), ' ')
	if _, err = decodeNativeTerminalEvidence(payloadOver, s); !errors.Is(err, errNativeEvidence) {
		t.Fatal("payload cap+1 accepted")
	}
}

func TestNativeEvidenceNodeAndStringBudgetsAreInclusive(t *testing.T) {
	validNodes := []byte("[" + strings.Repeat("0,", maxNativeEvidenceNodes-2) + "0]")
	if _, err := strictEvidenceValue(validNodes, maxNativeEvidencePayloadBytes); err != nil {
		t.Fatal("valid node budget rejected")
	}
	overNodes := []byte("[" + strings.Repeat("0,", maxNativeEvidenceNodes-1) + "0]")
	if _, err := strictEvidenceValue(overNodes, maxNativeEvidencePayloadBytes); !errors.Is(err, errNativeEvidence) {
		t.Fatal("node budget+1 accepted")
	}
	validString := []byte("\"" + strings.Repeat("x", maxNativeEvidenceStringBytes) + "\"")
	if _, err := strictEvidenceValue(validString, len(validString)); err != nil {
		t.Fatal("valid string budget rejected")
	}
	overString := []byte("\"" + strings.Repeat("x", maxNativeEvidenceStringBytes+1) + "\"")
	if _, err := strictEvidenceValue(overString, len(overString)); !errors.Is(err, errNativeEvidence) {
		t.Fatal("string budget+1 accepted")
	}
}

func TestNativeEvidenceRejectsNoncanonicalBase64PadBits(t *testing.T) {
	s, _ := evidenceFixtureSnapshot(t)
	result, err := encodeNativeTerminalEvidence(s)
	if err != nil {
		t.Fatal("fixture encode failed")
	}
	value, err := strictEvidenceValue(result.PayloadBytes, maxNativeEvidencePayloadBytes)
	if err != nil {
		t.Fatal("fixture payload parse failed")
	}
	payload, err := evidenceObject(value, "domain", "kind", "version", "disposition", "tuple", "responseBase64", "evidenceSource")
	if err != nil {
		t.Fatal("fixture payload shape failed")
	}
	original, _ := evidenceString(payload, "responseBase64")
	decoded, err := base64.StdEncoding.DecodeString(original)
	if err != nil {
		t.Fatal("fixture base64 invalid")
	}
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	found := false
	for i := 0; i < len(original) && !found; i++ {
		if original[i] == '=' {
			break
		}
		oldIndex := strings.IndexByte(alphabet, original[i])
		for j := 0; j < len(alphabet); j++ {
			if j == oldIndex {
				continue
			}
			candidate := original[:i] + alphabet[j:j+1] + original[i+1:]
			permissive, e := base64.StdEncoding.DecodeString(candidate)
			_, se := base64.StdEncoding.Strict().DecodeString(candidate)
			if e == nil && bytes.Equal(permissive, decoded) && se != nil {
				copyValue, e := strictEvidenceValue(result.PayloadBytes, maxNativeEvidencePayloadBytes)
				if e != nil {
					t.Fatal("fixture payload reparse failed")
				}
				copyPayload, _ := evidenceObject(copyValue, "domain", "kind", "version", "disposition", "tuple", "responseBase64", "evidenceSource")
				copyPayload["responseBase64"] = candidate
				mutated, e := json.Marshal(copyPayload)
				if e != nil {
					t.Fatal("mutated payload marshal failed")
				}
				if _, e = decodeNativeTerminalEvidence(mutated, s); !errors.Is(e, errNativeEvidence) {
					t.Fatal("noncanonical base64 pad bits accepted")
				}
				found = true
				break
			}
		}
	}
	if !found {
		t.Fatal("failed to construct noncanonical pad-bit vector")
	}
}

func TestNativeEvidenceEveryPayloadEnvelopeBindingFailsClosed(t *testing.T) {
	s, _ := evidenceFixtureSnapshot(t)
	result, err := encodeNativeTerminalEvidence(s)
	if err != nil {
		t.Fatal("fixture encode failed")
	}
	mutations := []struct {
		name   string
		change func(map[string]any)
	}{
		{"domain", func(p map[string]any) { p["domain"] = "foreign" }},
		{"kind", func(p map[string]any) { p["kind"] = "foreign" }},
		{"version", func(p map[string]any) { p["version"] = json.Number("2") }},
		{"disposition", func(p map[string]any) { p["disposition"] = "release" }},
		{"evidenceSource", func(p map[string]any) { p["evidenceSource"] = "foreign" }},
		{"responseBase64", func(p map[string]any) { p["responseBase64"] = "AAAA" }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			value, e := strictEvidenceValue(result.PayloadBytes, maxNativeEvidencePayloadBytes)
			if e != nil {
				t.Fatal("fixture payload parse failed")
			}
			payload, e := evidenceObject(value, "domain", "kind", "version", "disposition", "tuple", "responseBase64", "evidenceSource")
			if e != nil {
				t.Fatal("fixture payload schema failed")
			}
			mutation.change(payload)
			raw, e := json.Marshal(payload)
			if e != nil {
				t.Fatal("mutated payload marshal failed")
			}
			if _, e = decodeNativeTerminalEvidence(raw, s); !errors.Is(e, errNativeEvidence) || e.Error() != "ERR_NATIVE_EVIDENCE_CODEC" {
				t.Fatalf("envelope binding %s accepted or leaked error", mutation.name)
			}
		})
	}
}

func TestNativeEvidenceIndependentRequestTerminalAndResponseBindings(t *testing.T) {
	s, _ := evidenceFixtureSnapshot(t)
	original, err := encodeNativeTerminalEvidence(s)
	if err != nil {
		t.Fatal("fixture encode failed")
	}
	deny := func(name string, x nativeEvidenceSnapshot) {
		t.Helper()
		if _, e := encodeNativeTerminalEvidence(x); !errors.Is(e, errNativeEvidence) {
			t.Errorf("%s: mismatched snapshot encoded", name)
		}
		if _, e := decodeNativeTerminalEvidence(original.PayloadBytes, x); !errors.Is(e, errNativeEvidence) {
			t.Errorf("%s: original payload accepted against mismatched snapshot", name)
		}
	}
	requestMutations := []struct{ name, old, replacement string }{
		{"requestId", `"requestId":"request-1"`, `"requestId":"foreign"`},
		{"jobId", `"jobId":"job-1"`, `"jobId":"foreign"`},
		{"hostId", `"hostId":"host-1"`, `"hostId":"foreign"`},
		{"operation", `"operation":"load"`, `"operation":"drain"`},
		{"idempotencyKey", `"idempotencyKey":"idem-1"`, `"idempotencyKey":"other-idem"`},
		{"sequence", `"sequence":7`, `"sequence":8`},
		{"deadline", `"deadline":"2026-11-04T16:15:43.000Z"`, `"deadline":"2026-11-04T16:15:44.000Z"`},
		{"capabilityOperation", `"operation":"model-load"`, `"operation":"model-drain"`},
		{"capabilityTargetKind", `"targetKind":"model"`, `"targetKind":"host"`},
		{"capabilityTargetId", `"targetId":"model-1"`, `"targetId":"foreign"`},
		{"capabilityModelId", `"modelId":"model-1"`, `"modelId":"other-model"`},
		{"capabilityRequestDigest", `"requestDigest":"d7c3a4d75dd3c77bc7c4b2b02a9a96660abb60cb38c0c16187f7f563c5b7b695"`, `"requestDigest":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"`},
		{"capabilityExpiry", `"expiresAt":"2026-11-04T16:15:43.000Z"`, `"expiresAt":"2026-11-04T16:15:44.000Z"`},
	}
	for _, mutation := range requestMutations {
		x := s
		x.StoredRequest = bytes.Replace(s.StoredRequest, []byte(mutation.old), []byte(mutation.replacement), 1)
		if bytes.Equal(x.StoredRequest, s.StoredRequest) {
			t.Fatalf("%s fixture replacement missed", mutation.name)
		}
		deny("request/"+mutation.name, x)
	}
	for _, mutation := range []struct {
		name   string
		change func(*nativeEvidenceSnapshot)
	}{
		{"queuePreimage", func(x *nativeEvidenceSnapshot) {
			x.QueueEncoding = append(append([]byte(nil), x.QueueEncoding...), ' ')
		}},
		{"queueDigest", func(x *nativeEvidenceSnapshot) { x.QueueDigest = x.AuthorizationDigest }},
		{"authorizationDigest", func(x *nativeEvidenceSnapshot) { x.AuthorizationDigest = strings.Repeat("f", 64) }},
		{"terminalHost", func(x *nativeEvidenceSnapshot) { x.TerminalHostID = "foreign" }},
		{"terminalJob", func(x *nativeEvidenceSnapshot) { x.TerminalJobID = "foreign" }},
		{"terminalRequest", func(x *nativeEvidenceSnapshot) { x.TerminalRequestID = "foreign" }},
		{"terminalState", func(x *nativeEvidenceSnapshot) { x.TerminalState = "running" }},
		{"terminalRevision", func(x *nativeEvidenceSnapshot) { x.TerminalRevision = "" }},
	} {
		x := s
		mutation.change(&x)
		deny("snapshot/"+mutation.name, x)
	}
	for _, mutation := range []struct{ name, old, replacement string }{
		{"responseRequest", `"requestId":"request-1"`, `"requestId":"foreign"`},
		{"responseJob", `"jobId":"job-1"`, `"jobId":"foreign"`},
		{"responseHost", `"hostId":"host-1"`, `"hostId":"foreign"`},
		{"responseSequence", `"sequence":7`, `"sequence":8`},
	} {
		x := s
		x.ResponseBytes = bytes.Replace(s.ResponseBytes, []byte(mutation.old), []byte(mutation.replacement), 1)
		if bytes.Equal(x.ResponseBytes, s.ResponseBytes) {
			t.Fatalf("%s fixture replacement missed", mutation.name)
		}
		deny(mutation.name, x)
	}
	// Validly rebound changes are valid new evidence, but an old payload must
	// not be reusable against the changed queue and authorization tuple.
	req, err := parseNativeEvidenceStoredRequest(s)
	if err != nil {
		t.Fatal("fixture request parse failed")
	}
	req.IdempotencyKey = "other-idem"
	req.Capability.RequestDigest, err = authorizationDigest(req)
	if err != nil {
		t.Fatal("changed request digest failed")
	}
	x := s
	x.StoredRequest, err = json.Marshal(req)
	if err != nil {
		t.Fatal("changed request marshal failed")
	}
	x.QueueEncoding = append([]byte(nil), x.StoredRequest...)
	x.QueueDigest = evidenceDigest(x.QueueEncoding)
	x.AuthorizationDigest = req.Capability.RequestDigest
	changed, err := encodeNativeTerminalEvidence(x)
	if err != nil {
		t.Fatal("validly rebound request rejected")
	}
	if _, err = decodeNativeTerminalEvidence(original.PayloadBytes, x); !errors.Is(err, errNativeEvidence) {
		t.Fatal("old payload accepted for changed request")
	}
	if _, err = decodeNativeTerminalEvidence(changed.PayloadBytes, x); err != nil {
		t.Fatal("newly bound payload did not round-trip")
	}
}

func TestNativeEvidenceDecoderRequiresSnapshotSourceAndBoundsBeforeCopy(t *testing.T) {
	s, _ := evidenceFixtureSnapshot(t)
	for _, source := range []string{"synthetic", "explicit_snapshot", "retained_same_process"} {
		t.Run(source, func(t *testing.T) {
			x := s
			x.EvidenceSource = source
			encoded, err := encodeNativeTerminalEvidence(x)
			if err != nil {
				t.Fatal("source fixture encode failed")
			}
			if _, err = decodeNativeTerminalEvidence(encoded.PayloadBytes, x); err != nil {
				t.Fatal("matching source rejected")
			}
			for _, other := range []string{"synthetic", "explicit_snapshot", "retained_same_process"} {
				if other == source {
					continue
				}
				x.EvidenceSource = other
				if _, err = decodeNativeTerminalEvidence(encoded.PayloadBytes, x); !errors.Is(err, errNativeEvidence) {
					t.Errorf("payload source %s accepted for snapshot %s", source, other)
				}
			}
		})
	}
	oversized := make([]byte, maxNativeEvidencePayloadBytes+1)
	if allocations := testing.AllocsPerRun(3, func() {
		if _, err := decodeNativeTerminalEvidence(oversized, s); !errors.Is(err, errNativeEvidence) {
			panic("oversized payload accepted")
		}
	}); allocations != 0 {
		t.Errorf("oversized payload allocated before rejection: %v", allocations)
	}
	if _, err := decodeNativeTerminalEvidence(nil, s); !errors.Is(err, errNativeEvidence) {
		t.Fatal("empty payload accepted")
	}
}
