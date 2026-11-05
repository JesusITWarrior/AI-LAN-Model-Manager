package command

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Frozen vectors only: this is not a Go evidence codec or JS queue serializer.
// Load inside selected tests, never init: unrelated native qualification tests
// must not require this repository-level fixture.
type nativeEvidenceFixture struct {
	Version                    uint64          `json:"version"`
	ResponseDigestPrefix       string          `json:"responseDigestPrefix"`
	TupleDigestPrefix          string          `json:"tupleDigestPrefix"`
	AuthorizationRequestDigest string          `json:"authorizationRequestDigest"`
	StoredQueueDigest          string          `json:"storedQueueDigest"`
	StoredQueueEncoding        string          `json:"storedQueueEncoding"`
	StoredRequest              json.RawMessage `json:"storedRequest"`
	Vectors                    []struct {
		Name               string `json:"name"`
		ResponseBase64     string `json:"responseBase64"`
		ResponseByteLength uint64 `json:"responseByteLength"`
		ResponseDigest     string `json:"responseDigest"`
		TupleEncoding      string `json:"tupleEncoding"`
		TupleDigest        string `json:"tupleDigest"`
	} `json:"vectors"`
}

func nativeEvidenceSHA(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func loadNativeEvidenceFixture(t *testing.T) nativeEvidenceFixture {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "apps", "controller", "src", "testdata", "native-terminal-evidence-codec-v1.json")
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("required shared fixture unavailable:", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(raw) == 0 || len(raw) > 65536 {
		t.Fatal("fixture read failed or exceeded local 64 KiB cap")
	}
	var fixture nativeEvidenceFixture
	if strictStreamJSON(raw, &fixture) != nil {
		t.Fatal("fixture must have exact schema and strict JSON")
	}
	if fixture.Version != 1 || fixture.ResponseDigestPrefix != "lanmm-native-response-bytes-v1\x00" || fixture.TupleDigestPrefix != "lanmm-native-terminal-evidence-tuple-digest-v1\x00" {
		t.Fatal("fixture version or digest domains changed")
	}
	if fixture.AuthorizationRequestDigest != "d7c3a4d75dd3c77bc7c4b2b02a9a96660abb60cb38c0c16187f7f563c5b7b695" || fixture.StoredQueueDigest != "ab6c2470463feffd6542aa24f4b7cdcc399d927d9338058cc24c0736b5b2baf5" {
		t.Fatal("frozen request digests changed")
	}
	if len(fixture.StoredQueueEncoding) > 32768 || len(fixture.StoredQueueEncoding) != 470 {
		t.Fatal("queue encoding length changed or exceeded local cap")
	}
	names := []string{"original", "escaped-unicode-slash", "reversed-top-level-key-order", "trailing-newline"}
	lengths := []uint64{254, 262, 254, 255}
	if len(fixture.Vectors) != len(names) {
		t.Fatal("fixture must contain exactly four vectors")
	}
	for i, vector := range fixture.Vectors {
		if vector.Name != names[i] || vector.ResponseByteLength != lengths[i] || len(vector.ResponseBase64) > 699052 || len(vector.TupleEncoding) == 0 || len(vector.TupleEncoding) > 4096 || !digestPattern.MatchString(vector.ResponseDigest) || !digestPattern.MatchString(vector.TupleDigest) {
			t.Fatalf("vector %d: frozen metadata or local bounds invalid", i)
		}
	}
	return fixture
}

func nativeEvidenceRequest(t *testing.T, raw []byte) Request {
	t.Helper()
	var request Request
	if strictStreamJSON(raw, &request) != nil {
		t.Fatal("known-valid fixture request failed strict decoding")
	}
	return request
}

func assertNativeEvidenceSameRequest(t *testing.T, left, right Request) {
	t.Helper()
	leftParams, leftErr := normalizedJSON(left.Params)
	rightParams, rightErr := normalizedJSON(right.Params)
	if leftErr != nil || rightErr != nil || !reflect.DeepEqual(leftParams, rightParams) {
		t.Fatal("fixture request params differ semantically")
	}
	left.Params, right.Params = nil, nil
	if !reflect.DeepEqual(left, right) {
		t.Fatal("fixture request bindings differ semantically")
	}
}

func TestNativeTerminalEvidenceFixtureRequestPreimage(t *testing.T) {
	fixture := loadNativeEvidenceFixture(t)
	request := nativeEvidenceRequest(t, fixture.StoredRequest)
	preimageRequest := nativeEvidenceRequest(t, []byte(fixture.StoredQueueEncoding))
	assertNativeEvidenceSameRequest(t, request, preimageRequest)
	const timestamp = "2026-11-04T16:15:43.000Z"
	if request.RequestID != "request-1" || request.JobID != "job-1" || request.HostID != "host-1" || request.IdempotencyKey != "idem-1" || request.Sequence != 7 || request.Sequence > maxSafeInteger || request.Operation != "load" || request.Deadline != timestamp {
		t.Fatal("historical request binding changed")
	}
	capability := request.Capability
	if capability.Operation != "model-load" || capability.TargetKind != "model" || capability.TargetID != "model-1" || capability.HostID != request.HostID || capability.ModelID == nil || *capability.ModelID != "model-1" || capability.ExpiresAt != timestamp || !targetMatches(request) {
		t.Fatal("historical capability binding changed")
	}
	params, err := normalizedJSON(request.Params)
	if err != nil || !reflect.DeepEqual(params, map[string]any{"modelId": "model-1", "providerId": "ollama-1", "model": "model:1"}) {
		t.Fatal("historical params changed")
	}
	for _, candidate := range []Request{request, preimageRequest} {
		digest, err := authorizationDigest(candidate)
		if err != nil || digest != fixture.AuthorizationRequestDigest || digest != candidate.Capability.RequestDigest {
			t.Fatal("existing authorization digest disagrees with frozen request")
		}
	}
	if nativeEvidenceSHA([]byte(fixture.StoredQueueEncoding)) != fixture.StoredQueueDigest {
		t.Fatal("frozen JS queue preimage digest mismatch")
	}
}

func TestNativeTerminalEvidenceCrossLanguageVectors(t *testing.T) {
	fixture := loadNativeEvidenceFixture(t)
	request := nativeEvidenceRequest(t, fixture.StoredRequest)
	var original Response
	responseDigests, tupleDigests := map[string]bool{}, map[string]bool{}
	for i, vector := range fixture.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			raw, err := base64.StdEncoding.Strict().DecodeString(vector.ResponseBase64)
			if err != nil || base64.StdEncoding.EncodeToString(raw) != vector.ResponseBase64 || len(raw) == 0 || len(raw) > 524288 || uint64(len(raw)) != vector.ResponseByteLength {
				t.Fatal("response base64 grammar or complete byte length mismatch")
			}
			// Hash original complete bytes, never the decoded/reencoded response.
			responseDigest := nativeEvidenceSHA(append([]byte("lanmm-native-response-bytes-v1\x00"), raw...))
			if responseDigest != vector.ResponseDigest {
				t.Fatal("response original-byte domain hash mismatch")
			}
			var response Response
			if strictStreamJSON(raw, &response) != nil {
				t.Fatal("known-valid response failed strict decoding")
			}
			if response.RequestID != request.RequestID || response.JobID != request.JobID || response.HostID != request.HostID || response.Sequence != request.Sequence || response.Status != "failed" || response.ErrorCode == nil || *response.ErrorCode != "ADAPTER_FAILED" || response.Progress != nil || response.ObservedAt != "2026-11-04T16:15:43.000Z" || response.Observation == nil {
				t.Fatal("historical response bindings or terminal fields changed")
			}
			if i == 0 {
				original = response
			} else if !reflect.DeepEqual(original, response) {
				// Response's any observation decodes consistently across all four
				// known-valid vectors; this is not general numeric validation.
				t.Fatal("response semantics differ across byte representations")
			}
			// Independently ordered 14-value tuple, not parsed from tupleEncoding.
			// json.Marshal suffices only for this bounded ASCII/safe-integer tuple.
			tuple, err := json.Marshal([]any{
				"lanmm-native-terminal-evidence-v1", request.HostID, request.JobID, request.RequestID,
				request.Sequence, request.IdempotencyKey, fixture.AuthorizationRequestDigest, fixture.StoredQueueDigest,
				"timed-out", "history-1", responseDigest, len(raw), response.Status, "retained",
			})
			if err != nil || !bytes.Equal(tuple, []byte(vector.TupleEncoding)) {
				t.Fatal("independent ordered tuple bytes mismatch")
			}
			tupleDigest := nativeEvidenceSHA(append([]byte("lanmm-native-terminal-evidence-tuple-digest-v1\x00"), tuple...))
			if tupleDigest != vector.TupleDigest {
				t.Fatal("independent tuple domain hash mismatch")
			}
			if responseDigests[responseDigest] || tupleDigests[tupleDigest] {
				t.Fatal("equivalent responses must retain distinct byte and tuple digests")
			}
			responseDigests[responseDigest], tupleDigests[tupleDigest] = true, true
		})
	}
	if len(responseDigests) != 4 || len(tupleDigests) != 4 {
		t.Fatal("all four distinct response and tuple digests required")
	}
}

func TestNativeTerminalEvidenceQueueOrderIsNotCanonical(t *testing.T) {
	fixture := loadNativeEvidenceFixture(t)
	request := nativeEvidenceRequest(t, []byte(fixture.StoredQueueEncoding))
	const original = `"params":{"modelId":"model-1","providerId":"ollama-1","model":"model:1"}`
	const reversed = `"params":{"model":"model:1","providerId":"ollama-1","modelId":"model-1"}`
	if strings.Count(fixture.StoredQueueEncoding, original) != 1 {
		t.Fatal("queue counterexample requires exactly one known params substring")
	}
	changed := strings.Replace(fixture.StoredQueueEncoding, original, reversed, 1)
	reordered := nativeEvidenceRequest(t, []byte(changed))
	assertNativeEvidenceSameRequest(t, request, reordered)
	for _, candidate := range []Request{request, reordered} {
		digest, err := authorizationDigest(candidate)
		if err != nil || digest != fixture.AuthorizationRequestDigest || digest != candidate.Capability.RequestDigest {
			t.Fatal("queue order must not change semantic authorization digest")
		}
	}
	if nativeEvidenceSHA([]byte(fixture.StoredQueueEncoding)) != fixture.StoredQueueDigest || nativeEvidenceSHA([]byte(changed)) == fixture.StoredQueueDigest {
		t.Fatal("queue digest must distinguish semantically equal params order")
	}
	// Go Request declares capability before params: Go marshal is NOT the JS
	// parsed-request queue preimage. This negative check is not a serializer.
	goMarshal, err := json.Marshal(request)
	if err != nil || bytes.Equal(goMarshal, []byte(fixture.StoredQueueEncoding)) || nativeEvidenceSHA(goMarshal) == fixture.StoredQueueDigest {
		t.Fatal("Go json.Marshal(Request) must not impersonate JS queue serialization")
	}
}
