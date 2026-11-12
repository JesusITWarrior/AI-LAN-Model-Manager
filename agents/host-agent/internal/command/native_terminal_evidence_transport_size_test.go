package command

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/transport"
)

func maxMetadataEvidenceSnapshot(t *testing.T, responseLength int) nativeEvidenceSnapshot {
	return maxMetadataEvidenceSnapshotWithSource(t, responseLength, "retained_same_process")
}

func maxMetadataEvidenceSnapshotWithSource(t *testing.T, responseLength int, evidenceSource string, revisionLength ...int) nativeEvidenceSnapshot {
	t.Helper()
	id := "A" + strings.Repeat("x", 127)
	revisionSize := len(id)
	if len(revisionLength) != 0 {
		revisionSize = revisionLength[0]
	}
	model := strings.Repeat("m", 256)
	modelID := id
	request := Request{RequestID: id, JobID: id, HostID: id, Operation: "load", IdempotencyKey: id, Sequence: 7,
		Deadline: "2026-11-04T16:15:43.000Z", Capability: Capability{Operation: "model-load", TargetKind: "model", TargetID: id,
			HostID: id, ModelID: &modelID, RequestDigest: strings.Repeat("0", 64), ExpiresAt: "2026-11-04T16:15:43.000Z"}}
	params, err := json.Marshal(struct {
		ModelID    string `json:"modelId"`
		ProviderID string `json:"providerId"`
		Model      string `json:"model"`
	}{id, id, model})
	if err != nil {
		t.Fatal("maximum metadata params marshal failed")
	}
	request.Params = params
	auth, err := authorizationDigest(request)
	if err != nil {
		t.Fatal("maximum metadata authorization digest failed")
	}
	request.Capability.RequestDigest = auth
	queueEncoding, err := json.Marshal(struct {
		RequestID      string          `json:"requestId"`
		JobID          string          `json:"jobId"`
		HostID         string          `json:"hostId"`
		Operation      string          `json:"operation"`
		IdempotencyKey string          `json:"idempotencyKey"`
		Sequence       uint64          `json:"sequence"`
		Deadline       string          `json:"deadline"`
		Params         json.RawMessage `json:"params"`
		Capability     Capability      `json:"capability"`
	}{request.RequestID, request.JobID, request.HostID, request.Operation, request.IdempotencyKey, request.Sequence, request.Deadline, request.Params, request.Capability})
	if err != nil {
		t.Fatal("maximum metadata queue encoding failed")
	}
	errorCode := "ADAPTER_FAILED"
	response, err := json.Marshal(Response{RequestID: id, JobID: id, HostID: id, Sequence: 7, Status: "failed",
		Progress: nil, ObservedAt: "2026-11-04T16:15:43.000Z", Observation: nil, ErrorCode: &errorCode})
	if err != nil || len(response) >= responseLength {
		t.Fatalf("maximum metadata response marshal failed: %v", err)
	}
	response = append(response, []byte(strings.Repeat(" ", responseLength-len(response)))...)
	return nativeEvidenceSnapshot{StoredRequest: queueEncoding, QueueEncoding: queueEncoding, QueueDigest: evidenceDigest(queueEncoding),
		TerminalHostID: id, TerminalJobID: id, TerminalRequestID: id, TerminalState: "timed-out", TerminalRevision: id[:revisionSize],
		TerminalOccurredAt: "2026-11-04T16:15:43.000Z", ResponseBytes: response, AuthorizationDigest: auth,
		EvidenceSource: evidenceSource, RunnerHold: "retained", TrustProvenance: "unverified", TrustHostID: id, TrustBindingRevision: id}
}

func candidateEnvelope(snapshot nativeEvidenceSnapshot, constructionCount *int) (string, error) {
	encoded, err := encodeNativeTerminalEvidence(snapshot)
	if err != nil {
		return "codec", err
	}
	if len(encoded.PayloadBytes) > 360*1024 {
		return "payload-candidate", errNativeEvidence
	}
	if len(snapshot.ResponseBytes) > 256*1024 {
		return "response-candidate", errNativeEvidence
	}
	*constructionCount++
	_, err = transport.NewEnvelope("host-1", "request-1", "agent.command.result", "nonce-1", strings.Repeat("a", 64), "ABCD", 1,
		time.Date(2026, 11, 11, 20, 0, 0, 0, time.UTC), base64.StdEncoding.EncodeToString(encoded.PayloadBytes))
	return "", err
}

// This is an offline size-only test. NewEnvelope's acceptance does not imply
// application result-schema, signature, trust, handler, or runtime acceptance.
func TestEvidenceSizeConformance(t *testing.T) {
	const bodyLimit = 512 * 1024
	const unknownLimit = 32 * 1024
	newEnvelope := func(kind string, payload any) error {
		_, err := transport.NewEnvelope("host-1", "request-1", kind, "nonce-1", strings.Repeat("a", 64), "ABCD", 1,
			time.Date(2026, 11, 11, 20, 0, 0, 0, time.UTC), payload)
		return err
	}

	// Actual NewEnvelope JSON-marshaled payload-byte boundaries.
	if err := newEnvelope("agent.command.result", strings.Repeat("x", bodyLimit-2)); err != nil {
		t.Fatalf("result exact cap rejected: %v", err)
	}
	if err := newEnvelope("agent.command.result", strings.Repeat("x", bodyLimit-1)); err == nil {
		t.Fatal("result cap+1 accepted")
	}
	if err := newEnvelope("test.unknown", strings.Repeat("x", unknownLimit-2)); err != nil {
		t.Fatalf("unknown exact default cap rejected: %v", err)
	}
	if err := newEnvelope("test.unknown", strings.Repeat("x", unknownLimit-1)); err == nil {
		t.Fatal("unknown default cap+1 accepted")
	}

	const responseLimit = 512 * 1024
	const proposedResponseLimit = 256 * 1024
	const proposedPayloadLimit = 360 * 1024
	if got := 4 * ((responseLimit + 2) / 3); got != 699052 {
		t.Fatalf("current response base64 arithmetic: %d", got)
	}
	if got := 4 * ((768*1024 + 2) / 3); got != 1048576 {
		t.Fatalf("current payload base64 arithmetic: %d", got)
	}
	if got := 4 * ((proposedResponseLimit + 2) / 3); got != 349528 {
		t.Fatalf("proposed response base64 arithmetic: %d", got)
	}
	if got := 4 * ((proposedPayloadLimit + 2) / 3); got != 491520 {
		t.Fatalf("proposed payload base64 arithmetic: %d", got)
	}

	t.Run("maximum legal metadata proposal vector", func(t *testing.T) {
		snapshot := maxMetadataEvidenceSnapshot(t, proposedResponseLimit)
		encoded, err := encodeNativeTerminalEvidence(snapshot)
		if err != nil {
			t.Fatal("maximum metadata codec encode failed:", err)
		}
		decoded, err := decodeNativeTerminalEvidence(encoded.PayloadBytes, snapshot)
		if err != nil || len(decoded.ResponseBytes) != proposedResponseLimit {
			t.Fatalf("maximum metadata codec round trip failed: %v", err)
		}
		outer := base64.StdEncoding.EncodeToString(encoded.PayloadBytes)
		wrapped, err := json.Marshal(outer)
		if err != nil {
			t.Fatal("maximum metadata outer JSON marshal failed:", err)
		}
		env, err := transport.NewEnvelope("host-1", "request-1", "agent.command.result", "nonce-2", strings.Repeat("a", 64), "ABCD", 1,
			time.Date(2026, 11, 11, 20, 0, 0, 0, time.UTC), outer)
		if err != nil {
			t.Fatal("maximum metadata candidate rejected by synthetic transport:", err)
		}
		full, err := json.Marshal(env)
		if err != nil {
			t.Fatal("maximum metadata full envelope marshal failed:", err)
		}
		if len(encoded.PayloadBytes) != 350891 || evidenceDigest(encoded.PayloadBytes) != "ddfa7d7692a7e6f18cedef72386b6507c07133867550edb927d46b123d63e674" || len(outer) != 467856 || len(wrapped) != 467858 || len(full) != 468192 {
			t.Fatalf("frozen max metadata vector changed: response=%d payload=%d hash=%s outer=%d wrapped=%d fullEnvelope=%d",
				len(snapshot.ResponseBytes), len(encoded.PayloadBytes), evidenceDigest(encoded.PayloadBytes), len(outer), len(wrapped), len(full))
		}
		if len(encoded.PayloadBytes) > proposedPayloadLimit || len(wrapped) > bodyLimit || len(full) >= 786432 {
			t.Fatalf("maximum metadata candidate outside size candidate: payload=%d wrapped=%d envelope=%d", len(encoded.PayloadBytes), len(wrapped), len(full))
		}
	})

	t.Run("future local candidate +1 rejects before NewEnvelope", func(t *testing.T) {
		count := 0
		if reason, err := candidateEnvelope(maxMetadataEvidenceSnapshot(t, proposedResponseLimit+1), &count); reason != "response-candidate" || err == nil {
			t.Fatalf("response +1 was not locally rejected: reason=%s err=%v", reason, err)
		}
		payloadOver := maxMetadataEvidenceSnapshotWithSource(t, 275461, "explicit_snapshot", 126)
		encodedOver, err := encodeNativeTerminalEvidence(payloadOver)
		if err != nil || len(encodedOver.PayloadBytes) != proposedPayloadLimit+1 {
			t.Fatalf("payload +1 vector mismatch: payload=%d err=%v", len(encodedOver.PayloadBytes), err)
		}
		if reason, err := candidateEnvelope(payloadOver, &count); reason != "payload-candidate" || err == nil {
			t.Fatalf("payload +1 was not locally rejected: reason=%s err=%v", reason, err)
		}
		if count != 0 {
			t.Fatalf("rejected local candidates constructed %d envelopes", count)
		}
		if reason, err := candidateEnvelope(maxMetadataEvidenceSnapshot(t, proposedResponseLimit), &count); reason != "" || err != nil || count != 1 {
			t.Fatalf("candidate boundary did not reach exactly one envelope: reason=%s err=%v count=%d", reason, err, count)
		}
	})

	t.Run("raw codec payload cap and oversized transport", func(t *testing.T) {
		snapshot := maxMetadataEvidenceSnapshot(t, proposedResponseLimit)
		encoded, err := encodeNativeTerminalEvidence(snapshot)
		if err != nil {
			t.Fatal("raw-cap source encode failed:", err)
		}
		atCap := append(append([]byte(nil), encoded.PayloadBytes...), bytes.Repeat([]byte(" "), maxNativeEvidencePayloadBytes-len(encoded.PayloadBytes))...)
		if _, err = decodeNativeTerminalEvidence(atCap, snapshot); err != nil {
			t.Fatal("valid JSON padded to raw codec cap rejected:", err)
		}
		if _, err = decodeNativeTerminalEvidence(append(atCap, ' '), snapshot); err == nil {
			t.Fatal("raw codec cap +1 accepted")
		}
		if err = newEnvelope("agent.command.result", base64.StdEncoding.EncodeToString(atCap)); err == nil {
			t.Fatal("actual NewEnvelope accepted oversized outer encoding")
		}
	})

	t.Run("UTF-8 JSON byte measurement", func(t *testing.T) {
		encoded, err := json.Marshal(map[string]string{"evidence": "雪"})
		if err != nil {
			t.Fatal("unicode JSON marshal failed:", err)
		}
		if len(encoded) != 18 {
			t.Fatalf("Go encoding/json UTF-8 byte length = %d, want 18 paired with TS JS string length 16 / byte length 18", len(encoded))
		}
		if err = newEnvelope("agent.command.result", map[string]string{"evidence": "雪"}); err != nil {
			t.Fatal("actual NewEnvelope rejected small UTF-8 body:", err)
		}
	})

	base, _ := evidenceFixtureSnapshot(t)
	for _, tc := range []struct {
		name          string
		want          int
		payloadBytes  int
		payloadSHA256 string
		outerBytes    int
		wrappedBytes  int
		fits          bool
	}{
		{name: "current-max-response", want: responseLimit, payloadBytes: 699798,
			payloadSHA256: "e1973574b4082ac653609bfa8c6eb1607c84a21783cb5eeb58b6ac8a96686658", outerBytes: 933064, wrappedBytes: 933066, fits: false},
		{name: "proposed-response", want: proposedResponseLimit, payloadBytes: 350274,
			payloadSHA256: "580abfc50192432ec31d30b8d7e30258c80f58560001fd962926ec5ff44c4a82", outerBytes: 467032, wrappedBytes: 467034, fits: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := append([]byte(nil), base.ResponseBytes...)
			if len(raw) >= tc.want {
				t.Fatal("fixture response unexpectedly large")
			}
			raw = append(raw, []byte(strings.Repeat(" ", tc.want-len(raw)))...)
			snapshot := base
			snapshot.ResponseBytes = raw
			encoded, err := encodeNativeTerminalEvidence(snapshot)
			if err != nil {
				t.Fatalf("codec rejected %d-byte response: %v", tc.want, err)
			}
			decoded, err := decodeNativeTerminalEvidence(encoded.PayloadBytes, snapshot)
			if err != nil || len(decoded.ResponseBytes) != tc.want {
				t.Fatalf("codec round trip failed at %d: %v", tc.want, err)
			}
			responseBase64 := base64.StdEncoding.EncodeToString(raw)
			if len(responseBase64) != 4*((tc.want+2)/3) {
				t.Fatalf("response base64 size mismatch: %d", len(responseBase64))
			}
			outer := base64.StdEncoding.EncodeToString(encoded.PayloadBytes)
			payloadHash := evidenceDigest(encoded.PayloadBytes)
			jsonPayload, err := json.Marshal(outer)
			if len(encoded.PayloadBytes) != tc.payloadBytes || payloadHash != tc.payloadSHA256 || len(outer) != tc.outerBytes || len(jsonPayload) != tc.wrappedBytes {
				t.Fatalf("frozen size vector mismatch: payload=%d hash=%s outer=%d wrapped=%d", len(encoded.PayloadBytes), payloadHash, len(outer), len(jsonPayload))
			}
			if err != nil {
				t.Fatal("synthetic payload marshal failed")
			}
			if !tc.fits {
				if len(outer) <= bodyLimit || newEnvelope("agent.command.result", outer) == nil {
					t.Fatal("current maximum response unexpectedly fit result transport size bound")
				}
				return
			}
			if len(encoded.PayloadBytes) > proposedPayloadLimit || len(jsonPayload) > bodyLimit {
				t.Fatalf("proposed vector does not fit: raw=%d wrapper=%d", len(encoded.PayloadBytes), len(jsonPayload))
			}
			if err := newEnvelope("agent.command.result", outer); err != nil {
				t.Fatalf("synthetic proposed-size payload rejected: %v", err)
			}
			envelope, err := transport.NewEnvelope("host-1", "request-1", "agent.command.result", "nonce-2", strings.Repeat("a", 64), "ABCD", 1,
				time.Date(2026, 11, 11, 20, 0, 0, 0, time.UTC), outer)
			if err != nil {
				t.Fatal("synthetic envelope rejected")
			}
			full, err := json.Marshal(envelope)
			if err != nil || len(full) >= 786432 {
				t.Fatalf("serialized envelope not below existing whole-request cap: %d (%v)", len(full), err)
			}
		})
	}

	if bodyLimit-491520 != 32768 {
		t.Fatal("proposed outer-base64 wrapper headroom changed")
	}
}
