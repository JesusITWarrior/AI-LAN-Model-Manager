package fleet

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/command"
	agenttransport "github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/transport"
)

type commandRoundTrip func(*http.Request) (*http.Response, error)

func (f commandRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type ordinaryFailureAdapter struct{ calls int }

func (a *ordinaryFailureAdapter) Execute(context.Context, string, json.RawMessage) (any, error) {
	a.calls++
	return nil, errors.New("private provider endpoint and prompt must not escape")
}

// Synthetic certificates and real serialized/signed envelopes exercise the same
// strict verifier and durable controller sequence reservation as the native host.
func signedCommandClient(t *testing.T, mutate func([]byte) []byte, next func(int) *command.Request, result func(command.Response) int) *HTTPSClient {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(17), Subject: pkix.Name{CommonName: "controller"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	fp := sha256.Sum256(der)
	fingerprint := hex.EncodeToString(fp[:])
	polls := 0
	client := &HTTPSClient{base: "https://synthetic.invalid", hostID: "host-1", fingerprint: fingerprint, serial: "11", privateKey: keyPEM, store: SequenceStore{CertDir: t.TempDir()}, now: time.Now}
	client.http = &http.Client{Transport: commandRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Context().Err() != nil {
			return nil, r.Context().Err()
		}
		var request agenttransport.Envelope
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			t.Fatal("bad request wire")
		}
		response := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}}
		if r.URL.Path == commandPollPath {
			polls++
			env, err := agenttransport.NewEnvelope("host-1", request.RequestID, "controller.command.poll", "synthetic-nonce", fingerprint, "11", request.Sequence, time.Now(), map[string]any{"command": next(polls), "cancelledJobIds": []string{}, "streamCommand": nil})
			if err != nil || agenttransport.Sign(&env, keyPEM) != nil {
				t.Fatal("sign")
			}
			raw, _ := json.Marshal(env)
			if mutate != nil {
				raw = mutate(raw)
			}
			response.Body = io.NopCloser(bytes.NewReader(raw))
			return response, nil
		}
		if r.URL.Path != commandResultPath {
			t.Fatal("unexpected command path")
		}
		var value command.Response
		if json.Unmarshal(request.Payload, &value) != nil {
			t.Fatal("bad result wire")
		}
		response.StatusCode = result(value)
		body := `{"ok":true}`
		if response.StatusCode != 200 {
			body = `{"ok":false,"error":"ERR_COMMAND_RESULT"}`
		}
		response.Body = io.NopCloser(strings.NewReader(body))
		return response, nil
	})}
	return client
}
func runnerRequest(job string, deadline time.Time) command.Request {
	model := "model-1"
	stamp := deadline.UTC().Format("2006-01-02T15:04:05.000Z")
	r := command.Request{RequestID: "request-" + job, JobID: job, HostID: "host-1", Operation: "load", IdempotencyKey: "idem-" + job, Sequence: 1, Deadline: stamp, Params: json.RawMessage(`{"providerId":"ollama-main","model":"acme/bert:latest"}`), Capability: command.Capability{Operation: "model-load", TargetKind: "model", TargetID: model, HostID: "host-1", ModelID: &model, ExpiresAt: stamp}}
	var params any
	_ = json.Unmarshal(r.Params, &params)
	bound := map[string]any{"requestId": r.RequestID, "jobId": r.JobID, "hostId": r.HostID, "operation": r.Operation, "idempotencyKey": r.IdempotencyKey, "sequence": r.Sequence, "deadline": r.Deadline, "params": params, "capability": map[string]any{"operation": r.Capability.Operation, "targetKind": "model", "targetId": model, "hostId": r.HostID, "modelId": model, "expiresAt": stamp}}
	raw, _ := json.Marshal(bound)
	sum := sha256.Sum256(raw)
	r.Capability.RequestDigest = hex.EncodeToString(sum[:])
	return r
}
func TestSignedNativePollReportsCodecCertificateSignatureAndSequenceStages(t *testing.T) {
	for _, code := range []string{"POLL_CODEC", "POLL_CERTIFICATE", "POLL_SIGNATURE", "POLL_SEQUENCE"} {
		t.Run(code, func(t *testing.T) {
			var logs bytes.Buffer
			prior := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
			defer slog.SetDefault(prior)
			mutate := func(raw []byte) []byte {
				switch code {
				case "POLL_CODEC":
					return append([]byte(`{"unexpected":true,`), raw[1:]...)
				case "POLL_CERTIFICATE":
					return bytes.Replace(raw, []byte(`"certSerial":"11"`), []byte(`"certSerial":"12"`), 1)
				case "POLL_SIGNATURE":
					return bytes.Replace(raw, []byte(`"signature":"`), []byte(`"signature":"00`), 1)
				}
				return raw
			}
			client := signedCommandClient(t, mutate, func(int) *command.Request { return nil }, func(command.Response) int { return 200 })
			if code == "POLL_SEQUENCE" {
				if os.WriteFile(filepath.Join(client.store.CertDir, "controller-command-sequence"), []byte("999\n"), 0600) != nil {
					t.Fatal("sequence fixture")
				}
			}
			if _, _, err := client.PollCommand(context.Background(), 0); err == nil {
				t.Fatal("invalid poll accepted")
			}
			if !strings.Contains(logs.String(), code) {
				t.Fatalf("missing stage %s", code)
			}
		})
	}
}
func TestRunCommandsRetriesOrdinaryFailureAndContinuesAfterAcknowledgement(t *testing.T) {
	var logs bytes.Buffer
	prior := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(prior)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	first := runnerRequest("first", time.Now().Add(time.Minute))
	second := runnerRequest("second", time.Now().Add(time.Minute))
	var results []string
	client := signedCommandClient(t, nil, func(n int) *command.Request {
		if n == 1 {
			return &first
		}
		return &second
	}, func(r command.Response) int {
		if r.Status != "failed" || r.ErrorCode == nil || *r.ErrorCode != "ADAPTER_FAILED" {
			t.Fatal("ordinary adapter failure was lost")
		}
		results = append(results, r.JobID)
		if len(results) == 1 {
			return 503
		}
		if r.JobID == "second" {
			cancel()
		}
		return 200
	})
	adapter := &ordinaryFailureAdapter{}
	executor, err := command.NewPersistent("host-1", adapter, time.Now, filepath.Join(t.TempDir(), "replay.json"))
	if err != nil {
		t.Fatal(err)
	}
	if client.RunCommands(ctx, executor) != nil {
		t.Fatal("runner")
	}
	if strings.Contains(logs.String(), "private provider") || strings.Contains(logs.String(), "acme/bert") || strings.Contains(logs.String(), "synthetic.invalid") {
		t.Fatal("command-stage diagnostics exposed private data")
	}
	for _, code := range []string{"EXECUTION_ADAPTER_FAILED", "RESULT_REJECTED", "RESULT_DELIVERED"} {
		if !strings.Contains(logs.String(), code) {
			t.Fatalf("missing stage %s", code)
		}
	}
	if strings.Join(results, ",") != "first,first,second" || adapter.calls != 2 {
		t.Fatalf("pending result retry failed: %v calls %d", results, adapter.calls)
	}
}

// Documents an existing unresolved reconciliation hazard, not a host-clear
// claim: a rejected expired result remains pending while new polls still lease.
func TestExpiredPendingResultRemainsBlockingUntilReconciled(t *testing.T) {
	var logs bytes.Buffer
	prior := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(prior)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	first := runnerRequest("expired", time.Now().Add(100*time.Millisecond))
	second := runnerRequest("later", time.Now().Add(time.Minute))
	var results []string
	client := signedCommandClient(t, nil, func(n int) *command.Request {
		if n == 1 {
			return &first
		}
		return &second
	}, func(r command.Response) int {
		results = append(results, r.JobID)
		if len(results) >= 3 {
			cancel()
		}
		return 400
	})
	adapter := &ordinaryFailureAdapter{}
	if client.RunCommands(ctx, command.New("host-1", adapter, time.Now)) != nil {
		t.Fatal("runner")
	}
	if strings.Count(logs.String(), "PENDING_RESULT_EXPIRED") != 1 {
		t.Fatal("expired pending result was not reported exactly once")
	}
	if len(results) < 3 || adapter.calls != 1 {
		t.Fatalf("pending state not reproduced: %v calls %d", results, adapter.calls)
	}
	for _, job := range results {
		if job != "expired" {
			t.Fatal("new request executed despite pending result")
		}
	}
}
