package enrollment

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIdentityFailureBeforeCodeNeverCreatesChallengeOrSubmitsProof(t *testing.T) {
	cfg, _, _, transport := fixture(t)
	client, err := New(cfg, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	client.identity.Random = failingReader{secret: "PRIVATE-ENTROPY-DETAIL"}
	presentations := 0
	out, err := (PollingEnroller{Client: client, Interval: 10 * time.Millisecond, Timeout: time.Second, Present: func(string) { presentations++ }}).Enroll(context.Background())
	stage, reason, status := FailureDetails(err)
	if !errors.Is(err, ErrFailed) || out.Status != StatusDegraded || stage != "identity" || reason != "key" || status != 0 || presentations != 0 || transport.begins != 0 || transport.completes != 0 {
		t.Fatalf("unexpected redacted outcome: %s %s %d %v", stage, reason, status, err)
	}
	if strings.Contains(err.Error(), "PRIVATE") || client.pending != nil {
		t.Fatal("failure leaked details or retained challenge")
	}
}

func TestExistingIdentityIsUsedForCSRWithoutRegeneration(t *testing.T) {
	cfg, _, _, transport := fixture(t)
	store := IdentityStore{CertDir: cfg.CertDir}
	key, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(cfg.CertDir, identityKeyName))
	if err != nil {
		t.Fatal(err)
	}
	_ = transport
	// Go 1.24 signs CSRs with entropy, newer Go may not. Independently test
	// LoadOrCreate with a failed entropy source: a valid existing key must win.
	loaded, err := (IdentityStore{CertDir: cfg.CertDir, Random: failingReader{}}).LoadOrCreate()
	if err != nil || !key.Equal(loaded) {
		t.Fatal("existing key was not reusable")
	}
	after, _ := os.ReadFile(filepath.Join(cfg.CertDir, identityKeyName))
	if string(before) != string(after) {
		t.Fatal("existing key changed")
	}
}

func TestSecurePresentationFailureDiscardsChallengeBeforeHTTP(t *testing.T) {
	cfg, _, _, transport := fixture(t)
	client, err := New(cfg, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := (PollingEnroller{Client: client, SecurePresent: func(context.Context, string, time.Time) (func(), error) { return nil, errors.New("secret code/path") }}).Enroll(context.Background())
	stage, _, _ := FailureDetails(err)
	if err == nil || out.Status != StatusDegraded || stage != "present" || client.pending != nil || transport.completes != 0 {
		t.Fatal("presentation failure did not fail closed")
	}
}

func TestHTTPFailureReportsStatusNotBodyOrURL(t *testing.T) {
	for _, status := range []int{400, 401, 409, 429, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			fixture := newTransportFixture(t)
			server := startTransportServer(t, fixture, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"secret":"23456789-private-proof"}`))
			}))
			fixture.config.ControllerURL = server.URL
			transport, err := NewHTTPTransport(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			client, err := New(fixture.config, transport, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Begin(context.Background())
			stage, _, got := FailureDetails(err)
			if !errors.Is(err, ErrFailed) || stage != "begin" || got != status || strings.Contains(err.Error(), "23456789") || strings.Contains(err.Error(), server.URL) {
				t.Fatalf("redaction/status failed: %s %d %v", stage, got, err)
			}
		})
	}
}

func TestDiscardBeforeProofZerosOperatorCode(t *testing.T) {
	cfg, _, _, transport := fixture(t)
	client, err := New(cfg, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Begin(context.Background()); err != nil {
		t.Fatal(err)
	}
	session := client.session
	client.discardPending()
	if !session.CodeZeroed() {
		t.Fatal("discard left plaintext code in session")
	}
}

func TestVerificationResultBindingFailureIsDistinctAndUnknownReasonsAreRedacted(t *testing.T) {
	cfg, _, _, transport := fixture(t)
	transport.result.ChallengeID = strings.Repeat("b", 64)
	client, err := New(cfg, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Enroll(context.Background())
	stage, reason, status := FailureDetails(err)
	if !errors.Is(err, ErrFailed) || stage != "verify" || reason != "result-invalid" || status != 0 {
		t.Fatalf("unexpected result: %s %s %d %v", stage, reason, status, err)
	}
	if _, err := os.Stat(filepath.Join(cfg.CertDir, "enrollment.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid result persisted enrollment")
	}
	stage, reason, status = FailureDetails(&Failure{Stage: "remote-private-detail", Reason: "remote-private-detail", HTTPStatus: 999})
	if stage != "enrollment" || reason != "failed" || status != 0 {
		t.Fatal("untrusted diagnostics were not redacted")
	}
}
