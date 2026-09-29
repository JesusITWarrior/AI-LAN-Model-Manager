package enrollment

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestCrossLanguageEnrollmentHelper is invoked by the controller's TypeScript
// integration test. It deliberately uses the production Go transport, client,
// polling enroller, identity store, and file store against the live TLS server
// supplied by that test. A normal Go test run skips it.
func TestCrossLanguageEnrollmentHelper(t *testing.T) {
	controllerURL := os.Getenv("LANMM_CROSS_LANGUAGE_CONTROLLER_URL")
	if controllerURL == "" {
		t.Skip("controller integration helper")
	}
	caPEM := os.Getenv("LANMM_CROSS_LANGUAGE_CA_PEM")
	pin := os.Getenv("LANMM_CROSS_LANGUAGE_CA_PIN")
	certDir := os.Getenv("LANMM_CROSS_LANGUAGE_CERT_DIR")
	cfg := Config{
		ControllerURL: controllerURL, PinnedCACertificatePEM: caPEM,
		PinnedCAFingerprintSHA256: pin, CandidateID: "agent-1",
		Address: "192.168.1.20", Port: 7443, ProtocolMajor: 1,
		ProtocolMinor: 0, CertDir: certDir,
	}
	transport, err := NewHTTPTransport(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(cfg, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	var presentedCode string
	outcome, err := (PollingEnroller{
		Client: client, Interval: 10 * time.Millisecond, Timeout: 10 * time.Second,
		Present: func(code string) {
			presentedCode = code
			fmt.Printf("LANMM_CROSS_LANGUAGE_OPERATOR_CODE=%s\n", code)
		},
	}).Enroll(context.Background())
	if err != nil || outcome.Status != StatusEnrolled {
		t.Fatalf("outcome=%+v err=%v", outcome, err)
	}
	keyInfo, err := os.Stat(filepath.Join(certDir, "host-key.pem"))
	if err != nil || keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode=%v err=%v", keyInfo, err)
	}
	publicState, err := os.ReadFile(filepath.Join(certDir, stateName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(publicState), "PRIVATE KEY") || strings.Contains(string(publicState), presentedCode) {
		t.Fatal("public state contains private enrollment material")
	}
	var persisted Result
	if err := json.Unmarshal(publicState, &persisted); err != nil || persisted.CertificatePEM == "" || persisted.CAPEM != caPEM {
		t.Fatalf("persisted result invalid: err=%v", err)
	}

	// A nil transport makes the restart assertion structural: success is possible
	// only by loading and validating the persisted key/certificate/public state.
	restarted, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	restartOutcome, err := (PollingEnroller{Client: restarted, Present: func(string) { t.Fatal("restart presented a code") }}).Enroll(context.Background())
	if err != nil || restartOutcome.Status != StatusEnrolled {
		t.Fatalf("restart outcome=%+v err=%v", restartOutcome, err)
	}
	report, _ := json.Marshal(map[string]any{
		"status": outcome.Status, "restartStatus": restartOutcome.Status,
		"challengeId": persisted.ChallengeID, "certificatePersisted": true,
		"privateKeyPersisted": true, "restartTransport": "nil",
	})
	fmt.Printf("LANMM_CROSS_LANGUAGE_RESULT=%s\n", report)
}

func TestPollingEnrollerTimeoutClearsInMemoryPendingMaterial(t *testing.T) {
	cfg, _, _, transport := fixture(t)
	transport.endErr = ErrPending
	client, err := New(cfg, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	presentations := 0
	outcome, err := (PollingEnroller{Client: client, Interval: 10 * time.Millisecond, Timeout: 50 * time.Millisecond, Present: func(string) { presentations++ }}).Enroll(context.Background())
	if !errors.Is(err, ErrUnavailable) || outcome.Status != StatusPending || presentations != 1 || transport.completes == 0 {
		t.Fatalf("outcome=%+v err=%v presentations=%d completes=%d", outcome, err, presentations, transport.completes)
	}
	if client.pending != nil || client.session != nil || client.proof != nil || client.key != nil || client.csr != nil {
		t.Fatal("pending enrollment material retained after timeout")
	}
}

func TestPollingEnrollerWaitsForOwnerAndPersistsRestartableIdentity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "LANMM test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	serverPair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER}))
	if err != nil {
		t.Fatal(err)
	}

	binding := map[string]any{"candidateId": "agent-1", "address": "192.168.1.20", "port": float64(7443), "protocolMajor": float64(1), "protocolMinor": float64(0)}
	challengeID := strings.Repeat("a", 64)
	controllerNonce := "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
	operatorCode := "23456789"
	pin := FingerprintSHA256(caDER)
	var ownerConfirmed atomic.Bool
	var completeCalls atomic.Int32
	firstComplete := make(chan struct{}, 1)
	var requestMu sync.Mutex
	var firstProof string

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/agent/v1/enrollment/begin":
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "value": map[string]any{"challengeId": challengeID, "controllerNonce": controllerNonce, "binding": binding, "expiresAt": now.Add(time.Minute).Format("2006-01-02T15:04:05.000Z"), "operatorCode": operatorCode, "caFingerprint": pin}})
		case "/agent/v1/enrollment/complete":
			completeCalls.Add(1)
			proof, _ := body["proof"].(string)
			requestMu.Lock()
			if firstProof == "" {
				firstProof = proof
			} else if proof != firstProof {
				requestMu.Unlock()
				http.Error(w, "changed proof", http.StatusBadRequest)
				return
			}
			requestMu.Unlock()
			select {
			case firstComplete <- struct{}{}:
			default:
			}
			if !ownerConfirmed.Load() {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": map[string]any{"code": "OWNER_CONFIRMATION_PENDING", "message": "Owner confirmation pending."}})
				return
			}
			csrPEM, _ := body["csrPem"].(string)
			block, _ := pem.Decode([]byte(csrPEM))
			if block == nil {
				http.Error(w, "bad csr", http.StatusBadRequest)
				return
			}
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil || csr.CheckSignature() != nil {
				http.Error(w, "bad csr", http.StatusBadRequest)
				return
			}
			leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "agent-1"}, IPAddresses: []net.IP{net.ParseIP("192.168.1.20")}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
			leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, csr.PublicKey, caKey)
			if err != nil {
				http.Error(w, "issue", http.StatusInternalServerError)
				return
			}
			leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "value": map[string]any{"challengeId": challengeID, "caFingerprint": pin, "caCertificatePem": caPEM, "certificateFingerprint": FingerprintSHA256(leafDER), "certificateSerial": "03", "certificatePem": leafPEM, "notBefore": leafTemplate.NotBefore.Format("2006-01-02T15:04:05.000Z"), "notAfter": leafTemplate.NotAfter.Format("2006-01-02T15:04:05.000Z")}})
		default:
			http.NotFound(w, r)
		}
	})
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverPair}}
	server.StartTLS()
	defer server.Close()

	cfg := Config{ControllerURL: server.URL, PinnedCACertificatePEM: caPEM, PinnedCAFingerprintSHA256: pin, CandidateID: "agent-1", Address: "192.168.1.20", Port: 7443, ProtocolMajor: 1, CertDir: t.TempDir()}
	transport, err := NewHTTPTransport(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(cfg, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	presented := make(chan string, 1)
	runner := PollingEnroller{Client: client, Interval: 10 * time.Millisecond, Timeout: time.Second, Present: func(code string) { presented <- code }}
	go func() { <-firstComplete; ownerConfirmed.Store(true) }()
	outcome, err := runner.Enroll(context.Background())
	if err != nil || outcome.Status != StatusEnrolled {
		t.Fatalf("outcome=%+v err=%v", outcome, err)
	}
	if code := <-presented; code != operatorCode {
		t.Fatalf("code=%q", code)
	}
	if completeCalls.Load() < 2 {
		t.Fatalf("complete calls=%d", completeCalls.Load())
	}
	select {
	case extra := <-presented:
		t.Fatalf("code presented twice: %s", extra)
	default:
	}

	restarted, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	status := restarted.Status()
	if status.Status != StatusEnrolled || status.Result.CertificatePEM == "" || status.Result.CAPEM != caPEM {
		t.Fatalf("restart status=%+v", status)
	}
	before := completeCalls.Load()
	outcome, err = (PollingEnroller{Client: restarted, Present: func(string) { t.Fatal("restart presented code") }}).Enroll(context.Background())
	if err != nil || outcome.Status != StatusEnrolled || completeCalls.Load() != before {
		t.Fatalf("restart outcome=%+v err=%v calls=%d", outcome, err, completeCalls.Load())
	}
	for _, name := range []string{"host-key.pem", "enrollment.json"} {
		if _, err := os.Stat(filepath.Join(cfg.CertDir, name)); err != nil {
			t.Fatal(err)
		}
	}
	publicState, err := os.ReadFile(filepath.Join(cfg.CertDir, "enrollment.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(publicState), "PRIVATE KEY") || strings.Contains(string(publicState), operatorCode) {
		t.Fatal("public state contains private enrollment material")
	}
}
