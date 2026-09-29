package enrollment

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/pairing"
)

type fakeTransport struct {
	challenge Challenge
	result    Result
	beginErr  error
	endErr    error
	begins    int
	completes int
	got       Challenge
	gotCSR    []byte
	caKey     *ecdsa.PrivateKey
	caCert    *x509.Certificate
}

func (f *fakeTransport) Begin(context.Context, pairing.Binding) (Challenge, error) {
	f.begins++
	return f.challenge, f.beginErr
}

func (f *fakeTransport) Complete(_ context.Context, ch Challenge, _ pairing.Proof, csrPEM []byte) (Result, error) {
	f.completes++
	f.got, f.gotCSR = ch, append([]byte(nil), csrPEM...)
	if f.endErr != nil {
		return Result{}, f.endErr
	}
	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(rest) != 0 {
		return Result{}, errors.New("bad csr")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return Result{}, errors.New("bad csr")
	}
	now := time.Now().UTC()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: f.result.Binding.CandidateID}, IPAddresses: []net.IP{net.ParseIP(f.result.Binding.Address)}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, f.caCert, csr.PublicKey, f.caKey)
	if err != nil {
		return Result{}, err
	}
	result := f.result
	result.CertificatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return result, nil
}

func fixture(t *testing.T) (Config, Challenge, Result, *fakeTransport) {
	t.Helper()
	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "LAN Model Manager CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	pin := FingerprintSHA256(caDER)
	cfg := Config{ControllerURL: "https://controller.example:7443", PinnedCAFingerprintSHA256: pin, CandidateID: "agent-1", Address: "192.168.1.20", Port: 7443, ProtocolMajor: 1, CertDir: t.TempDir()}
	binding, err := cfg.binding()
	if err != nil {
		t.Fatal(err)
	}
	ch := Challenge{ControllerURL: cfg.ControllerURL, PinnedCAFingerprintSHA256: pin, OperatorCode: "23456789", Pairing: pairing.Challenge{ChallengeID: strings.Repeat("a", 64), ControllerNonce: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc", Binding: binding, ExpiresAt: now.Add(time.Hour)}}
	result := Result{ControllerURL: cfg.ControllerURL, PinnedCAFingerprintSHA256: pin, ChallengeID: ch.Pairing.ChallengeID, Binding: binding, CAPEM: caPEM, EnrolledAt: now}
	transport := &fakeTransport{challenge: ch, result: result, caKey: caKey, caCert: caCert}
	return cfg, ch, result, transport
}

func TestStrictConfigAndUnconfigured(t *testing.T) {
	cfg, _, _, _ := fixture(t)
	bad := []Config{{}, cfg, cfg, cfg, cfg}
	bad[1].ControllerURL = "http://controller.example"
	bad[2].ControllerURL = "https://CONTROLLER.example"
	bad[3].PinnedCAFingerprintSHA256 = strings.ToUpper(cfg.PinnedCAFingerprintSHA256)
	bad[4].Address = "192.168.001.020"
	for i, candidate := range bad {
		if _, err := New(candidate, &fakeTransport{}, nil); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("case %d: %v", i, err)
		}
	}
}

func TestHappyPathProvesPossessionAndRestartAvoidsNetwork(t *testing.T) {
	cfg, ch, _, transport := fixture(t)
	client, err := New(cfg, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := client.Enroll(context.Background())
	if err != nil || out.Status != StatusEnrolled || out.OperatorCode != ch.OperatorCode {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	if transport.got.OperatorCode != "" || len(transport.gotCSR) == 0 {
		t.Fatal("completion boundary missing redaction or CSR")
	}
	out, err = client.Enroll(context.Background())
	if err != nil || out.OperatorCode != "" || transport.begins != 1 || transport.completes != 1 {
		t.Fatalf("replay out=%+v err=%v", out, err)
	}
	restarted, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err = restarted.Enroll(context.Background())
	if err != nil || out.Status != StatusEnrolled {
		t.Fatalf("restart out=%+v err=%v", out, err)
	}
}

func TestRestartRejectsCertificateKeyMismatch(t *testing.T) {
	cfg, _, _, transport := fixture(t)
	client, err := New(cfg, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(cfg.CertDir, "host-key.pem")
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := (IdentityStore{CertDir: cfg.CertDir}).LoadOrCreate(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg, nil, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("mismatch accepted: %v", err)
	}
}

func TestWrongBindingControllerExpiryReplayAndCancellation(t *testing.T) {
	for _, mutate := range []func(*Challenge){func(ch *Challenge) { ch.ControllerURL = "https://other.example" }, func(ch *Challenge) { ch.Pairing.Binding.Port++ }, func(ch *Challenge) { ch.Pairing.ExpiresAt = time.Now().Add(-time.Second) }} {
		cfg, ch, _, transport := fixture(t)
		mutate(&ch)
		transport.challenge = ch
		client, err := New(cfg, transport, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = client.Enroll(context.Background()); !errors.Is(err, ErrFailed) {
			t.Fatalf("first: %v", err)
		}
		if _, err = client.Enroll(context.Background()); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("replay: %v", err)
		}
		if transport.completes != 0 {
			t.Fatal("invalid challenge completed")
		}
	}
	cfg, _, _, transport := fixture(t)
	client, err := New(cfg, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = client.Enroll(ctx); !errors.Is(err, ErrUnavailable) || transport.begins != 0 {
		t.Fatalf("cancel: %v", err)
	}
}

func TestErrorsAreRedacted(t *testing.T) {
	cfg, ch, _, transport := fixture(t)
	secret := "23456789-controller-secret"
	transport.beginErr = errors.New(secret)
	client, err := New(cfg, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Enroll(context.Background())
	if !errors.Is(err, ErrFailed) || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), ch.OperatorCode) {
		t.Fatalf("leak: %v", err)
	}
}
