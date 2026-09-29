package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/enrollment"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/service"
)

func testCA(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), enrollment.FingerprintSHA256(der)
}

func clearEnrollmentEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range enrollmentEnvironment {
		t.Setenv(key, "")
		_ = os.Unsetenv(key)
	}
}

func TestLoadConfigRejectsUnknownLANMMEnvironment(t *testing.T) {
	t.Setenv("LANMM_UNEXPECTED", "value")
	if _, err := loadConfig(); err == nil {
		t.Fatal("unknown LANMM environment variable accepted")
	}
}

func TestEnrollmentConfigurationIsExplicitAndAllOrNone(t *testing.T) {
	clearEnrollmentEnvironment(t)
	root := t.TempDir()
	cfg := service.Config{HostID: "agent-1", StateDir: root}
	if err := configureEnrollment(&cfg); err != nil || cfg.Enroller != nil {
		t.Fatalf("default err=%v enroller=%T", err, cfg.Enroller)
	}

	t.Setenv("LANMM_ENROLLMENT_CONTROLLER_URL", "https://controller.example:7443")
	if err := configureEnrollment(&cfg); err == nil {
		t.Fatal("partial enrollment accepted")
	}

	caPEM, pin := testCA(t)
	t.Setenv("LANMM_ENROLLMENT_CA_CERT_PEM", caPEM)
	t.Setenv("LANMM_ENROLLMENT_CA_FINGERPRINT_SHA256", pin)
	t.Setenv("LANMM_ENROLLMENT_CANDIDATE_ADDRESS", "192.168.1.20")
	t.Setenv("LANMM_ENROLLMENT_CANDIDATE_PORT", "7443")
	t.Setenv("LANMM_ENROLLMENT_PROTOCOL_MAJOR", "1")
	t.Setenv("LANMM_ENROLLMENT_PROTOCOL_MINOR", "0")
	if err := configureEnrollment(&cfg); err != nil || cfg.Enroller == nil {
		t.Fatalf("complete err=%v enroller=%T", err, cfg.Enroller)
	}

	file := filepath.Join(root, "ca.pem")
	if err := os.WriteFile(file, []byte(caPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LANMM_ENROLLMENT_CA_CERT_FILE", file)
	if err := configureEnrollment(&cfg); err == nil {
		t.Fatal("simultaneous PEM and file accepted")
	}
	t.Setenv("LANMM_ENROLLMENT_CA_CERT_PEM", "")
	_ = os.Unsetenv("LANMM_ENROLLMENT_CA_CERT_PEM")
	if err := configureEnrollment(&cfg); err != nil {
		t.Fatalf("CA file rejected: %v", err)
	}
}

func TestPinnedCAFileRejectsRelativeSymlinkAndOversize(t *testing.T) {
	caPEM, _ := testCA(t)
	root := t.TempDir()
	regular := filepath.Join(root, "ca.pem")
	if err := os.WriteFile(regular, []byte(caPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	if value, err := readPinnedCAFile(regular); err != nil || value != caPEM {
		t.Fatalf("regular err=%v", err)
	}
	if _, err := readPinnedCAFile("ca.pem"); err == nil {
		t.Fatal("relative path accepted")
	}
	link := filepath.Join(root, "link.pem")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPinnedCAFile(link); err == nil {
		t.Fatal("symlink accepted")
	}
	large := filepath.Join(root, "large.pem")
	if err := os.WriteFile(large, make([]byte, (64<<10)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPinnedCAFile(large); err == nil {
		t.Fatal("oversized CA accepted")
	}
}
