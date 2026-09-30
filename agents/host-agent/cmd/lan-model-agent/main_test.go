package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/enrollment"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/service"
)

func TestCommandLineHelpVersionAndUnknownArguments(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"--help"}} {
		var out bytes.Buffer
		if code, handled := handleCommandLine(args, &out); !handled || code != 0 || !strings.Contains(out.String(), "Usage: lan-model-agent") {
			t.Fatalf("help args=%v code=%d handled=%v out=%q", args, code, handled, out.String())
		}
	}
	var versionOut bytes.Buffer
	if code, handled := handleCommandLine([]string{"--version"}, &versionOut); !handled || code != 0 || versionOut.String() != "lan-model-agent "+version+"\n" {
		t.Fatalf("version code=%d handled=%v out=%q", code, handled, versionOut.String())
	}
	var badOut bytes.Buffer
	if code, handled := handleCommandLine([]string{"--unknown"}, &badOut); !handled || code != exitConfig || strings.Contains(badOut.String(), "LANMM_") {
		t.Fatalf("unknown code=%d handled=%v out=%q", code, handled, badOut.String())
	}
	if code, handled := handleCommandLine(nil, &bytes.Buffer{}); handled || code != 0 {
		t.Fatalf("service launch code=%d handled=%v", code, handled)
	}
}

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

func TestExplicitReEnrollmentArchivesIdentityAndConsumesMarker(t *testing.T) {
	state := t.TempDir()
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	cert := filepath.Join(state, "cert")
	if err := os.Mkdir(cert, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cert, "host-key.pem"), []byte("old secret"), 0600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(state, "reenroll.request")
	if err := os.WriteFile(marker, []byte("owner-authorized-reenroll\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := service.Config{StateDir: state, CertDir: cert}
	if err := prepareExplicitReEnrollment(&cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marker remains: %v", err)
	}
	entries, err := os.ReadDir(state)
	if err != nil {
		t.Fatal(err)
	}
	retired := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "cert.retired-") {
			retired++
			raw, readErr := os.ReadFile(filepath.Join(state, entry.Name(), "host-key.pem"))
			if readErr != nil || string(raw) != "old secret" {
				t.Fatalf("archive = %q, %v", raw, readErr)
			}
		}
	}
	if retired != 1 {
		t.Fatalf("retired=%d", retired)
	}
	if info, err := os.Stat(cert); err != nil || !info.IsDir() {
		t.Fatalf("new cert dir: %v", err)
	}
	if err := prepareExplicitReEnrollment(&cfg); err != nil {
		t.Fatal(err)
	}
}
func TestExplicitReEnrollmentRejectsSymlinkMarker(t *testing.T) {
	state := t.TempDir()
	target := filepath.Join(state, "target")
	if err := os.WriteFile(target, []byte("owner-authorized-reenroll\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(state, "reenroll.request")); err != nil {
		t.Skip("symlink unavailable")
	}
	if prepareExplicitReEnrollment(&service.Config{StateDir: state}) == nil {
		t.Fatal("symlink marker accepted")
	}
}
