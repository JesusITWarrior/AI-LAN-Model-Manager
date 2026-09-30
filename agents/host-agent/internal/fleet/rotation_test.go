package fleet

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentcert "github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/certificate"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/enrollment"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/pairing"
)

func TestCertificateRenewalDueBoundaries(t *testing.T) {
	now := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	leaf := &x509.Certificate{NotAfter: now.Add(7 * 24 * time.Hour)}
	if !certificateRenewalDue(leaf, now, 7*24*time.Hour) {
		t.Fatal("exact boundary not due")
	}
	leaf.NotAfter = leaf.NotAfter.Add(time.Millisecond)
	if certificateRenewalDue(leaf, now, 7*24*time.Hour) {
		t.Fatal("early rotation")
	}
	leaf.NotAfter = now.Add(-time.Second)
	if !certificateRenewalDue(leaf, now, 7*24*time.Hour) {
		t.Fatal("expired certificate not due")
	}
}

func TestIdentityGenerationRestartAndInterruptedOrphan(t *testing.T) {
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("chmod")
	}
	binding := pairing.Binding{CandidateID: "agent-1", Address: "192.168.1.20", Port: 7443, ProtocolMajor: 1}
	request, err := agentcert.GenerateRequest(agentcert.Binding{CandidateID: binding.CandidateID, Address: binding.Address, Port: binding.Port, ProtocolMajor: binding.ProtocolMajor})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(request.PrivateKeyPEM)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key := parsed.(*ecdsa.PrivateKey)
	_ = key
	result := enrollment.Result{ControllerURL: "https://192.168.1.10:7443", PinnedCAFingerprintSHA256: string(make([]byte, 64)), ChallengeID: string(make([]byte, 64)), Binding: binding, CertificatePEM: "certificate-one", CAPEM: "ca", EnrolledAt: time.Now().UTC()}
	pending := pendingRotation{Generation: "1" + string(make([]byte, 31)), KeyPEM: string(request.PrivateKeyPEM), CSRPEM: string(request.CSRPEM), SourceFingerprint: string(make([]byte, 64))}
	// Use canonical hexadecimal fixture values rather than NUL-filled placeholders.
	pending.Generation = "1" + repeatHex("a", 31)
	result.PinnedCAFingerprintSHA256 = repeatHex("b", 64)
	result.ChallengeID = repeatHex("c", 64)
	pending.SourceFingerprint = repeatHex("d", 64)
	if err = publishIdentityGeneration(dir, pending, result); err != nil {
		t.Fatal(err)
	}
	loaded, loadedKey, err := loadFleetIdentity(dir)
	if err != nil || loaded.CertificatePEM != "certificate-one" || loadedKey.D.Cmp(key.D) != 0 {
		t.Fatalf("restart load failed: %v", err)
	}
	orphan := filepath.Join(dir, "fleet-identities", repeatHex("e", 32))
	if err = os.Mkdir(orphan, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(orphan, "partial"), []byte("interrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, _, err = loadFleetIdentity(dir)
	if err != nil || loaded.CertificatePEM != "certificate-one" {
		t.Fatalf("orphan replaced active identity: %v", err)
	}
	// Exact immutable generation completed before a pointer crash is resumable.
	second := result
	second.CertificatePEM = "certificate-two"
	p2 := pending
	p2.Generation = repeatHex("f", 32)
	target := filepath.Join(dir, "fleet-identities", p2.Generation)
	if err = os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err = writeSecure(filepath.Join(target, "host-key.pem"), []byte(p2.KeyPEM)); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(second)
	if err = writeSecure(filepath.Join(target, "enrollment.json"), append(encoded, '\n')); err != nil {
		t.Fatal(err)
	}
	if err = publishIdentityGeneration(dir, p2, second); err != nil {
		t.Fatal(err)
	}
	loaded, _, err = loadFleetIdentity(dir)
	if err != nil || loaded.CertificatePEM != "certificate-two" {
		t.Fatalf("pointer recovery = %#v, %v", loaded, err)
	}
}
func repeatHex(v string, n int) string {
	out := ""
	for len(out) < n {
		out += v
	}
	return out[:n]
}
