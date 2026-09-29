package enrollment

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/pairing"
)

type failingReader struct {
	secret string
}

func (f failingReader) Read([]byte) (int, error) { return 0, errors.New(f.secret) }

func identityBinding() pairing.Binding {
	return pairing.Binding{CandidateID: "agent-1", Address: "192.168.1.20", Port: 7443, ProtocolMajor: 1}
}

func TestIdentityGenerateLoadRestartAndPermissions(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "certs")
	store := IdentityStore{CertDir: directory}
	first, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	second, err := (IdentityStore{CertDir: directory, Random: failingReader{secret: "must-not-read"}}).LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if !first.Equal(second) {
		t.Fatal("restart loaded a different key")
	}
	info, err := os.Stat(filepath.Join(directory, identityKeyName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %o", info.Mode().Perm())
	}
	raw, err := os.ReadFile(filepath.Join(directory, identityKeyName))
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		t.Fatal("identity is not exactly one PKCS#8 PEM block")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityConcurrentCreatePublishesOneKey(t *testing.T) {
	store := IdentityStore{CertDir: filepath.Join(t.TempDir(), "certs")}
	const callers = 12
	keys := make(chan *ecdsa.PrivateKey, callers)
	errorsSeen := make(chan error, callers)
	var wait sync.WaitGroup
	for i := 0; i < callers; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			key, err := store.LoadOrCreate()
			if err != nil {
				errorsSeen <- err
				return
			}
			keys <- key
		}()
	}
	wait.Wait()
	close(keys)
	close(errorsSeen)
	for err := range errorsSeen {
		t.Fatal(err)
	}
	var first *ecdsa.PrivateKey
	for key := range keys {
		if first == nil {
			first = key
		} else if !first.Equal(key) {
			t.Fatal("concurrent callers observed different identities")
		}
	}
	if first == nil {
		t.Fatal("no identity returned")
	}
}

func TestIdentityEntropyFailureAndNoOverwrite(t *testing.T) {
	secret := "entropy-secret-value"
	store := IdentityStore{CertDir: filepath.Join(t.TempDir(), "certs"), Random: failingReader{secret: secret}}
	if _, err := store.LoadOrCreate(); !errors.Is(err, ErrIdentity) || strings.Contains(err.Error(), secret) {
		t.Fatalf("unredacted entropy error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.CertDir, identityKeyName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial key was published: %v", err)
	}

	validStore := IdentityStore{CertDir: filepath.Join(t.TempDir(), "valid")}
	key, err := validStore.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(validStore.CertDir, identityKeyName))
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := (IdentityStore{CertDir: validStore.CertDir, Random: failingReader{secret: secret}}).LoadOrCreate()
	if err != nil || !key.Equal(loaded) {
		t.Fatalf("valid key was not preserved: %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(validStore.CertDir, identityKeyName))
	if !bytes.Equal(raw, after) {
		t.Fatal("valid key was overwritten")
	}
}

func TestMalformedAndWrongCurveKeysAreQuarantined(t *testing.T) {
	for name, contents := range map[string][]byte{
		"malformed": []byte("PRIVATE SECRET material"),
		"wrong-curve": func() []byte {
			key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			der, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, identityKeyName)
			if err := os.WriteFile(path, contents, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := (IdentityStore{CertDir: directory}).LoadOrCreate(); !errors.Is(err, ErrIdentityCorrupt) || strings.Contains(err.Error(), string(contents)) {
				t.Fatalf("load error = %v", err)
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("bad key remains at live path: %v", err)
			}
			matches, err := filepath.Glob(path + ".corrupt-*")
			if err != nil || len(matches) != 1 {
				t.Fatalf("quarantine matches=%v err=%v", matches, err)
			}
		})
	}
}

func TestCreateCSRBindingAndSignature(t *testing.T) {
	store := IdentityStore{CertDir: filepath.Join(t.TempDir(), "certs")}
	binding := identityBinding()
	encoded, key, err := store.CreateCSR(binding)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(rest) != 0 {
		t.Fatal("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("CSR signature: %v", err)
	}
	if !csrMatchesBinding(csr, binding) || !csr.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Fatal("CSR does not match binding/key")
	}
	bad := binding
	bad.Address = "192.168.001.020"
	if _, _, err := store.CreateCSR(bad); !errors.Is(err, ErrIdentity) {
		t.Fatalf("accepted invalid binding: %v", err)
	}
}

type issuedFixture struct {
	result Result
	key    *ecdsa.PrivateKey
	roots  *x509.CertPool
	pin    string
	now    time.Time
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
}

func makeIssued(t *testing.T, mutate func(*x509.Certificate)) issuedFixture {
	t.Helper()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: bigInt(1), Subject: pkix.Name{CommonName: "LAN Model Manager CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := identityBinding()
	leafTemplate := &x509.Certificate{SerialNumber: bigInt(2), Subject: pkix.Name{CommonName: binding.CandidateID}, IPAddresses: []net.IP{net.ParseIP(binding.Address)}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if mutate != nil {
		mutate(leafTemplate)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	pin := FingerprintSHA256(caDER)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	return issuedFixture{result: Result{PinnedCAFingerprintSHA256: pin, Binding: binding, CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})), CAPEM: string(caPEM)}, key: key, roots: roots, pin: pin, now: now, caKey: caKey, caCert: caCert}
}

func TestVerifyIssuedSuccessWithPoolAndPEM(t *testing.T) {
	fixture := makeIssued(t, nil)
	if err := VerifyIssued(fixture.result, fixture.key, fixture.roots, fixture.pin, fixture.now); err != nil {
		t.Fatal(err)
	}
	if err := VerifyIssued(fixture.result, fixture.key, []byte(fixture.result.CAPEM), fixture.pin, fixture.now); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyIssuedRejectsWrongKeyBindingEKUValidityCAAndPin(t *testing.T) {
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tests := []struct {
		name   string
		mutate func(*issuedFixture)
	}{
		{"key", func(f *issuedFixture) { f.key = wrongKey }},
		{"cn", func(f *issuedFixture) { f.result.Binding.CandidateID = "other-agent" }},
		{"san", func(f *issuedFixture) { f.result.Binding.Address = "192.168.1.21" }},
		{"expired", func(f *issuedFixture) { f.now = f.now.Add(48 * time.Hour) }},
		{"ca", func(f *issuedFixture) { f.roots = x509.NewCertPool() }},
		{"pin", func(f *issuedFixture) { f.pin = strings.Repeat("0", 64) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := makeIssued(t, nil)
			test.mutate(&fixture)
			if err := VerifyIssued(fixture.result, fixture.key, fixture.roots, fixture.pin, fixture.now); !errors.Is(err, ErrIssuedInvalid) {
				t.Fatalf("accepted invalid certificate: %v", err)
			}
		})
	}
	noEKU := makeIssued(t, func(template *x509.Certificate) {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	})
	if err := VerifyIssued(noEKU.result, noEKU.key, noEKU.roots, noEKU.pin, noEKU.now); !errors.Is(err, ErrIssuedInvalid) {
		t.Fatalf("accepted wrong EKU: %v", err)
	}
}

func TestVerifyIssuedErrorsAreRedactedAndLeafIsExact(t *testing.T) {
	fixture := makeIssued(t, nil)
	secret := "private-controller-secret"
	fixture.result.CertificatePEM += secret
	err := VerifyIssued(fixture.result, fixture.key, fixture.roots, fixture.pin, fixture.now)
	if !errors.Is(err, ErrIssuedInvalid) || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), fixture.result.CertificatePEM) {
		t.Fatalf("unredacted error: %v", err)
	}
}

func bigInt(value int64) *big.Int { return big.NewInt(value) }

var _ io.Reader = failingReader{}
