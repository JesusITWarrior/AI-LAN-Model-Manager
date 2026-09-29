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
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/pairing"
)

var (
	ErrIdentity        = errors.New("enrollment identity failed")
	ErrIdentityCorrupt = errors.New("enrollment identity corrupt")
	ErrIssuedInvalid   = errors.New("issued certificate invalid")
)

const (
	identityKeyName = "host-key.pem"
	maxIdentityKey  = 64 << 10
)

// IdentityStore owns the agent's persistent enrollment key. Random may be set
// by tests; production callers leave it nil to use crypto/rand.Reader.
type IdentityStore struct {
	CertDir string
	Random  io.Reader
}

// LoadOrCreate loads the existing identity or atomically publishes a new one.
// A concurrently-created valid identity always wins and is never overwritten.
func (s IdentityStore) LoadOrCreate() (*ecdsa.PrivateKey, error) {
	if !validCertDir(s.CertDir) {
		return nil, ErrIdentity
	}
	path := filepath.Join(s.CertDir, identityKeyName)
	key, err := loadIdentityKey(path)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		if errors.Is(err, ErrIdentityCorrupt) {
			quarantineIdentity(path)
			return nil, ErrIdentityCorrupt
		}
		return nil, ErrIdentity
	}
	if err := os.MkdirAll(s.CertDir, 0o700); err != nil {
		return nil, ErrIdentity
	}
	info, err := os.Lstat(s.CertDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrIdentity
	}

	random := s.Random
	if random == nil {
		random = rand.Reader
	}
	key, err = ecdsa.GenerateKey(elliptic.P256(), random)
	if err != nil {
		return nil, ErrIdentity
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, ErrIdentity
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := publishIdentity(path, encoded); err != nil {
		if errors.Is(err, os.ErrExist) {
			key, loadErr := loadIdentityKey(path)
			if loadErr == nil {
				return key, nil
			}
		}
		return nil, ErrIdentity
	}
	return key, nil
}

// Load returns the existing identity without generating one.
func (s IdentityStore) Load() (*ecdsa.PrivateKey, error) {
	if !validCertDir(s.CertDir) {
		return nil, ErrIdentity
	}
	key, err := loadIdentityKey(filepath.Join(s.CertDir, identityKeyName))
	if err == nil {
		return key, nil
	}
	if errors.Is(err, ErrIdentityCorrupt) {
		quarantineIdentity(filepath.Join(s.CertDir, identityKeyName))
		return nil, ErrIdentityCorrupt
	}
	return nil, ErrIdentity
}

// CreateCSR creates a signed request bound exactly to the pairing candidate.
// The returned key is the persistent key used to sign the request.
func (s IdentityStore) CreateCSR(binding pairing.Binding) ([]byte, *ecdsa.PrivateKey, error) {
	if !validIdentityBinding(binding) {
		return nil, nil, ErrIdentity
	}
	key, err := s.LoadOrCreate()
	if err != nil {
		return nil, nil, err
	}
	random := s.Random
	if random == nil {
		random = rand.Reader
	}
	spiffeURI := &url.URL{Scheme: "spiffe", Host: "lanmodelmanager", Path: "/host/" + binding.CandidateID}
	der, err := x509.CreateCertificateRequest(random, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: binding.CandidateID},
		IPAddresses:        []net.IP{net.ParseIP(binding.Address)},
		URIs:               []*url.URL{spiffeURI},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	if err != nil {
		return nil, nil, ErrIdentity
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil || !csrMatchesBinding(csr, binding) {
		return nil, nil, ErrIdentity
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), key, nil
}

// VerifyIssued verifies the controller-issued leaf against the persistent key,
// pairing binding, pinned CA, requested time, and client-auth purpose. caSource
// may be a *x509.CertPool, CA PEM as []byte/string, or nil when Result.CAPEM is
// populated. Result.CAPEM is always used to identify the pinned CA certificate.
func VerifyIssued(result Result, key *ecdsa.PrivateKey, caSource any, pinnedFingerprint string, now time.Time) error {
	if key == nil || key.Curve != elliptic.P256() || now.IsZero() || !hex64.MatchString(pinnedFingerprint) || result.PinnedCAFingerprintSHA256 != pinnedFingerprint || !validIdentityBinding(result.Binding) {
		return ErrIssuedInvalid
	}
	leaf, err := parseOneCertificate([]byte(result.CertificatePEM))
	if err != nil {
		return ErrIssuedInvalid
	}
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !publicKey.Equal(&key.PublicKey) || leaf.Subject.CommonName != result.Binding.CandidateID || len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != result.Binding.Address || now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) || !hasClientAuth(leaf.ExtKeyUsage) {
		return ErrIssuedInvalid
	}

	caCertificates, err := parseCertificates([]byte(result.CAPEM))
	if err != nil {
		return ErrIssuedInvalid
	}
	var pinnedCA *x509.Certificate
	for _, cert := range caCertificates {
		if FingerprintSHA256(cert.Raw) == pinnedFingerprint {
			pinnedCA = cert
			break
		}
	}
	if pinnedCA == nil || !pinnedCA.IsCA {
		return ErrIssuedInvalid
	}

	roots := x509.NewCertPool()
	roots.AddCert(pinnedCA)
	intermediates := x509.NewCertPool()
	for _, cert := range caCertificates {
		if cert != pinnedCA {
			intermediates.AddCert(cert)
		}
	}
	switch source := caSource.(type) {
	case nil:
	case *x509.CertPool:
		if source == nil {
			return ErrIssuedInvalid
		}
		// Verify once against the caller's trust input as well as the pinned root.
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: source, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			return ErrIssuedInvalid
		}
	case []byte:
		pool, certs, err := poolFromPEM(source)
		if err != nil || !containsFingerprint(certs, pinnedFingerprint) {
			return ErrIssuedInvalid
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			return ErrIssuedInvalid
		}
	case string:
		pool, certs, err := poolFromPEM([]byte(source))
		if err != nil || !containsFingerprint(certs, pinnedFingerprint) {
			return ErrIssuedInvalid
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			return ErrIssuedInvalid
		}
	default:
		return ErrIssuedInvalid
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return ErrIssuedInvalid
	}
	return nil
}

func validCertDir(directory string) bool {
	return directory != "" && strings.TrimSpace(directory) == directory && filepath.IsAbs(directory) && filepath.Clean(directory) == directory
}

func validIdentityBinding(binding pairing.Binding) bool {
	ip := net.ParseIP(binding.Address)
	return idPattern.MatchString(binding.CandidateID) && ip != nil && !strings.Contains(binding.Address, "%") && ip.String() == binding.Address && binding.Port != 0 && binding.ProtocolMajor == 1
}

func csrMatchesBinding(csr *x509.CertificateRequest, binding pairing.Binding) bool {
	publicKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	return ok && publicKey.Curve == elliptic.P256() && csr.Subject.CommonName == binding.CandidateID &&
		len(csr.IPAddresses) == 1 && csr.IPAddresses[0].String() == binding.Address && len(csr.URIs) == 1 &&
		csr.URIs[0].String() == "spiffe://lanmodelmanager/host/"+binding.CandidateID
}

func loadIdentityKey(path string) (*ecdsa.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maxIdentityKey {
		return nil, ErrIdentityCorrupt
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrIdentityCorrupt
	}
	data, err := io.ReadAll(io.LimitReader(file, maxIdentityKey+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil || len(data) == 0 || len(data) > maxIdentityKey {
		return nil, ErrIdentityCorrupt
	}
	if !bytes.HasPrefix(data, []byte("-----BEGIN PRIVATE "+"KEY-----\n")) {
		return nil, ErrIdentityCorrupt
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(rest) != 0 {
		return nil, ErrIdentityCorrupt
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, ErrIdentityCorrupt
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() || !key.PublicKey.Curve.IsOnCurve(key.X, key.Y) {
		return nil, ErrIdentityCorrupt
	}
	return key, nil
}

func publishIdentity(path string, data []byte) error {
	directory := filepath.Dir(path)
	temp, err := os.CreateTemp(directory, ".host-key-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Link(tempName, path); err != nil {
		return err
	}
	if directoryHandle, err := os.Open(directory); err == nil {
		_ = directoryHandle.Sync()
		_ = directoryHandle.Close()
	}
	return nil
}

func quarantineIdentity(path string) {
	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	_ = os.Rename(path, fmt.Sprintf("%s.corrupt-%s", path, stamp))
}

func parseOneCertificate(value []byte) (*x509.Certificate, error) {
	if !bytes.HasPrefix(value, []byte("-----BEGIN CERTIFICATE-----\n")) {
		return nil, ErrIssuedInvalid
	}
	block, rest := pem.Decode(value)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(rest) != 0 {
		return nil, ErrIssuedInvalid
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseCertificates(value []byte) ([]*x509.Certificate, error) {
	if len(value) == 0 || len(value) > maxState {
		return nil, ErrIssuedInvalid
	}
	var certificates []*x509.Certificate
	for len(value) > 0 {
		if !bytes.HasPrefix(value, []byte("-----BEGIN CERTIFICATE-----\n")) {
			return nil, ErrIssuedInvalid
		}
		block, rest := pem.Decode(value)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(rest) >= len(value) {
			return nil, ErrIssuedInvalid
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrIssuedInvalid
		}
		certificates = append(certificates, certificate)
		value = rest
	}
	if len(certificates) == 0 {
		return nil, ErrIssuedInvalid
	}
	return certificates, nil
}

func poolFromPEM(value []byte) (*x509.CertPool, []*x509.Certificate, error) {
	certificates, err := parseCertificates(value)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	for _, certificate := range certificates {
		pool.AddCert(certificate)
	}
	return pool, certificates, nil
}

func containsFingerprint(certificates []*x509.Certificate, fingerprint string) bool {
	for _, certificate := range certificates {
		if FingerprintSHA256(certificate.Raw) == fingerprint {
			return true
		}
	}
	return false
}

func hasClientAuth(usages []x509.ExtKeyUsage) bool {
	for _, usage := range usages {
		if usage == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}
