package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
)

var ErrIdentity = errors.New("certificate identity failed")
var hostID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Binding struct {
	CandidateID   string
	Address       string
	Port          uint16
	ProtocolMajor uint16
	ProtocolMinor uint16
}
type Request struct {
	PrivateKeyPEM []byte
	CSRPEM        []byte
}

func validate(b Binding) bool {
	ip := net.ParseIP(b.Address)
	return hostID.MatchString(b.CandidateID) && ip != nil && ip.String() == b.Address && b.Port > 0 && b.ProtocolMajor == 1
}
func GenerateRequest(b Binding) (Request, error) {
	if !validate(b) {
		return Request{}, ErrIdentity
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Request{}, ErrIdentity
	}
	uri, _ := url.Parse("spiffe://lanmodelmanager/host/" + b.CandidateID)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: b.CandidateID}, IPAddresses: []net.IP{net.ParseIP(b.Address)}, URIs: []*url.URL{uri}, SignatureAlgorithm: x509.ECDSAWithSHA256}, key)
	if err != nil {
		return Request{}, ErrIdentity
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Request{}, ErrIdentity
	}
	return Request{PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), CSRPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})}, nil
}
func VerifyRequest(csrPEM []byte, b Binding) error {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || !validate(b) {
		return ErrIdentity
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil || csr.SignatureAlgorithm != x509.ECDSAWithSHA256 || csr.Subject.CommonName != b.CandidateID || len(csr.IPAddresses) != 1 || csr.IPAddresses[0].String() != b.Address || len(csr.URIs) != 1 || csr.URIs[0].String() != "spiffe://lanmodelmanager/host/"+b.CandidateID {
		return ErrIdentity
	}
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return ErrIdentity
	}
	return nil
}
func StoreIdentity(directory string, keyPEM, certPEM, caPEM []byte) error {
	if directory == "" {
		return ErrIdentity
	}
	if info, err := os.Lstat(directory); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
			return ErrIdentity
		}
	} else if !os.IsNotExist(err) {
		return ErrIdentity
	} else if os.MkdirAll(directory, 0700) != nil {
		return ErrIdentity
	}
	for _, name := range []string{"host-key.pem", "host-cert.pem", "ca-cert.pem"} {
		if _, err := os.Lstat(filepath.Join(directory, name)); err == nil {
			return ErrIdentity
		} else if !os.IsNotExist(err) {
			return ErrIdentity
		}
	}
	for name, value := range map[string][]byte{"host-key.pem": keyPEM, "host-cert.pem": certPEM, "ca-cert.pem": caPEM} {
		temp, err := os.CreateTemp(directory, ".identity-")
		if err != nil {
			return ErrIdentity
		}
		tmp := temp.Name()
		if temp.Chmod(0600) != nil || func() error { _, e := temp.Write(value); return e }() != nil || temp.Sync() != nil || temp.Close() != nil || os.Rename(tmp, filepath.Join(directory, name)) != nil {
			temp.Close()
			os.Remove(tmp)
			return ErrIdentity
		}
	}
	return nil
}
func LoadIdentity(directory string) (key, cert, ca []byte, err error) {
	info, e := os.Lstat(directory)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return nil, nil, nil, ErrIdentity
	}
	values := make([][]byte, 3)
	for i, name := range []string{"host-key.pem", "host-cert.pem", "ca-cert.pem"} {
		path := filepath.Join(directory, name)
		s, e := os.Lstat(path)
		if e != nil || !s.Mode().IsRegular() || s.Mode()&os.ModeSymlink != 0 || s.Mode().Perm() != 0600 || s.Size() > 65536 {
			return nil, nil, nil, ErrIdentity
		}
		values[i], e = os.ReadFile(path)
		if e != nil {
			return nil, nil, nil, ErrIdentity
		}
	}
	return values[0], values[1], values[2], nil
}
