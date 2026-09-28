package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func tlsFixture(t *testing.T) (tls.Certificate, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDer, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pair, err := tls.X509KeyPair(certPem, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDer}))
	if err != nil {
		t.Fatal(err)
	}
	return pair, certPem
}
func TestTLSConfigsRequireTLS13AndMutualAuthentication(t *testing.T) {
	pair, ca := tlsFixture(t)
	client, err := ClientTLSConfig(pair, ca, "controller.local")
	if err != nil {
		t.Fatal(err)
	}
	server, err := ServerTLSConfig(pair, ca)
	if err != nil {
		t.Fatal(err)
	}
	if client.MinVersion != tls.VersionTLS13 || server.MinVersion != tls.VersionTLS13 || server.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("weak tls configuration")
	}
	if _, err = ClientTLSConfig(tls.Certificate{}, ca, "controller.local"); err == nil {
		t.Fatal("accepted missing certificate")
	}
}
