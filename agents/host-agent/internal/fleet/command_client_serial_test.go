package fleet

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	agenttransport "github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/transport"
)

func TestSignedPollRealCertificateNumericAndLegacyPaddedSerial(t *testing.T) {
	for _, serial := range []string{"01111111111111111111111111111111", "0ABCDEF123456789", "11111111111111111111111111111111", "01"} {
		t.Run(serial, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			number, _ := new(big.Int).SetString(serial, 16)
			template := &x509.Certificate{SerialNumber: number, Subject: pkix.Name{CommonName: "controller"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
			der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			keyDER, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
			digest := sha256.Sum256(der)
			fingerprint := hex.EncodeToString(digest[:])
			request := agenttransport.Envelope{RequestID: "serial-request", Sequence: 1}
			for _, wireSerial := range []string{strings.ToUpper(number.Text(16)), serial} {
				env, err := agenttransport.NewEnvelope("agent-1", request.RequestID, "controller.command.poll", "serial-nonce", fingerprint, wireSerial, 1, time.Now(), map[string]any{"command": nil, "cancelledJobIds": []string{}})
				if err != nil {
					t.Fatal(err)
				}
				// Emulate an older controller that signed the Node byte-padded serial.
				env.CertSerial = wireSerial
				if agenttransport.Sign(&env, keyPEM) != nil {
					t.Fatal("sign")
				}
				response := func(value agenttransport.Envelope) *http.Response {
					raw, _ := json.Marshal(value)
					return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(raw)), TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}}
				}
				got, err := verifyControllerEnvelope(response(env), request, "agent-1", 1)
				if err != nil || got.CertSerial != wireSerial {
					t.Fatalf("original signed serial %s: %v", wireSerial, err)
				}
				if wireSerial != strings.ToUpper(number.Text(16)) {
					changed := env
					changed.CertSerial = strings.ToUpper(number.Text(16))
					if _, err = verifyControllerEnvelope(response(changed), request, "agent-1", 1); err == nil {
						t.Fatal("serial rewritten without resigning accepted")
					}
				}
				changed := env
				changed.CertSerial = "DEADBEEF"
				_ = agenttransport.Sign(&changed, keyPEM)
				if _, err = verifyControllerEnvelope(response(changed), request, "agent-1", 1); err == nil {
					t.Fatal("foreign signed serial accepted")
				}
				changed = env
				changed.CertFingerprint = strings.Repeat("f", 64)
				_ = agenttransport.Sign(&changed, keyPEM)
				if _, err = verifyControllerEnvelope(response(changed), request, "agent-1", 1); err == nil {
					t.Fatal("foreign signed fingerprint accepted")
				}
			}
		})
	}
}
