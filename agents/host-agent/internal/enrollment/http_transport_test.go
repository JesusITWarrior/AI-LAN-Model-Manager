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
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/pairing"
)

type transportFixture struct {
	config      Config
	binding     pairing.Binding
	challengeID string
	nonce       string
	caPEM       string
	caCert      *x509.Certificate
	caKey       *ecdsa.PrivateKey
	leafPEM     string
	leafPin     string
	leafSerial  string
	notBefore   string
	notAfter    string
}

func newTransportFixture(t *testing.T) transportFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "transport test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(0xAA), Subject: pkix.Name{CommonName: "agent-1"}, IPAddresses: []net.IP{net.ParseIP("192.168.1.20")}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	binding := pairing.Binding{CandidateID: "agent-1", Address: "192.168.1.20", Port: 7443, ProtocolMajor: 1}
	return transportFixture{
		config:  Config{PinnedCACertificatePEM: caPEM, PinnedCAFingerprintSHA256: FingerprintSHA256(caDER), CandidateID: binding.CandidateID, Address: binding.Address, Port: binding.Port, ProtocolMajor: 1, CertDir: t.TempDir()},
		binding: binding, challengeID: strings.Repeat("a", 64), nonce: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc", caPEM: caPEM, caCert: caCert, caKey: caKey,
		leafPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})), leafPin: FingerprintSHA256(leafDER), leafSerial: "AA",
		notBefore: leafTemplate.NotBefore.Format("2006-01-02T15:04:05.000Z"), notAfter: leafTemplate.NotAfter.Format("2006-01-02T15:04:05.000Z"),
	}
}

func (f transportFixture) serverCertificate(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "controller"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, f.caCert, &key.PublicKey, f.caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func startTransportServer(t *testing.T, f transportFixture, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{f.serverCertificate(t, "127.0.0.1")}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func (f transportFixture) beginEnvelope() map[string]any {
	return map[string]any{"ok": true, "value": map[string]any{"challengeId": f.challengeID, "controllerNonce": f.nonce, "binding": f.binding, "expiresAt": time.Now().UTC().Add(time.Hour).Format("2006-01-02T15:04:05.000Z"), "operatorCode": "23456789", "caFingerprint": f.config.PinnedCAFingerprintSHA256}}
}

func (f transportFixture) completeEnvelope() map[string]any {
	return map[string]any{"ok": true, "value": map[string]any{"challengeId": f.challengeID, "caFingerprint": f.config.PinnedCAFingerprintSHA256, "caCertificatePem": f.caPEM, "certificateFingerprint": f.leafPin, "certificateSerial": f.leafSerial, "certificatePem": f.leafPEM, "notBefore": f.notBefore, "notAfter": f.notAfter}}
}

func writeJSON(t *testing.T, response http.ResponseWriter, value any) {
	t.Helper()
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(response).Encode(value); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPTransportControllerCompatibilityAndReplaySurface(t *testing.T) {
	f := newTransportFixture(t)
	var requests atomic.Int32
	server := startTransportServer(t, f, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Method != http.MethodPost || request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" || request.Header.Get("X-CSRF-Token") != "" {
			t.Errorf("unsafe request: method=%s headers=%v", request.Method, request.Header)
		}
		var object map[string]json.RawMessage
		if err := json.NewDecoder(request.Body).Decode(&object); err != nil {
			t.Errorf("request JSON: %v", err)
		}
		switch request.URL.Path {
		case "/agent/v1/enrollment/begin":
			if len(object) != 2 || object["binding"] == nil || object["caFingerprint"] == nil {
				t.Errorf("begin keys: %v", object)
			}
			writeJSON(t, response, f.beginEnvelope())
		case "/agent/v1/enrollment/complete":
			for _, forbidden := range []string{"operatorCode", "authorization", "cookie", "managementToken", "inferenceToken"} {
				if _, exists := object[forbidden]; exists {
					t.Errorf("forbidden complete field %q", forbidden)
				}
			}
			if len(object) != 7 {
				t.Errorf("complete keys: %v", object)
			}
			writeJSON(t, response, f.completeEnvelope())
		default:
			http.NotFound(response, request)
		}
	}))
	f.config.ControllerURL = server.URL
	transport, err := NewHTTPTransport(f.config)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := transport.Begin(context.Background(), f.binding)
	if err != nil || challenge.OperatorCode != "23456789" || challenge.Pairing.ChallengeID != f.challengeID {
		t.Fatalf("challenge=%+v err=%v", challenge, err)
	}
	challenge.OperatorCode = ""
	proof := pairing.Proof{ChallengeID: f.challengeID, ControllerNonce: f.nonce, AgentNonce: strings.Repeat("A", 43), Proof: strings.Repeat("b", 64), Binding: f.binding}
	result, err := transport.Complete(context.Background(), challenge, proof, []byte("-----BEGIN CERTIFICATE REQUEST-----\nrequest\n-----END CERTIFICATE REQUEST-----\n"))
	if err != nil || result.ChallengeID != f.challengeID || result.Binding != f.binding || result.CertificatePEM != f.leafPEM || result.CAPEM != f.caPEM || result.EnrolledAt.IsZero() {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if requests.Load() != 2 {
		t.Fatalf("requests=%d", requests.Load())
	}
}

func TestHTTPTransportRejectsTrustHostRedirectAndStatus(t *testing.T) {
	f := newTransportFixture(t)
	server := startTransportServer(t, f, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/agent/v1/enrollment/begin" {
			http.Redirect(response, request, "/elsewhere", http.StatusFound)
			return
		}
		http.Error(response, "secret remote detail", http.StatusInternalServerError)
	}))
	f.config.ControllerURL = server.URL
	wrongPin := f.config
	wrongPin.PinnedCAFingerprintSHA256 = strings.Repeat("0", 64)
	if _, err := NewHTTPTransport(wrongPin); !errors.Is(err, ErrInvalidConfig) || strings.Contains(err.Error(), f.caPEM) {
		t.Fatalf("wrong pin: %v", err)
	}
	wrongCA := newTransportFixture(t)
	wrongCA.config.ControllerURL = server.URL
	transport, err := NewHTTPTransport(wrongCA.config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = transport.Begin(context.Background(), wrongCA.binding); !errors.Is(err, ErrFailed) || err.Error() != ErrFailed.Error() {
		t.Fatalf("wrong CA: %v", err)
	}
	transport, err = NewHTTPTransport(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = transport.Begin(context.Background(), f.binding); !errors.Is(err, ErrFailed) || err.Error() != ErrFailed.Error() {
		t.Fatalf("redirect: %v", err)
	}
	parsed, _ := url.Parse(server.URL)
	f.config.ControllerURL = "https://localhost:" + parsed.Port()
	transport, err = NewHTTPTransport(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = transport.Begin(context.Background(), f.binding); !errors.Is(err, ErrFailed) || err.Error() != ErrFailed.Error() {
		t.Fatalf("wrong host: %v", err)
	}

	statusServer := startTransportServer(t, f, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(response, `{"ok":false,"error":{"code":"SECRET_DETAIL","message":"do not expose"}}`)
	}))
	f.config.ControllerURL = statusServer.URL
	transport, err = NewHTTPTransport(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = transport.Begin(context.Background(), f.binding); !errors.Is(err, ErrFailed) || err.Error() != ErrFailed.Error() || strings.Contains(err.Error(), "SECRET_DETAIL") {
		t.Fatalf("status: %v", err)
	}
}

func TestHTTPTransportRejectsOversizedDuplicateUnknownAndMissingJSON(t *testing.T) {
	for name, body := range map[string]string{
		"oversized": strings.Repeat("x", EnrollmentResponseLimit+1),
		"duplicate": `{"ok":true,"ok":true,"value":{}}`,
		"unknown":   `{"ok":true,"value":{},"extra":false}`,
		"missing":   `{"ok":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newTransportFixture(t)
			server := startTransportServer(t, f, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(response, body)
			}))
			f.config.ControllerURL = server.URL
			transport, err := NewHTTPTransport(f.config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = transport.Begin(context.Background(), f.binding); !errors.Is(err, ErrFailed) || err.Error() != ErrFailed.Error() {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestHTTPTransportPropagatesCancellation(t *testing.T) {
	f := newTransportFixture(t)
	started := make(chan struct{})
	server := startTransportServer(t, f, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(started)
		<-time.After(time.Second)
	}))
	f.config.ControllerURL = server.URL
	transport, err := NewHTTPTransport(f.config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-started; cancel() }()
	if _, err = transport.Begin(ctx, f.binding); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation=%v", err)
	}
}

type closingBody struct {
	io.Reader
	closed atomic.Bool
}

func (body *closingBody) Close() error {
	body.closed.Store(true)
	return nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestHTTPTransportClosesEveryResponseBody(t *testing.T) {
	f := newTransportFixture(t)
	for _, status := range []int{http.StatusOK, http.StatusBadRequest} {
		body := &closingBody{Reader: strings.NewReader(`{"ok":true,"value":{}}`)}
		transport := &HTTPTransport{controllerURL: "https://controller.example", fingerprint: f.config.PinnedCAFingerprintSHA256, caPEM: f.caPEM, now: time.Now}
		transport.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: body}, nil
		})}
		_, _ = transport.Begin(context.Background(), f.binding)
		if !body.closed.Load() {
			t.Fatalf("status %d body not closed", status)
		}
	}
}
