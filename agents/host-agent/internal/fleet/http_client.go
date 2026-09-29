package fleet

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/enrollment"
	agenttransport "github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/transport"
)

const (
	helloPath       = "/agent/v1/fleet/hello"
	heartbeatPath   = "/agent/v1/fleet/heartbeat"
	maxResponseBody = 16 << 10
	sequenceName    = "fleet-sequence"
)

// ErrHTTPClient is deliberately redacted: network, certificate, URL, and
// controller response details never cross the fleet boundary.
var ErrHTTPClient = errors.New("fleet transport failed")

type Result struct {
	OK     bool    `json:"ok"`
	Result *Ack    `json:"result,omitempty"`
	Error  *string `json:"error,omitempty"`
}
type Ack struct {
	Accepted                      bool   `json:"accepted"`
	Sequence                      uint64 `json:"sequence"`
	NextHeartbeatIntervalMs       int64  `json:"nextHeartbeatIntervalMs"`
	NextHeartbeatIntervalJitterMs int64  `json:"nextHeartbeatIntervalJitterMs"`
	NextHeartbeatWindowMs         int64  `json:"nextHeartbeatWindowMs"`
}
type Hello struct {
	Platform                  string `json:"platform"`
	ProtocolMinor             uint64 `json:"protocolMinor"`
	ObservedAt                string `json:"observedAt"`
	Model                     string `json:"model,omitempty"`
	PreferredIntervalMs       int64  `json:"preferredIntervalMs,omitempty"`
	PreferredIntervalJitterMs int64  `json:"preferredIntervalJitterMs,omitempty"`
	PreferredWindowMs         int64  `json:"preferredWindowMs,omitempty"`
}

type SequenceStore struct{ CertDir string }

func (s SequenceStore) Load() (uint64, error) {
	raw, err := os.ReadFile(filepath.Join(s.CertDir, sequenceName))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil || len(raw) < 2 || len(raw) > 32 || raw[len(raw)-1] != '\n' {
		return 0, ErrHTTPClient
	}
	var value uint64
	if _, err := fmt.Sscanf(string(raw), "%d\n", &value); err != nil {
		return 0, ErrHTTPClient
	}
	return value, nil
}
func (s SequenceStore) Reserve(next uint64) error {
	if next == 0 {
		return ErrHTTPClient
	}
	if err := os.MkdirAll(s.CertDir, 0o700); err != nil {
		return ErrHTTPClient
	}
	tmp, err := os.CreateTemp(s.CertDir, ".fleet-sequence-")
	if err != nil {
		return ErrHTTPClient
	}
	name := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(name)
		}
	}()
	if tmp.Chmod(0o600) != nil {
		return ErrHTTPClient
	}
	if _, err = fmt.Fprintf(tmp, "%d\n", next); err != nil || tmp.Sync() != nil || tmp.Close() != nil {
		return ErrHTTPClient
	}
	if err = os.Rename(name, filepath.Join(s.CertDir, sequenceName)); err != nil {
		return ErrHTTPClient
	}
	committed = true
	if dir, openErr := os.Open(s.CertDir); openErr == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

// HTTPSClient is an outbound-only TLS 1.3 mTLS fleet client. It uses only the
// enrolled CA, never ambient roots, proxy variables, redirects, or credentials.
type HTTPSClient struct {
	mu           sync.Mutex
	http         *http.Client
	artifactHTTP *http.Client
	base         string
	hostID       string
	minor        uint64
	fingerprint  string
	serial       string
	privateKey   []byte
	sequence     uint64
	store        SequenceStore
	now          func() time.Time
	lastObserved time.Time
}

func NewHTTPSClient(certDir string) (*HTTPSClient, error) {
	if !filepath.IsAbs(certDir) || filepath.Clean(certDir) != certDir {
		return nil, ErrHTTPClient
	}
	result, err := (enrollment.FileStore{CertDir: certDir}).Load(context.Background())
	if err != nil {
		return nil, ErrHTTPClient
	}
	key, err := (enrollment.IdentityStore{CertDir: certDir}).Load()
	if err != nil {
		return nil, ErrHTTPClient
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil || !publicCertificatesOnly(result.CAPEM) {
		return nil, ErrHTTPClient
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair([]byte(result.CertificatePEM), keyPEM)
	if err != nil || len(cert.Certificate) == 0 {
		return nil, ErrHTTPClient
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, ErrHTTPClient
	}
	u, err := url.Parse(result.ControllerURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, ErrHTTPClient
	}
	tlsConfig, err := agenttransport.ClientTLSConfig(cert, []byte(result.CAPEM), u.Hostname())
	if err != nil {
		return nil, ErrHTTPClient
	}
	store := SequenceStore{CertDir: certDir}
	sequence, err := store.Load()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(leaf.Raw)
	serial := strings.ToUpper(leaf.SerialNumber.Text(16))
	transport := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, DisableCompression: true, ForceAttemptHTTP2: false, MaxIdleConns: 1, MaxIdleConnsPerHost: 1, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 8 * time.Second}
	noRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: noRedirect}
	artifactClient := &http.Client{Transport: transport, CheckRedirect: noRedirect}
	return &HTTPSClient{http: client, artifactHTTP: artifactClient, base: result.ControllerURL, hostID: result.Binding.CandidateID, minor: uint64(result.Binding.ProtocolMinor), fingerprint: hex.EncodeToString(digest[:]), serial: serial, privateKey: keyPEM, sequence: sequence, store: store, now: time.Now}, nil
}

func (c *HTTPSClient) observedAt() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	value := c.now().UTC().Truncate(time.Millisecond)
	if !value.After(c.lastObserved) {
		value = c.lastObserved.Add(time.Millisecond)
	}
	c.lastObserved = value
	return value.Format("2006-01-02T15:04:05.000Z")
}

func (c *HTTPSClient) next() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sequence == ^uint64(0) {
		return 0, ErrHTTPClient
	}
	n := c.sequence + 1
	if c.store.Reserve(n) != nil {
		return 0, ErrHTTPClient
	}
	c.sequence = n
	return n, nil
}
func randomHex(bytesCount int) (string, error) {
	raw := make([]byte, bytesCount)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func (c *HTTPSClient) post(ctx context.Context, path, messageType string, sequence uint64, payload any) (Ack, error) {
	requestID, err := randomHex(16)
	if err != nil {
		return Ack{}, ErrHTTPClient
	}
	nonce, err := randomHex(16)
	if err != nil {
		return Ack{}, ErrHTTPClient
	}
	env, err := agenttransport.NewEnvelope(c.hostID, requestID, messageType, nonce, c.fingerprint, c.serial, sequence, c.now(), payload)
	if err != nil {
		return Ack{}, ErrHTTPClient
	}
	if err = agenttransport.Sign(&env, c.privateKey); err != nil {
		return Ack{}, ErrHTTPClient
	}
	body, err := json.Marshal(env)
	if err != nil || len(body) > 64<<10 {
		return Ack{}, ErrHTTPClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return Ack{}, ErrHTTPClient
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return Ack{}, ErrHTTPClient
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBody+1))
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]))
	if err != nil || len(raw) > maxResponseBody || response.StatusCode != http.StatusOK || mediaType != "application/json" {
		return Ack{}, ErrHTTPClient
	}
	var result Result
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(&struct{}{}) != io.EOF || !result.OK || result.Error != nil || result.Result == nil || !validTiming(*result.Result) || result.Result.Sequence != sequence {
		return Ack{}, ErrHTTPClient
	}
	return *result.Result, nil
}

func (c *HTTPSClient) SendHello(ctx context.Context, platform, model string, interval, jitter, window time.Duration) (Ack, error) {
	sequence, err := c.next()
	if err != nil {
		return Ack{}, err
	}
	payload := Hello{Platform: platform, ProtocolMinor: c.minor, ObservedAt: c.observedAt(), Model: model, PreferredIntervalMs: interval.Milliseconds(), PreferredIntervalJitterMs: jitter.Milliseconds(), PreferredWindowMs: window.Milliseconds()}
	return c.post(ctx, helloPath, "transport.hello", sequence, payload)
}
func (c *HTTPSClient) Send(ctx context.Context, snapshot Snapshot) (uint64, error) {
	sequence, err := c.next()
	if err != nil {
		return 0, err
	}
	snapshot.Sequence = sequence
	snapshot.ProtocolMinor = c.minor
	snapshot.ObservedAt = c.observedAt()
	ack, err := c.post(ctx, heartbeatPath, "transport.heartbeat", sequence, snapshot)
	if err != nil {
		return 0, err
	}
	return ack.Sequence, nil
}
func (c *HTTPSClient) CloseIdleConnections() {
	c.http.CloseIdleConnections()
	if c.artifactHTTP != nil {
		c.artifactHTTP.CloseIdleConnections()
	}
}

// Avoid accidental acceptance of private-key material as a CA bundle in future edits.
func publicCertificatesOnly(value string) bool {
	for rest := []byte(value); len(rest) > 0; {
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return false
		}
		rest = next
	}
	return value != ""
}
