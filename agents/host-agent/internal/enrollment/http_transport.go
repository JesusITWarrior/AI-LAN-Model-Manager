package enrollment

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/pairing"
)

const (
	EnrollmentResponseLimit  = 24 * 1024
	EnrollmentConnectTimeout = 5 * time.Second
	EnrollmentHeaderTimeout  = 5 * time.Second
	EnrollmentRequestTimeout = 15 * time.Second
)

var (
	serialPattern         = regexp.MustCompile(`^[A-F0-9]{2,40}$`)
	controllerTimePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)
)

// HTTPTransport is the production, enrollment-only HTTPS boundary. It has no
// cookie jar and never follows redirects or uses ambient system trust roots.
type HTTPTransport struct {
	controllerURL string
	fingerprint   string
	caPEM         string
	client        *http.Client
	now           func() time.Time
}

// NewHTTPTransport constructs a client rooted exclusively in the configured
// CA. Configuration errors are reported without echoing any configured value.
func NewHTTPTransport(cfg Config) (*HTTPTransport, error) {
	if _, err := cfg.binding(); err != nil {
		return nil, ErrInvalidConfig
	}
	ca, err := pinnedCACertificate(cfg.PinnedCACertificatePEM, cfg.PinnedCAFingerprintSHA256)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	u, err := url.Parse(cfg.ControllerURL)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	pin := cfg.PinnedCAFingerprintSHA256
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: u.Hostname(),
		VerifyConnection: func(state tls.ConnectionState) error {
			for _, chain := range state.VerifiedChains {
				if len(chain) > 0 && FingerprintSHA256(chain[len(chain)-1].Raw) == pin {
					return nil
				}
			}
			return ErrFailed
		},
	}
	dialer := &net.Dialer{Timeout: EnrollmentConnectTimeout, KeepAlive: 30 * time.Second}
	roundTripper := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   EnrollmentConnectTimeout,
		ResponseHeaderTimeout: EnrollmentHeaderTimeout,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       30 * time.Second,
		DisableCompression:    true,
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   2,
		MaxConnsPerHost:       2,
	}
	client := &http.Client{
		Transport: roundTripper,
		Timeout:   EnrollmentRequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &HTTPTransport{controllerURL: cfg.ControllerURL, fingerprint: pin, caPEM: cfg.PinnedCACertificatePEM, client: client, now: time.Now}, nil
}

func (t *HTTPTransport) Begin(ctx context.Context, binding pairing.Binding) (Challenge, error) {
	request := beginRequest{Binding: binding, CAFingerprint: t.fingerprint}
	var envelope beginEnvelope
	if err := t.post(ctx, "/agent/v1/enrollment/begin", request, &envelope); err != nil {
		return Challenge{}, err
	}
	value := envelope.Value
	expiresAt, err := parseControllerTime(value.ExpiresAt)
	if err != nil || !envelope.OK || value.CAFingerprint != t.fingerprint || value.Binding != binding || !hex64.MatchString(value.ChallengeID) || !validNonce(value.ControllerNonce) || !codeRE.MatchString(value.OperatorCode) {
		return Challenge{}, remoteError(ctx)
	}
	return Challenge{
		Pairing:       pairing.Challenge{ChallengeID: value.ChallengeID, ControllerNonce: value.ControllerNonce, Binding: value.Binding, ExpiresAt: expiresAt},
		ControllerURL: t.controllerURL, PinnedCAFingerprintSHA256: t.fingerprint, OperatorCode: value.OperatorCode,
	}, nil
}

func (t *HTTPTransport) Complete(ctx context.Context, challenge Challenge, proof pairing.Proof, csrPEM []byte) (Result, error) {
	if challenge.ControllerURL != t.controllerURL || challenge.PinnedCAFingerprintSHA256 != t.fingerprint || challenge.Pairing.ChallengeID != proof.ChallengeID || challenge.Pairing.ControllerNonce != proof.ControllerNonce || challenge.Pairing.Binding != proof.Binding || len(csrPEM) == 0 || len(csrPEM) > 16*1024 {
		return Result{}, remoteError(ctx)
	}
	request := completeRequest{
		ChallengeID: proof.ChallengeID, ControllerNonce: proof.ControllerNonce, AgentNonce: proof.AgentNonce,
		Proof: proof.Proof, Binding: proof.Binding, CAFingerprint: t.fingerprint, CSRPEM: string(csrPEM),
	}
	var envelope completeEnvelope
	if err := t.post(ctx, "/agent/v1/enrollment/complete", request, &envelope); err != nil {
		return Result{}, err
	}
	value := envelope.Value
	if !envelope.OK || value.ChallengeID != proof.ChallengeID || value.CAFingerprint != t.fingerprint || value.CACertificatePEM != t.caPEM || !hex64.MatchString(value.CertificateFingerprint) || !serialPattern.MatchString(value.CertificateSerial) {
		return Result{}, remoteError(ctx)
	}
	notBefore, errBefore := parseControllerTime(value.NotBefore)
	notAfter, errAfter := parseControllerTime(value.NotAfter)
	leaf, errLeaf := singleCertificate(value.CertificatePEM)
	serial := new(big.Int)
	_, serialOK := serial.SetString(value.CertificateSerial, 16)
	if errBefore != nil || errAfter != nil || !notAfter.After(notBefore) || errLeaf != nil || !serialOK || FingerprintSHA256(leaf.Raw) != value.CertificateFingerprint || leaf.SerialNumber.Cmp(serial) != 0 {
		return Result{}, remoteError(ctx)
	}
	return Result{
		ControllerURL: t.controllerURL, PinnedCAFingerprintSHA256: t.fingerprint,
		ChallengeID: proof.ChallengeID, Binding: proof.Binding,
		CertificatePEM: value.CertificatePEM, CAPEM: value.CACertificatePEM, EnrolledAt: t.now().UTC(),
	}, nil
}

func (t *HTTPTransport) post(ctx context.Context, path string, input, output any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	body, err := json.Marshal(input)
	if err != nil {
		return remoteError(ctx)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, t.controllerURL+path, bytes.NewReader(body))
	if err != nil {
		return remoteError(ctx)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := t.client.Do(request)
	if err != nil {
		return remoteError(ctx)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return remoteError(ctx)
	}
	if mediaType := strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0])); mediaType != "application/json" {
		return remoteError(ctx)
	}
	if response.ContentLength > EnrollmentResponseLimit {
		return remoteError(ctx)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, EnrollmentResponseLimit+1))
	if err != nil || len(raw) == 0 || len(raw) > EnrollmentResponseLimit || decodeExactJSON(raw, output) != nil {
		return remoteError(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func remoteError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrFailed
}

func pinnedCACertificate(value, fingerprint string) (*x509.Certificate, error) {
	cert, err := singleCertificate(value)
	if err != nil || !cert.IsCA || FingerprintSHA256(cert.Raw) != fingerprint {
		return nil, ErrInvalidConfig
	}
	return cert, nil
}

func singleCertificate(value string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(rest) != 0 {
		return nil, errors.New("invalid certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseControllerTime(value string) (time.Time, error) {
	if !controllerTimePattern.MatchString(value) {
		return time.Time{}, errors.New("invalid time")
	}
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z", value)
	if err != nil || parsed.Format("2006-01-02T15:04:05.000Z") != value {
		return time.Time{}, errors.New("invalid time")
	}
	return parsed, nil
}

func validNonce(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func decodeExactJSON(raw []byte, destination any) error {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	var shape any
	if err := json.Unmarshal(raw, &shape); err != nil {
		return err
	}
	destinationType := reflect.TypeOf(destination)
	if destinationType == nil || destinationType.Kind() != reflect.Pointer || destinationType.Elem().Kind() != reflect.Struct || !exactJSONShape(shape, destinationType.Elem()) {
		return errors.New("invalid json shape")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing json")
	}
	return nil
}

func exactJSONShape(value any, expected reflect.Type) bool {
	for expected.Kind() == reflect.Pointer {
		expected = expected.Elem()
	}
	switch expected.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		fields := make(map[string]reflect.Type)
		for index := 0; index < expected.NumField(); index++ {
			field := expected.Field(index)
			if field.PkgPath != "" {
				continue
			}
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			fields[name] = field.Type
		}
		if len(object) != len(fields) {
			return false
		}
		for name, fieldType := range fields {
			child, exists := object[name]
			if !exists || !exactJSONShape(child, fieldType) {
				return false
			}
		}
		return true
	case reflect.Slice, reflect.Array:
		array, ok := value.([]any)
		if !ok {
			return false
		}
		for _, child := range array {
			if !exactJSONShape(child, expected.Elem()) {
				return false
			}
		}
		return true
	default:
		return value != nil
	}
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var value func() error
	value = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			keys := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				key, ok := keyToken.(string)
				if err != nil || !ok {
					return errors.New("invalid object key")
				}
				if _, exists := keys[key]; exists {
					return errors.New("duplicate object key")
				}
				keys[key] = struct{}{}
				if err := value(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return errors.New("invalid object")
			}
		case '[':
			for decoder.More() {
				if err := value(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return errors.New("invalid array")
			}
		default:
			return errors.New("invalid delimiter")
		}
		return nil
	}
	if err := value(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing json")
	}
	return nil
}

type beginRequest struct {
	Binding       pairing.Binding `json:"binding"`
	CAFingerprint string          `json:"caFingerprint"`
}

type beginEnvelope struct {
	OK    bool       `json:"ok"`
	Value beginValue `json:"value"`
}

type beginValue struct {
	ChallengeID     string          `json:"challengeId"`
	ControllerNonce string          `json:"controllerNonce"`
	Binding         pairing.Binding `json:"binding"`
	ExpiresAt       string          `json:"expiresAt"`
	OperatorCode    string          `json:"operatorCode"`
	CAFingerprint   string          `json:"caFingerprint"`
}

type completeRequest struct {
	ChallengeID     string          `json:"challengeId"`
	ControllerNonce string          `json:"controllerNonce"`
	AgentNonce      string          `json:"agentNonce"`
	Proof           string          `json:"proof"`
	Binding         pairing.Binding `json:"binding"`
	CAFingerprint   string          `json:"caFingerprint"`
	CSRPEM          string          `json:"csrPem"`
}

type completeEnvelope struct {
	OK    bool          `json:"ok"`
	Value completeValue `json:"value"`
}

type completeValue struct {
	ChallengeID            string `json:"challengeId"`
	CAFingerprint          string `json:"caFingerprint"`
	CACertificatePEM       string `json:"caCertificatePem"`
	CertificateFingerprint string `json:"certificateFingerprint"`
	CertificateSerial      string `json:"certificateSerial"`
	CertificatePEM         string `json:"certificatePem"`
	NotBefore              string `json:"notBefore"`
	NotAfter               string `json:"notAfter"`
}

var _ Transport = (*HTTPTransport)(nil)
