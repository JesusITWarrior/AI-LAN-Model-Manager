package transport

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrTransport = errors.New("transport envelope invalid")

type ProtocolVersion struct {
	Major uint64 `json:"major"`
	Minor uint64 `json:"minor"`
}
type Envelope struct {
	ProtocolVersion ProtocolVersion `json:"protocolVersion"`
	MessageType     string          `json:"messageType"`
	HostID          string          `json:"hostId"`
	RequestID       string          `json:"requestId"`
	Sequence        uint64          `json:"sequence"`
	SentAt          string          `json:"sentAt"`
	Nonce           string          `json:"nonce"`
	BodyDigest      string          `json:"bodyDigest"`
	CertFingerprint string          `json:"certFingerprint"`
	CertSerial      string          `json:"certSerial"`
	Signature       string          `json:"signature"`
	Payload         json.RawMessage `json:"payload"`
}

func SignedFields(e Envelope) string {
	return strings.Join([]string{"lanmm-transport-signed-v1", "ecdsa-p256-sha256", e.HostID, e.RequestID, strconv.FormatUint(e.Sequence, 10), e.SentAt, e.Nonce, e.CertFingerprint, e.CertSerial, e.BodyDigest}, "\x1f")
}
func bodyDigest(body []byte) string { h := sha256.Sum256(body); return hex.EncodeToString(h[:]) }
func Sign(e *Envelope, privateKeyPEM []byte) error {
	if e == nil || e.Sequence == 0 || e.ProtocolVersion.Major != 1 || len(e.Payload) == 0 {
		return ErrTransport
	}
	var compact bytes.Buffer
	if json.Compact(&compact, e.Payload) != nil {
		return ErrTransport
	}
	e.Payload = compact.Bytes()
	e.BodyDigest = bodyDigest(e.Payload)
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return ErrTransport
	}
	raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return ErrTransport
	}
	key, ok := raw.(*ecdsa.PrivateKey)
	if !ok {
		return ErrTransport
	}
	hash := sha256.Sum256([]byte(SignedFields(*e)))
	sig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		return ErrTransport
	}
	e.Signature = hex.EncodeToString(sig)
	return nil
}
func Verify(e Envelope, publicKey *ecdsa.PublicKey) error {
	if publicKey == nil || e.Sequence == 0 || e.ProtocolVersion.Major != 1 {
		return ErrTransport
	}
	if bodyDigest(e.Payload) != e.BodyDigest {
		return ErrTransport
	}
	sig, err := hex.DecodeString(e.Signature)
	if err != nil {
		return ErrTransport
	}
	hash := sha256.Sum256([]byte(SignedFields(e)))
	if !ecdsa.VerifyASN1(publicKey, hash[:], sig) {
		return ErrTransport
	}
	return nil
}

type Sequencer struct {
	mu   sync.Mutex
	next uint64
}

func NewSequencer(start uint64) *Sequencer { return &Sequencer{next: start} }
func (s *Sequencer) Next() uint64          { s.mu.Lock(); defer s.mu.Unlock(); s.next++; return s.next }
func NewEnvelope(hostID, requestID, messageType, nonce, fingerprint, serial string, sequence uint64, now time.Time, payload any) (Envelope, error) {
	body, err := json.Marshal(payload)
	if err != nil || len(body) > 32768 {
		return Envelope{}, ErrTransport
	}
	return Envelope{ProtocolVersion: ProtocolVersion{Major: 1}, MessageType: messageType, HostID: hostID, RequestID: requestID, Sequence: sequence, SentAt: now.UTC().Format("2006-01-02T15:04:05.000Z"), Nonce: nonce, CertFingerprint: fingerprint, CertSerial: serial, Payload: body}, nil
}
