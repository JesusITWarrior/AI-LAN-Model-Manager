package pairing

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrInvalidChallenge = errors.New("invalid pairing challenge")
var ErrPairingConsumed = errors.New("pairing challenge unavailable")
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var hex64 = regexp.MustCompile(`^[a-f0-9]{64}$`)
var humanCode = regexp.MustCompile(`^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{8}$`)

type Binding struct {
	CandidateID   string `json:"candidateId"`
	Address       string `json:"address"`
	Port          uint16 `json:"port"`
	ProtocolMajor uint16 `json:"protocolMajor"`
	ProtocolMinor uint16 `json:"protocolMinor"`
}
type Challenge struct {
	ChallengeID     string
	ControllerNonce string
	Binding         Binding
	ExpiresAt       time.Time
}
type Proof struct {
	ChallengeID     string
	ControllerNonce string
	AgentNonce      string
	Proof           string
	Binding         Binding
}
type Presenter func(code string) error

type Session struct {
	mu        sync.Mutex
	challenge Challenge
	code      []byte
	presenter Presenter
	consumed  bool
	random    func([]byte) (int, error)
}

func validBinding(b Binding) bool {
	ip := net.ParseIP(b.Address)
	return idPattern.MatchString(b.CandidateID) && ip != nil && !strings.Contains(b.Address, "%") && ip.String() == b.Address && b.Port > 0 && b.ProtocolMajor == 1
}
func NewSession(challenge Challenge, code []byte, presenter Presenter) (*Session, error) {
	return NewSessionWithRandom(challenge, code, presenter, rand.Read)
}
func NewSessionWithRandom(challenge Challenge, code []byte, presenter Presenter, random func([]byte) (int, error)) (*Session, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(challenge.ControllerNonce)
	if err != nil || len(decoded) != 32 || !hex64.MatchString(challenge.ChallengeID) || !validBinding(challenge.Binding) || challenge.ExpiresAt.IsZero() || !humanCode.Match(code) || presenter == nil || random == nil {
		return nil, ErrInvalidChallenge
	}
	copyCode := append([]byte(nil), code...)
	return &Session{challenge: challenge, code: copyCode, presenter: presenter, random: random}, nil
}
func (s *Session) Present(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.consumed || !now.Before(s.challenge.ExpiresAt) {
		return ErrPairingConsumed
	}
	return s.presenter(string(s.code))
}
func (s *Session) BuildProof(now time.Time) (Proof, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.consumed || !now.Before(s.challenge.ExpiresAt) {
		return Proof{}, ErrPairingConsumed
	}
	nonce := make([]byte, 32)
	n, err := s.random(nonce)
	if err != nil || n != len(nonce) {
		zero(nonce)
		return Proof{}, errors.New("pairing randomness failed")
	}
	agentNonce := base64.RawURLEncoding.EncodeToString(nonce)
	controllerDigest := sha256.Sum256([]byte(s.challenge.ControllerNonce))
	agentDigest := sha256.Sum256([]byte(agentNonce))
	transcript := strings.Join([]string{"lanmm-pairing-v1", s.challenge.ChallengeID, hex.EncodeToString(controllerDigest[:]), hex.EncodeToString(agentDigest[:]), s.challenge.Binding.CandidateID, s.challenge.Binding.Address, strconv.Itoa(int(s.challenge.Binding.Port)), strconv.Itoa(int(s.challenge.Binding.ProtocolMajor)), strconv.Itoa(int(s.challenge.Binding.ProtocolMinor))}, "\x1f")
	codeDigest := sha256.Sum256(s.code)
	mac := hmac.New(sha256.New, codeDigest[:])
	_, _ = mac.Write([]byte(transcript))
	result := Proof{ChallengeID: s.challenge.ChallengeID, ControllerNonce: s.challenge.ControllerNonce, AgentNonce: agentNonce, Proof: hex.EncodeToString(mac.Sum(nil)), Binding: s.challenge.Binding}
	zero(s.code)
	zero(nonce)
	s.consumed = true
	return result, nil
}
func (s *Session) CodeZeroed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.code {
		if b != 0 {
			return false
		}
	}
	return true
}
func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
