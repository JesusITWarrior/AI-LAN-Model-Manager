package pairing

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	Code            string  `json:"code"`
	ChallengeID     string  `json:"challengeId"`
	ControllerNonce string  `json:"controllerNonce"`
	AgentNonce      string  `json:"agentNonce"`
	Binding         Binding `json:"binding"`
	Proof           string  `json:"proof"`
}

func load(t *testing.T) fixture {
	raw, err := os.ReadFile("testdata/proof.json")
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}
func challenge(f fixture) Challenge {
	return Challenge{ChallengeID: f.ChallengeID, ControllerNonce: f.ControllerNonce, Binding: f.Binding, ExpiresAt: time.Date(2026, 9, 27, 20, 10, 0, 0, time.UTC)}
}
func TestProofMatchesFixtureAndZeroesSecrets(t *testing.T) {
	f := load(t)
	presented := ""
	session, err := NewSessionWithRandom(challenge(f), []byte(f.Code), func(code string) error { presented = code; return nil }, func(out []byte) (int, error) {
		for i := range out {
			out[i] = 9
		}
		return len(out), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 27, 20, 0, 0, 0, time.UTC)
	if err = session.Present(now); err != nil || presented != f.Code {
		t.Fatalf("present: %v %q", err, presented)
	}
	proof, err := session.BuildProof(now)
	if err != nil {
		t.Fatal(err)
	}
	if proof.Proof != f.Proof || proof.AgentNonce != f.AgentNonce {
		t.Fatalf("fixture mismatch %#v", proof)
	}
	if !session.CodeZeroed() {
		t.Fatal("code not zeroed")
	}
	if _, err = session.BuildProof(now); !errors.Is(err, ErrPairingConsumed) {
		t.Fatalf("replay: %v", err)
	}
}
func TestExpiryMismatchAndRedactedErrors(t *testing.T) {
	f := load(t)
	expired := challenge(f)
	expired.ExpiresAt = time.Date(2026, 9, 27, 20, 0, 0, 0, time.UTC)
	session, err := NewSession(expired, []byte(f.Code), func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err = session.BuildProof(expired.ExpiresAt); !errors.Is(err, ErrPairingConsumed) {
		t.Fatalf("expiry: %v", err)
	}
	bad := challenge(f)
	bad.Binding.Address = "host.local"
	if _, err = NewSession(bad, []byte(f.Code), func(string) error { return nil }); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("invalid: %v", err)
	}
	if strings.Contains(err.Error(), f.Code) || strings.Contains(err.Error(), f.ControllerNonce) {
		t.Fatal("secret leaked")
	}
}
