package enrollment

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/pairing"
)

const pin = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

type fakeTransport struct {
	challenge Challenge
	result    Result
	beginErr  error
	endErr    error
	begins    int
	completes int
	got       Challenge
}

func (f *fakeTransport) Begin(ctx context.Context, b pairing.Binding) (Challenge, error) {
	f.begins++
	return f.challenge, f.beginErr
}
func (f *fakeTransport) Complete(ctx context.Context, ch Challenge, p pairing.Proof) (Result, error) {
	f.completes++
	f.got = ch
	return f.result, f.endErr
}

func fixture(t *testing.T) (Config, Challenge, Result) {
	t.Helper()
	cfg := Config{ControllerURL: "https://controller.example:7443", PinnedCAFingerprintSHA256: pin, CandidateID: "agent-1", Address: "192.168.1.20", Port: 7443, ProtocolMajor: 1, CertDir: t.TempDir()}
	binding, err := cfg.binding()
	if err != nil {
		t.Fatal(err)
	}
	ch := Challenge{ControllerURL: cfg.ControllerURL, PinnedCAFingerprintSHA256: pin, OperatorCode: "23456789", Pairing: pairing.Challenge{ChallengeID: strings.Repeat("a", 64), ControllerNonce: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc", Binding: binding, ExpiresAt: time.Now().Add(time.Hour)}}
	result := Result{ControllerURL: cfg.ControllerURL, PinnedCAFingerprintSHA256: pin, ChallengeID: ch.Pairing.ChallengeID, Binding: binding, EnrolledAt: time.Now().UTC()}
	return cfg, ch, result
}

func TestStrictConfigAndUnconfigured(t *testing.T) {
	cfg, _, _ := fixture(t)
	bad := []Config{{}, cfg, cfg, cfg, cfg}
	bad[1].ControllerURL = "http://controller.example"
	bad[2].ControllerURL = "https://CONTROLLER.example"
	bad[3].PinnedCAFingerprintSHA256 = strings.ToUpper(pin)
	bad[4].Address = "192.168.001.020"
	for i, candidate := range bad {
		if _, err := New(candidate, &fakeTransport{}, nil); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("case %d: %v", i, err)
		}
	}
}

func TestHappyPathReturnsCodeOnceAndRestartAvoidsNetwork(t *testing.T) {
	cfg, ch, result := fixture(t)
	transport := &fakeTransport{challenge: ch, result: result}
	client, err := New(cfg, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := client.Enroll(context.Background())
	if err != nil || out.Status != StatusEnrolled || out.OperatorCode != ch.OperatorCode {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	if transport.got.OperatorCode != "" {
		t.Fatal("operator code sent to Complete")
	}
	out, err = client.Enroll(context.Background())
	if err != nil || out.OperatorCode != "" || transport.begins != 1 || transport.completes != 1 {
		t.Fatalf("replay out=%+v err=%v calls=%d/%d", out, err, transport.begins, transport.completes)
	}
	restarted, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err = restarted.Enroll(context.Background())
	if err != nil || out.Status != StatusEnrolled {
		t.Fatalf("restart out=%+v err=%v", out, err)
	}
}

func TestWrongBindingControllerExpiryReplayAndCancellation(t *testing.T) {
	for _, mutate := range []func(*Challenge){
		func(ch *Challenge) { ch.ControllerURL = "https://other.example" },
		func(ch *Challenge) { ch.Pairing.Binding.Port++ },
		func(ch *Challenge) { ch.Pairing.ExpiresAt = time.Now().Add(-time.Second) },
	} {
		cfg, ch, result := fixture(t)
		mutate(&ch)
		transport := &fakeTransport{challenge: ch, result: result}
		client, err := New(cfg, transport, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = client.Enroll(context.Background()); !errors.Is(err, ErrFailed) {
			t.Fatalf("first: %v", err)
		}
		if _, err = client.Enroll(context.Background()); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("replay: %v", err)
		}
		if transport.completes != 0 {
			t.Fatal("invalid challenge completed")
		}
	}
	cfg, ch, result := fixture(t)
	transport := &fakeTransport{challenge: ch, result: result}
	client, err := New(cfg, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = client.Enroll(ctx); !errors.Is(err, ErrUnavailable) || transport.begins != 0 {
		t.Fatalf("cancel: %v calls=%d", err, transport.begins)
	}
}

func TestErrorsAreRedacted(t *testing.T) {
	cfg, ch, result := fixture(t)
	secret := "23456789-controller-secret"
	client, err := New(cfg, &fakeTransport{challenge: ch, result: result, beginErr: errors.New(secret)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Enroll(context.Background())
	if !errors.Is(err, ErrFailed) || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), ch.OperatorCode) {
		t.Fatalf("leak: %v", err)
	}
}
