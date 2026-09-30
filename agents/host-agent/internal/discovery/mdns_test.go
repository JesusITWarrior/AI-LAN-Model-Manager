package discovery

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func fixture() Advertisement {
	return Advertisement{ID: "agent-1", DisplayName: "Office GPU", ProtocolVersion: ProtocolVersion{Major: 1, Minor: 0}, AgentPort: 7443, Platform: "linux", Addresses: []string{"192.168.1.20", "2001:db8::1"}, TTLSeconds: 120}
}
func TestAdvertisementMatchesCrossLanguageFixture(t *testing.T) {
	packet, err := BuildAdvertisement(fixture())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("testdata/advertisement.hex")
	if err != nil {
		t.Fatal(err)
	}
	expected, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if string(packet) != string(expected) {
		t.Fatalf("fixture mismatch: got %x", packet)
	}
}
func TestAdvertisementValidation(t *testing.T) {
	tests := []Advertisement{{}, {ID: "bad/id", DisplayName: "x", ProtocolVersion: ProtocolVersion{Major: 1}, AgentPort: 1, Platform: "linux", TTLSeconds: 1}, {ID: "x", DisplayName: "x", ProtocolVersion: ProtocolVersion{Major: 2}, AgentPort: 1, Platform: "linux", TTLSeconds: 1}, {ID: "x", DisplayName: "x", ProtocolVersion: ProtocolVersion{Major: 1}, AgentPort: 1, Platform: "linux", Addresses: []string{"2001:0db8::1"}, TTLSeconds: 1}, {ID: "x", DisplayName: "x\n", ProtocolVersion: ProtocolVersion{Major: 1}, AgentPort: 1, Platform: "linux", TTLSeconds: 1}}
	for _, item := range tests {
		if _, err := BuildAdvertisement(item); !errors.Is(err, ErrInvalidAdvertisement) {
			t.Fatalf("expected invalid: %#v: %v", item, err)
		}
	}
}

type fakeSender struct {
	sent     [][]byte
	closed   int
	sendErr  error
	closeErr error
}

func (f *fakeSender) Send(packet []byte) error {
	f.sent = append(f.sent, append([]byte(nil), packet...))
	return f.sendErr
}
func (f *fakeSender) Close() error { f.closed++; return f.closeErr }
func TestAdvertiserExplicitLifecycle(t *testing.T) {
	sender := &fakeSender{}
	advertiser, err := NewAdvertiser(sender, fixture())
	if err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) != 0 {
		t.Fatal("sent before start")
	}
	if err = advertiser.Start(); err != nil {
		t.Fatal(err)
	}
	if err = advertiser.Start(); err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("sends=%d", len(sender.sent))
	}
	if err = advertiser.Stop(); err != nil {
		t.Fatal(err)
	}
	if err = advertiser.Stop(); err != nil {
		t.Fatal(err)
	}
	if sender.closed != 1 {
		t.Fatalf("closes=%d", sender.closed)
	}
}
func TestAdvertiserErrorsAreRedacted(t *testing.T) {
	sender := &fakeSender{sendErr: errors.New("secret interface")}
	advertiser, _ := NewAdvertiser(sender, fixture())
	err := advertiser.Start()
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unredacted: %v", err)
	}
}

func TestAdvertiserRunIsPeriodicAndStops(t *testing.T) {
	value := fixture()
	value.TTLSeconds = 1
	sender := &fakeSender{}
	advertiser, err := NewAdvertiser(sender, value)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1100*time.Millisecond)
	defer cancel()
	if err = advertiser.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) < 2 {
		t.Fatalf("periodic sends=%d", len(sender.sent))
	}
	if sender.closed != 1 {
		t.Fatalf("closes=%d", sender.closed)
	}
}
