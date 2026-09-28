package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"sync"
	"testing"
	"time"
)

func key(t *testing.T) ([]byte, *ecdsa.PublicKey) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}), &k.PublicKey
}
func TestEnvelopeSignVerifyAndTamper(t *testing.T) {
	private, public := key(t)
	e, err := NewEnvelope("agent-1", "request-1", "transport.hello", "nonce-123", "aabb", "ABCD", 1, time.Date(2026, 9, 27, 20, 0, 0, 0, time.UTC), map[string]any{"ready": true})
	if err != nil {
		t.Fatal(err)
	}
	if err = Sign(&e, private); err != nil {
		t.Fatal(err)
	}
	if err = Verify(e, public); err != nil {
		t.Fatal(err)
	}
	e.Payload = json.RawMessage(`{"ready":false}`)
	if Verify(e, public) == nil {
		t.Fatal("accepted body tamper")
	}
}
func TestSequencerConcurrent(t *testing.T) {
	s := NewSequencer(0)
	seen := sync.Map{}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v := s.Next()
			if _, loaded := seen.LoadOrStore(v, true); loaded {
				t.Errorf("duplicate %d", v)
			}
		}()
	}
	wg.Wait()
}
