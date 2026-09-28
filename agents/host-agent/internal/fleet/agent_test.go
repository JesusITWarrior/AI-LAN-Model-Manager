package fleet

import (
	"context"
	"errors"
	"math/rand"
	"sync"
	"testing"
	"time"
)

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Date(2026, 9, 28, 5, 0, 0, 0, time.UTC) }

type collector struct{ err error }

func (c collector) Collect(context.Context) (Snapshot, error) {
	return Snapshot{Platform: "linux", ProtocolMinor: 0, Idle: true}, c.err
}

type sender struct {
	mu        sync.Mutex
	sequences []uint64
	bad       bool
	done      chan struct{}
}

func (s *sender) Send(_ context.Context, v Snapshot) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sequences = append(s.sequences, v.Sequence)
	if s.done != nil {
		close(s.done)
		s.done = nil
	}
	if s.bad {
		return 0, errors.New("bad")
	}
	return v.Sequence, nil
}
func TestRunOnceSequencesAndAcknowledges(t *testing.T) {
	out := &sender{}
	a := NewAgent(collector{}, out, fixedClock{})
	if a.LastAcknowledged() != 0 {
		t.Fatal("unexpected ack")
	}
	if err := a.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.LastAcknowledged() != 2 {
		t.Fatal("ack not advanced")
	}
	if len(out.sequences) != 2 || out.sequences[0] != 1 || out.sequences[1] != 2 {
		t.Fatal(out.sequences)
	}
}
func TestExplicitLifecycleAndFailureDoesNotAcknowledge(t *testing.T) {
	done := make(chan struct{})
	out := &sender{bad: true, done: done}
	a := NewAgent(collector{}, out, fixedClock{})
	ticks := make(chan time.Time, 1)
	if err := a.Start(context.Background(), ticks); err != nil {
		t.Fatal(err)
	}
	if err := a.Start(context.Background(), ticks); err == nil {
		t.Fatal("double start")
	}
	ticks <- time.Now()
	<-done
	close(ticks)
	if a.LastAcknowledged() != 0 {
		t.Fatal("failure acknowledged")
	}
	a.Stop()
}
func TestBackoffBoundedAndDeterministic(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	if Backoff(0, time.Second, time.Minute, 0, nil) != time.Second {
		t.Fatal("base")
	}
	if Backoff(20, time.Second, time.Minute, 0, nil) != time.Minute {
		t.Fatal("cap")
	}
	v := Backoff(2, time.Second, time.Minute, .25, r)
	if v < 3*time.Second || v > 5*time.Second {
		t.Fatal(v)
	}
	if Backoff(1, 0, time.Second, 0, nil) != 0 {
		t.Fatal("invalid")
	}
}
