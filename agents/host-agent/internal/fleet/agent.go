package fleet

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"sync"
	"time"
)

var ErrFleet = errors.New("fleet heartbeat failed")

type Snapshot struct {
	Platform      string `json:"platform"`
	ProtocolMinor uint64 `json:"protocolMinor"`
	Idle          bool   `json:"idle"`
	ObservedAt    string `json:"observedAt"`
	Sequence      uint64 `json:"sequence"`
	Providers     any    `json:"providers,omitempty"`
	Models        any    `json:"models,omitempty"`
	Resource      any    `json:"resource,omitempty"`
}
type Collector interface {
	Collect(context.Context) (Snapshot, error)
}
type Sender interface {
	Send(context.Context, Snapshot) (uint64, error)
}
type Clock interface{ Now() time.Time }
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

type Agent struct {
	mu           sync.Mutex
	collector    Collector
	sender       Sender
	clock        Clock
	sequence     uint64
	acknowledged uint64
	running      bool
	cancel       context.CancelFunc
}

func NewAgent(collector Collector, sender Sender, clock Clock) *Agent {
	if clock == nil {
		clock = realClock{}
	}
	return &Agent{collector: collector, sender: sender, clock: clock}
}
func (a *Agent) RunOnce(ctx context.Context) error {
	a.mu.Lock()
	if a.collector == nil || a.sender == nil {
		a.mu.Unlock()
		return ErrFleet
	}
	a.sequence++
	sequence := a.sequence
	a.mu.Unlock()
	snapshot, err := a.collector.Collect(ctx)
	if err != nil {
		return ErrFleet
	}
	snapshot.Sequence = sequence
	snapshot.ObservedAt = a.clock.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	ack, err := a.sender.Send(ctx, snapshot)
	if err != nil || ack != sequence {
		return ErrFleet
	}
	a.mu.Lock()
	a.acknowledged = ack
	a.mu.Unlock()
	return nil
}
func (a *Agent) LastAcknowledged() uint64 { a.mu.Lock(); defer a.mu.Unlock(); return a.acknowledged }
func (a *Agent) Start(parent context.Context, ticks <-chan time.Time) error {
	a.mu.Lock()
	if a.running || ticks == nil {
		a.mu.Unlock()
		return ErrFleet
	}
	ctx, cancel := context.WithCancel(parent)
	a.running = true
	a.cancel = cancel
	a.mu.Unlock()
	go func() {
		defer func() { a.mu.Lock(); a.running = false; a.cancel = nil; a.mu.Unlock() }()
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-ticks:
				if !ok {
					return
				}
				_ = a.RunOnce(ctx)
			}
		}
	}()
	return nil
}
func (a *Agent) Stop() {
	a.mu.Lock()
	cancel := a.cancel
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}
func Backoff(attempt uint, base, max time.Duration, jitter float64, random *rand.Rand) time.Duration {
	if base <= 0 || max < base || jitter < 0 || jitter > 1 {
		return 0
	}
	power := math.Pow(2, float64(min(attempt, 20)))
	delay := time.Duration(float64(base) * power)
	if delay > max {
		delay = max
	}
	if jitter == 0 || random == nil {
		return delay
	}
	factor := 1 - jitter + random.Float64()*2*jitter
	value := time.Duration(float64(delay) * factor)
	if value < 0 {
		return 0
	}
	if value > max {
		return max
	}
	return value
}
