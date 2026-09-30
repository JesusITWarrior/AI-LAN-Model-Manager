package fleet

import (
	"context"
	"errors"
	"math/rand"
	"testing"
	"time"
)

func runnerAck() Ack {
	return Ack{Accepted: true, Sequence: 1, NextHeartbeatIntervalMs: 1000, NextHeartbeatIntervalJitterMs: 0, NextHeartbeatWindowMs: 1000}
}

func TestRunnerReconnectsInitialHelloWithBoundedBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hellos, sends := 0, 0
	var delays []time.Duration
	client := &HTTPSClient{runBackoffBase: 10 * time.Millisecond, runBackoffCap: 25 * time.Millisecond, runRandom: rand.New(rand.NewSource(1))}
	client.runHello = func(context.Context, string, string, time.Duration, time.Duration, time.Duration) (Ack, error) {
		hellos++
		if hellos < 3 {
			return Ack{}, errors.New("private network detail")
		}
		return runnerAck(), nil
	}
	client.runSend = func(context.Context, Snapshot) (uint64, error) { sends++; cancel(); return 1, nil }
	client.runWait = func(ctx context.Context, d time.Duration) bool { delays = append(delays, d); return ctx.Err() == nil }
	if err := client.Run(ctx, collector{}, "linux", ""); err != nil {
		t.Fatal(err)
	}
	if hellos != 3 || sends != 1 {
		t.Fatalf("hellos=%d sends=%d", hellos, sends)
	}
	if len(delays) != 2 || delays[0] > 25*time.Millisecond || delays[1] > 25*time.Millisecond || delays[1] < delays[0] {
		t.Fatalf("delays=%v", delays)
	}
}

func TestRunnerReestablishesHelloAfterHeartbeatFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hellos, sends := 0, 0
	client := &HTTPSClient{runBackoffBase: time.Millisecond, runBackoffCap: time.Millisecond, runRandom: rand.New(rand.NewSource(2)), runWait: func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil }}
	client.runHello = func(context.Context, string, string, time.Duration, time.Duration, time.Duration) (Ack, error) {
		hellos++
		return runnerAck(), nil
	}
	client.runSend = func(context.Context, Snapshot) (uint64, error) {
		sends++
		if sends == 1 {
			return 0, errors.New("session lost")
		}
		cancel()
		return 2, nil
	}
	if err := client.Run(ctx, collector{}, "windows", ""); err != nil {
		t.Fatal(err)
	}
	if hellos != 2 || sends != 2 {
		t.Fatalf("hellos=%d sends=%d", hellos, sends)
	}
}

func TestRunnerBackoffCancellationReturnsPromptly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &HTTPSClient{runHello: func(context.Context, string, string, time.Duration, time.Duration, time.Duration) (Ack, error) {
		t.Fatal("hello after cancellation")
		return Ack{}, nil
	}}
	start := time.Now()
	if err := client.Run(ctx, collector{}, "linux", ""); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("cancellation delayed")
	}
}
