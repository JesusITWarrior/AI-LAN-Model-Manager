package fleet

import (
	"context"
	"math/rand"
	"time"
)

const (
	minInterval = time.Second
	maxInterval = 24 * time.Hour
	maxJitter   = 5 * time.Second
)

// Run maintains an authenticated fleet session until cancellation. A failed
// hello or heartbeat discards the session and performs a new hello after a
// bounded, cancellation-aware exponential backoff.
func (c *HTTPSClient) Run(ctx context.Context, collector Collector, platform, model string) error {
	if ctx == nil || collector == nil || (platform != "linux" && platform != "darwin" && platform != "windows") {
		return ErrHTTPClient
	}
	interval, jitter, window := 30*time.Second, 2*time.Second, 60*time.Second
	random := c.runnerRandom()
	attempt := uint(0)
	for {
		if ctx.Err() != nil {
			return nil
		}
		ack, err := c.runnerHello(ctx, platform, model, interval, jitter, window)
		if err != nil || !validTiming(ack) {
			if !c.runnerWait(ctx, Backoff(attempt, c.runnerBase(), c.runnerCap(), .2, random)) {
				return nil
			}
			attempt++
			continue
		}
		interval, jitter, window = time.Duration(ack.NextHeartbeatIntervalMs)*time.Millisecond, time.Duration(ack.NextHeartbeatIntervalJitterMs)*time.Millisecond, time.Duration(ack.NextHeartbeatWindowMs)*time.Millisecond
		attempt = 0
		for {
			snapshot, collectErr := collector.Collect(ctx)
			if collectErr == nil {
				snapshot.Platform = platform
				_, collectErr = c.runnerSend(ctx, snapshot)
			}
			if collectErr != nil {
				if ctx.Err() != nil {
					return nil
				}
				// Collection failures do not invalidate mTLS state. Transport
				// failures do, so conservatively establish a fresh hello before
				// sending any later inventory.
				if !c.runnerWait(ctx, Backoff(attempt, c.runnerBase(), min(c.runnerCap(), min(interval, window)), .2, random)) {
					return nil
				}
				attempt++
				break
			}
			attempt = 0
			if ctx.Err() != nil {
				return nil
			}
			delay := interval
			if jitter > 0 {
				delay += time.Duration(random.Int63n(int64(2*jitter)+1)) - jitter
			}
			if delay < minInterval {
				delay = minInterval
			}
			if !c.runnerWait(ctx, delay) {
				return nil
			}
		}
	}
}

func (c *HTTPSClient) runnerHello(ctx context.Context, platform, model string, interval, jitter, window time.Duration) (Ack, error) {
	if c.runHello != nil {
		return c.runHello(ctx, platform, model, interval, jitter, window)
	}
	return c.SendHello(ctx, platform, model, interval, jitter, window)
}
func (c *HTTPSClient) runnerSend(ctx context.Context, snapshot Snapshot) (uint64, error) {
	if c.runSend != nil {
		return c.runSend(ctx, snapshot)
	}
	return c.Send(ctx, snapshot)
}
func (c *HTTPSClient) runnerWait(ctx context.Context, delay time.Duration) bool {
	if c.runWait != nil {
		return c.runWait(ctx, delay)
	}
	if delay <= 0 {
		delay = time.Millisecond
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
func (c *HTTPSClient) runnerRandom() *rand.Rand {
	if c.runRandom != nil {
		return c.runRandom
	}
	return rand.New(rand.NewSource(time.Now().UnixNano()))
}
func (c *HTTPSClient) runnerBase() time.Duration {
	if c.runBackoffBase > 0 {
		return c.runBackoffBase
	}
	return time.Second
}
func (c *HTTPSClient) runnerCap() time.Duration {
	if c.runBackoffCap > 0 {
		return c.runBackoffCap
	}
	return 30 * time.Second
}

func validTiming(ack Ack) bool {
	i, j, w := time.Duration(ack.NextHeartbeatIntervalMs)*time.Millisecond, time.Duration(ack.NextHeartbeatIntervalJitterMs)*time.Millisecond, time.Duration(ack.NextHeartbeatWindowMs)*time.Millisecond
	return ack.Accepted && i >= minInterval && i <= maxInterval && j >= 0 && j <= maxJitter && w >= minInterval && w <= maxInterval
}
