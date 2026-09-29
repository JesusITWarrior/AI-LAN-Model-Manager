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

// Run performs the authenticated hello, an immediate inventory heartbeat, and
// steady-state heartbeats until cancellation. Controller timing is accepted
// only inside the shared protocol bounds; failures use bounded exponential
// backoff and never expose their underlying details.
func (c *HTTPSClient) Run(ctx context.Context, collector Collector, platform, model string) error {
	if collector == nil || (platform != "linux" && platform != "darwin" && platform != "windows") {
		return ErrHTTPClient
	}
	interval, jitter, window := 30*time.Second, 2*time.Second, 60*time.Second
	ack, err := c.SendHello(ctx, platform, model, interval, jitter, window)
	if err != nil {
		return ErrHTTPClient
	}
	if validTiming(ack) {
		interval, jitter, window = time.Duration(ack.NextHeartbeatIntervalMs)*time.Millisecond, time.Duration(ack.NextHeartbeatIntervalJitterMs)*time.Millisecond, time.Duration(ack.NextHeartbeatWindowMs)*time.Millisecond
	}
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	attempt := uint(0)
	for {
		snapshot, collectErr := collector.Collect(ctx)
		if collectErr == nil {
			snapshot.Platform = platform
			_, collectErr = c.Send(ctx, snapshot)
		}
		var delay time.Duration
		if collectErr != nil {
			delay = Backoff(attempt, time.Second, min(interval, window), .2, random)
			attempt++
		} else {
			attempt = 0
			delay = interval
			if jitter > 0 {
				delay += time.Duration(random.Int63n(int64(2*jitter)+1)) - jitter
			}
			if delay < minInterval {
				delay = minInterval
			}
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-timer.C:
		}
	}
}

func validTiming(ack Ack) bool {
	i, j, w := time.Duration(ack.NextHeartbeatIntervalMs)*time.Millisecond, time.Duration(ack.NextHeartbeatIntervalJitterMs)*time.Millisecond, time.Duration(ack.NextHeartbeatWindowMs)*time.Millisecond
	return ack.Accepted && i >= minInterval && i <= maxInterval && j >= 0 && j <= maxJitter && w >= minInterval && w <= maxInterval
}
