package enrollment

import (
	"context"
	"errors"
	"time"
)

const (
	PollingIntervalDefault = time.Second
	PollingTimeoutDefault  = 2 * time.Minute
)

// PollingEnroller presents the one-time code exactly once, then retries the
// same proof and CSR for a bounded period while the controller waits for owner
// confirmation. It never persists the code or pending challenge.
type PollingEnroller struct {
	Client   *Client
	Present  func(string)
	Interval time.Duration
	Timeout  time.Duration
}

func (p PollingEnroller) Enroll(ctx context.Context) (Outcome, error) {
	if p.Client == nil || p.Present == nil {
		return Outcome{Status: StatusDegraded}, ErrInvalidConfig
	}
	if status := p.Client.Status(); status.Status == StatusEnrolled {
		return status, nil
	}
	interval, timeout := p.Interval, p.Timeout
	if interval == 0 {
		interval = PollingIntervalDefault
	}
	if timeout == 0 {
		timeout = PollingTimeoutDefault
	}
	if interval < 10*time.Millisecond || timeout < interval || timeout > PollingTimeoutDefault {
		return Outcome{Status: StatusDegraded}, ErrInvalidConfig
	}
	code, err := p.Client.Begin(ctx)
	if err != nil {
		return Outcome{Status: StatusDegraded}, err
	}
	p.Present(code)
	pollCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-pollCtx.Done():
			p.Client.discardPending()
			return Outcome{Status: StatusPending}, ErrUnavailable
		case <-ticker.C:
			outcome, completeErr := p.Client.Complete(pollCtx)
			if completeErr == nil {
				return outcome, nil
			}
			if !errors.Is(completeErr, ErrUnavailable) || outcome.Status != StatusPending {
				return outcome, completeErr
			}
		}
	}
}
