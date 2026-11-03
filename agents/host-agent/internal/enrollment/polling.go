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
	Client        *Client
	Present       func(string)
	SecurePresent func(context.Context, string, time.Time) (func(), error)
	Interval      time.Duration
	Timeout       time.Duration
}

func (p PollingEnroller) Enroll(ctx context.Context) (Outcome, error) {
	if p.Client == nil || (p.Present == nil && p.SecurePresent == nil) {
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
	pollCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	p.Client.mu.Lock()
	expires := p.Client.pending.Pairing.ExpiresAt
	p.Client.mu.Unlock()
	if deadline, ok := pollCtx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	if p.SecurePresent != nil {
		cleanup, presentErr := p.SecurePresent(pollCtx, code, expires)
		code = ""
		if presentErr != nil || cleanup == nil {
			p.Client.discardPending()
			return failedOutcome("present", "failed", nil)
		}
		defer cleanup()
	} else {
		p.Present(code)
		code = ""
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-pollCtx.Done():
			p.Client.discardPending()
			return Outcome{Status: StatusPending}, &Failure{Stage: "poll", Reason: "timeout"}
		case <-ticker.C:
			outcome, completeErr := p.Client.Complete(pollCtx)
			if completeErr == nil {
				return outcome, nil
			}
			// The deadline and ticker can become ready together. Complete maps an
			// already-cancelled request to degraded, but the polling contract must
			// report a bounded pending timeout and discard ephemeral proof material.
			if pollCtx.Err() != nil {
				p.Client.discardPending()
				return Outcome{Status: StatusPending}, &Failure{Stage: "poll", Reason: "timeout"}
			}
			if !errors.Is(completeErr, ErrUnavailable) || outcome.Status != StatusPending {
				return outcome, completeErr
			}
		}
	}
}
