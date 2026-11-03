package enrollment

import "errors"

type identityFailure struct{ reason string }

func (*identityFailure) Error() string { return "enrollment identity failed" }
func (*identityFailure) Unwrap() error { return ErrIdentity }

// Failure exposes only fixed local stage/reason and HTTP status, never
// response bodies, URLs, codes, proof, certificates or filesystem paths.
type Failure struct {
	Stage, Reason string
	HTTPStatus    int
}

func (f *Failure) Error() string { return "enrollment failed" }
func (f *Failure) Unwrap() error {
	if f.Stage == "poll" {
		return ErrUnavailable
	}
	return ErrFailed
}
func failedOutcome(stage, reason string, cause error) (Outcome, error) {
	failure := &Failure{Stage: stage, Reason: reason}
	var local *identityFailure
	if errors.As(cause, &local) {
		failure.Reason = local.reason
	}
	var remote *Failure
	if errors.As(cause, &remote) {
		failure.Reason, failure.HTTPStatus = remote.Reason, remote.HTTPStatus
	}
	return Outcome{Status: StatusDegraded}, failure
}

// FailureDetails is the only supported logging projection, including when a
// caller supplies an arbitrary error instead of a trusted enrollment error.
func FailureDetails(err error) (stage, reason string, status int) {
	var failure *Failure
	if errors.As(err, &failure) {
		switch failure.Stage {
		case "begin", "proof", "identity", "complete", "verify", "save", "poll", "present", "http":
			stage = failure.Stage
		}
		switch failure.Reason {
		case "failed", "network", "response", "rejected", "timeout", "cancelled", "expired", "permissions", "key", "binding", "csr-create", "csr-parse", "csr-signature", "csr-binding":
			reason = failure.Reason
		}
		if failure.HTTPStatus >= 100 && failure.HTTPStatus <= 599 {
			status = failure.HTTPStatus
		}
	}
	if stage == "" {
		stage = "enrollment"
	}
	if reason == "" {
		reason = "failed"
	}
	return
}
