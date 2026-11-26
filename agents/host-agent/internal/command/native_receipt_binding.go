package command

// Native receipt binding — offline, trust-free seam.
//
// ValidateNativeReceiptBinding asserts that a claimed controller-committed
// receipt binds to an accepted held-receipt snapshot on every field the claim
// carries. It performs no transport, signing, authentication, or replay work:
// it makes no claim about the cryptographic authenticity of either input and
// grants no execution, retirement, or release authority. A non-nil result
// names the first mismatched binding field, or reports that the accepted
// snapshot itself was rejected as malformed.
//
// This is a validation seam for a future controller-protocol verifier: it
// rejects mismatches, it never authorizes anything.

import "errors"

// nativeBindingField identifies which bound field a claim failed to match.
type nativeBindingField string

const (
	nativeBindingDomain              nativeBindingField = "domain"
	nativeBindingReceiptID           nativeBindingField = "receiptId"
	nativeBindingControllerCommitted nativeBindingField = "controllerCommitted"
	nativeBindingTupleDigest         nativeBindingField = "tupleDigest"
	nativeBindingHoldEpoch           nativeBindingField = "holdEpoch"
	nativeBindingResponseDigest      nativeBindingField = "responseDigest"
	nativeBindingDisposition         nativeBindingField = "disposition"
)

// nativeReceiptBindingError reports either a binding mismatch (a claim field
// that disagrees with the accepted snapshot) or an invalid accepted snapshot.
// Field names the first mismatched binding field, or is empty when the
// accepted snapshot was itself rejected (see Invalid).
type nativeReceiptBindingError struct {
	field nativeBindingField
	cause error
}

func (e *nativeReceiptBindingError) Error() string {
	if e.field == "" {
		return "native receipt snapshot rejected: " + e.cause.Error()
	}
	return "native receipt binding rejected: field " + string(e.field) + " does not match accepted snapshot"
}

func (e *nativeReceiptBindingError) Unwrap() error { return e.cause }

// Field names the first mismatched binding field. It is empty when the
// accepted snapshot was itself rejected as malformed.
func (e *nativeReceiptBindingError) Field() nativeBindingField { return e.field }

// Invalid reports whether the error is an invalid accepted snapshot rather
// than a binding mismatch between two otherwise well-formed inputs.
func (e *nativeReceiptBindingError) Invalid() bool { return e.field == "" }

// ValidateNativeReceiptBinding performs an offline, trust-free binding check
// between an accepted held-receipt snapshot and a claimed controller-committed
// receipt. It returns nil only when every field the claim carries agrees with
// the accepted snapshot; otherwise it returns a *nativeReceiptBindingError
// naming the first mismatched binding field, or reporting that the accepted
// snapshot was itself malformed. No input is mutated, and no state is cached
// between calls.
func ValidateNativeReceiptBinding(accepted nativeJournalRecord, claim nativeValidatedReceipt) error {
	return validateNativeReceiptBinding(accepted, claim)
}

func validateNativeReceiptBinding(accepted nativeJournalRecord, claim nativeValidatedReceipt) error {
	// The accepted snapshot is the ground truth. Reject it outright when it is
	// not a well-formed record: an untrusted base cannot bind to anything, and
	// that is not a binding mismatch between two inputs.
	if !nativeRecordValid(accepted) {
		return &nativeReceiptBindingError{cause: errNativeJournal}
	}

	// Copy the claim core once so later field comparisons never read through a
	// caller-supplied pointer that could be mutated after the call returns.
	c := claim.Core

	// Bound each claim field against the accepted snapshot. The first failure
	// names its field; later fields are not evaluated, so the reported field is
	// deterministic and stable regardless of how many fields are broken.
	if c.Domain != nativeReceiptDomain {
		return &nativeReceiptBindingError{field: nativeBindingDomain, cause: errNativeBindingDomain}
	}
	if !nativeText(c.ReceiptID) {
		return &nativeReceiptBindingError{field: nativeBindingReceiptID, cause: errNativeBindingReceiptID}
	}
	if !c.ControllerCommitted {
		return &nativeReceiptBindingError{field: nativeBindingControllerCommitted, cause: errNativeBindingUncommitted}
	}
	if !nativeHash(c.TupleDigest) {
		return &nativeReceiptBindingError{field: nativeBindingTupleDigest, cause: errNativeBindingTupleDigest}
	}
	if c.TupleDigest != accepted.TupleDigest {
		return &nativeReceiptBindingError{field: nativeBindingTupleDigest, cause: errNativeBindingTupleMismatch}
	}
	if c.HoldEpoch == 0 || c.HoldEpoch != accepted.HoldEpoch {
		return &nativeReceiptBindingError{field: nativeBindingHoldEpoch, cause: errNativeBindingHoldEpoch}
	}
	if !nativeHash(c.ResponseDigest) {
		return &nativeReceiptBindingError{field: nativeBindingResponseDigest, cause: errNativeBindingResponseDigest}
	}
	if c.ResponseDigest != accepted.Tuple.ResponseDigest {
		return &nativeReceiptBindingError{field: nativeBindingResponseDigest, cause: errNativeBindingResponseMismatch}
	}
	if c.Disposition != accepted.Tuple.Disposition {
		return &nativeReceiptBindingError{field: nativeBindingDisposition, cause: errNativeBindingDisposition}
	}
	// If the accepted snapshot already carried a controller-committed receipt,
	// the claim must reproduce its ReceiptID exactly; otherwise this is a
	// re-commit of a different receipt for the same operation.
	if accepted.Receipt != nil && c.ReceiptID != accepted.Receipt.ReceiptID {
		return &nativeReceiptBindingError{field: nativeBindingReceiptID, cause: errNativeBindingReceiptID}
	}
	return nil
}

var (
	errNativeBindingDomain           = errors.New("receipt domain does not match the controller-committed domain")
	errNativeBindingReceiptID        = errors.New("receipt id is malformed")
	errNativeBindingUncommitted      = errors.New("controller has not committed this receipt")
	errNativeBindingTupleDigest      = errors.New("tuple digest is malformed or does not match the accepted snapshot")
	errNativeBindingTupleMismatch    = errors.New("tuple digest does not match the accepted snapshot")
	errNativeBindingHoldEpoch        = errors.New("hold epoch is malformed or does not match the accepted snapshot")
	errNativeBindingResponseDigest   = errors.New("response digest is malformed or does not match the accepted snapshot")
	errNativeBindingResponseMismatch = errors.New("response digest does not match the accepted snapshot")
	errNativeBindingDisposition      = errors.New("disposition does not match the accepted snapshot")
)
