package command

import (
	"bytes"
	"strings"
	"testing"
)

// nativeBindingSnapshot builds a valid accepted journal record whose tuple and
// receipt fields are internally consistent. Any field can be mutated by a test
// to force a specific mismatch. The returned receipt is the matching claim.
func nativeBindingSnapshot(t *testing.T, disposition string) (nativeJournalRecord, nativeValidatedReceipt) {
	t.Helper()
	path, tuple, raw := nativeFixture(t, disposition)
	j, err := createNativeReceiptJournal(path, tuple, 7, raw)
	if err != nil {
		t.Fatal(err)
	}
	accepted := j.snapshot()
	claim := nativeValidatedReceipt{nativeReceiptCore{
		Domain:              nativeReceiptDomain,
		ReceiptID:           "receipt-1",
		TupleDigest:         accepted.TupleDigest,
		HoldEpoch:           7,
		ResponseDigest:      tuple.ResponseDigest,
		Disposition:         disposition,
		ControllerCommitted: true,
	}}
	return accepted, claim
}

func TestNativeReceiptBindingValid(t *testing.T) {
	for _, disposition := range []string{"ordinary", "pending_uncertain"} {
		accepted, claim := nativeBindingSnapshot(t, disposition)
		if err := ValidateNativeReceiptBinding(accepted, claim); err != nil {
			t.Fatalf("disposition %s: expected nil, got %v", disposition, err)
		}
	}
}

// TestNativeReceiptBindingFieldMismatch drives one broken claim field at a
// time and asserts the reported field. Every binding field is covered.
func TestNativeReceiptBindingFieldMismatch(t *testing.T) {
	cases := []struct {
		name   string
		field  nativeBindingField
		mutate func(claim *nativeReceiptCore)
	}{
		{"domain", nativeBindingDomain, func(c *nativeReceiptCore) { c.Domain = "lan-model-manager/wrong/v1" }},
		{"receiptId", nativeBindingReceiptID, func(c *nativeReceiptCore) { c.ReceiptID = "" }},
		{"receiptIdMalformed", nativeBindingReceiptID, func(c *nativeReceiptCore) { c.ReceiptID = "\xff\xfe-invalid-utf8" }},
		{"uncommitted", nativeBindingControllerCommitted, func(c *nativeReceiptCore) { c.ControllerCommitted = false }},
		{"tupleDigest", nativeBindingTupleDigest, func(c *nativeReceiptCore) { c.TupleDigest = strings.Repeat("f", 64) }},
		{"holdEpoch", nativeBindingHoldEpoch, func(c *nativeReceiptCore) { c.HoldEpoch = 8 }},
		{"holdEpochZero", nativeBindingHoldEpoch, func(c *nativeReceiptCore) { c.HoldEpoch = 0 }},
		{"responseDigest", nativeBindingResponseDigest, func(c *nativeReceiptCore) { c.ResponseDigest = strings.Repeat("0", 64) }},
		{"disposition", nativeBindingDisposition, func(c *nativeReceiptCore) { c.Disposition = "pending_uncertain" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			accepted, claim := nativeBindingSnapshot(t, "ordinary")
			tc.mutate(&claim.Core)
			err := ValidateNativeReceiptBinding(accepted, claim)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			var be *nativeReceiptBindingError
			if !asNativeBindingError(err, &be) {
				t.Fatalf("expected *nativeReceiptBindingError, got %T", err)
			}
			if be.Field() != tc.field {
				t.Fatalf("field = %v, want %v", be.Field(), tc.field)
			}
			if be.Invalid() {
				t.Fatalf("expected a binding mismatch, got invalid snapshot error")
			}
		})
	}
}

// TestNativeReceiptBindingInvalidSnapshot asserts that a malformed accepted
// snapshot is reported as an invalid snapshot (empty field), never as a
// binding mismatch between two inputs.
func TestNativeReceiptBindingInvalidSnapshot(t *testing.T) {
	accepted, claim := nativeBindingSnapshot(t, "ordinary")
	accepted.State = "corrupt-state"
	err := ValidateNativeReceiptBinding(accepted, claim)
	if err == nil {
		t.Fatal("expected error for invalid snapshot")
	}
	var be *nativeReceiptBindingError
	if !asNativeBindingError(err, &be) {
		t.Fatalf("expected *nativeReceiptBindingError, got %T", err)
	}
	if !be.Invalid() {
		t.Fatalf("expected Invalid(), got field %v", be.Field())
	}
}

// TestNativeReceiptBindingNilClaim asserts an empty claim is a mismatch.
func TestNativeReceiptBindingNilClaim(t *testing.T) {
	accepted, _ := nativeBindingSnapshot(t, "ordinary")
	if e := ValidateNativeReceiptBinding(accepted, nativeValidatedReceipt{}); e == nil {
		t.Fatal("expected error for nil core claim")
	}
}

// TestNativeReceiptBindingNoMutationAndAliasing asserts that a claim core is
// copied internally: mutating the caller's struct after the call does not
// change the outcome, and the accepted snapshot is never mutated by the check.
func TestNativeReceiptBindingNoMutationAndAliasing(t *testing.T) {
	accepted, claim := nativeBindingSnapshot(t, "ordinary")
	before := accepted

	// First call with a matching claim succeeds.
	if err := ValidateNativeReceiptBinding(accepted, claim); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}

	// Mutate the caller's claim core after the first call returns.
	claim.Core.Domain = "lan-model-manager/changed/v1"

	// A second call must reflect the current (mutated) state, proving the
	// validator reads the claim at call time and copies internally rather
	// than holding a reference to the caller's struct.
	if err := ValidateNativeReceiptBinding(accepted, claim); err == nil {
		t.Fatal("expected error after claim mutation")
	}

	// The accepted snapshot must be byte-identical to its pre-call state.
	if !nativeRecordsEqual(accepted, before) {
		t.Fatalf("accepted snapshot was mutated by the binding check")
	}
}

// TestNativeReceiptBindingNoMutationOfAcceptedTuple ensures the accepted
// snapshot's tuple fields are not aliased or mutated by the check. A
// mismatching claim must still fail, so success cannot be smuggled by
// aliasing the accepted snapshot.
func TestNativeReceiptBindingNoMutationOfAcceptedTuple(t *testing.T) {
	accepted, claim := nativeBindingSnapshot(t, "ordinary")
	beforeTuple := accepted.Tuple

	claim.Core.ResponseDigest = strings.Repeat("1", 64)
	claim.Core.HoldEpoch = 99

	if err := ValidateNativeReceiptBinding(accepted, claim); err == nil {
		t.Fatal("expected error for mismatching claim")
	}
	if accepted.Tuple.Host != beforeTuple.Host ||
		accepted.Tuple.Job != beforeTuple.Job ||
		accepted.Tuple.Request != beforeTuple.Request ||
		accepted.Tuple.ResponseDigest != beforeTuple.ResponseDigest ||
		accepted.Tuple.Disposition != beforeTuple.Disposition {
		t.Fatalf("accepted tuple was mutated by the binding check")
	}
}

// TestNativeReceiptBindingMalformedDigests ensures malformed (non-hex, wrong
// length) claim digests are rejected as binding failures, not accepted.
func TestNativeReceiptBindingMalformedDigests(t *testing.T) {
	accepted, claim := nativeBindingSnapshot(t, "ordinary")

	claim.Core.TupleDigest = "short"
	if err := ValidateNativeReceiptBinding(accepted, claim); err == nil {
		t.Fatal("expected error for malformed tuple digest")
	}

	claim.Core.TupleDigest = accepted.TupleDigest
	claim.Core.ResponseDigest = "not-hex-not-64"
	if err := ValidateNativeReceiptBinding(accepted, claim); err == nil {
		t.Fatal("expected error for malformed response digest")
	}
}

// TestNativeReceiptBindingMalformedResponseLength ensures the accepted snapshot
// with an out-of-range response is reported as an invalid snapshot.
func TestNativeReceiptBindingMalformedResponseLength(t *testing.T) {
	accepted, claim := nativeBindingSnapshot(t, "ordinary")
	accepted.Tuple.Length = 1 << 20 // beyond nativeResponseCap
	accepted.Response = make([]byte, accepted.Tuple.Length)
	err := ValidateNativeReceiptBinding(accepted, claim)
	if err == nil {
		t.Fatal("expected error for oversized response in snapshot")
	}
	var be *nativeReceiptBindingError
	if !asNativeBindingError(err, &be) || !be.Invalid() {
		t.Fatalf("expected Invalid(), got %v", err)
	}
}

// TestNativeReceiptBindingUncommittedClaim asserts an uncommitted claim fails
// regardless of the other fields.
func TestNativeReceiptBindingUncommittedClaim(t *testing.T) {
	accepted, claim := nativeBindingSnapshot(t, "ordinary")
	claim.Core.ControllerCommitted = false
	if err := ValidateNativeReceiptBinding(accepted, claim); err == nil {
		t.Fatal("expected error for uncommitted claim")
	}
}

// asNativeBindingError coerces a possibly-nil error into *nativeReceiptBindingError.
func asNativeBindingError(err error, be **nativeReceiptBindingError) bool {
	if err == nil {
		return false
	}
	v, ok := err.(*nativeReceiptBindingError)
	if !ok {
		return false
	}
	*be = v
	return true
}

// nativeRecordsEqual compares two accepted journal records for byte-identical
// content, since nativeJournalRecord contains a []byte field and cannot be
// compared with ==.
func nativeRecordsEqual(a, b nativeJournalRecord) bool {
	if a.Version != b.Version || a.Domain != b.Domain || a.Tuple != b.Tuple ||
		a.TupleDigest != b.TupleDigest || a.EvidenceTupleDigest != b.EvidenceTupleDigest ||
		a.HoldEpoch != b.HoldEpoch || a.State != b.State || a.Held != b.Held ||
		a.OperationGateClosed != b.OperationGateClosed || a.HoldUncertain != b.HoldUncertain ||
		a.ReceiptDigest != b.ReceiptDigest {
		return false
	}
	if !bytes.Equal(a.Response, b.Response) {
		return false
	}
	if (a.Receipt == nil) != (b.Receipt == nil) {
		return false
	}
	if a.Receipt != nil && b.Receipt != nil && *a.Receipt != *b.Receipt {
		return false
	}
	return true
}
