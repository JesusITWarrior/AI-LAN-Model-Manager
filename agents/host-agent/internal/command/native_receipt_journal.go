package command

// This is an unwired, evidence-only journal. Its owner must already have stopped
// Run/Quiesce and hold exclusive ownership of the operation. It has no executor,
// replay store, transport, certificate verifier, outbox or release capability.
// A validated receipt is an input from a future controller-protocol verifier;
// the checksum below detects corruption, NOT authenticity. Do not use this
// foundation as that verifier or as execution/retirement authorization.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"unicode/utf8"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/privatefile"
)

const (
	nativeJournalCap    = 192 * 1024
	nativeResponseCap   = 64 * 1024
	nativeJournalDomain = "lan-model-manager/native-held-receipt/v1"
	nativeReceiptDomain = "lan-model-manager/controller-committed-receipt/v1"
	nativeHeld          = "HELD"
	nativeEvidence      = "EVIDENCE_COMMITTED"
	nativeACK           = "ACK_DURABLE"
	nativeRetired       = "ORDINARY_OUTBOX_RETIRED_OPERATION_GATE_CLOSED"
)

var errNativeJournal = errors.New("native receipt journal rejected; operation remains held")

// Serializes journal CAS even across stale handles within this process. This is
// not a cross-process lock: the runner owner must provide exclusive process
// ownership. Never run receipt handling concurrently with Run or Quiesce.
var nativeJournalMu sync.Mutex

type nativeReceiptTuple struct {
	Host, Job, Request                                       string
	Sequence                                                 uint64
	Idempotency, AuthDigest, QueueDigest, ResponseDigest     string
	Length                                                   uint64
	TerminalState, TerminalRevision, EvidenceKind, HoldClass string
	CertFingerprint, Serial, Binding, Owner, Session, Action string
	Disposition                                              string
}

type nativeReceiptCore struct {
	Domain, ReceiptID, TupleDigest string
	HoldEpoch                      uint64
	ResponseDigest, Disposition    string
	ControllerCommitted            bool
}

// The future protocol owner must validate the signed receipt and current trust
// before supplying this core. This type deliberately contains no transport ACK.
type nativeValidatedReceipt struct{ Core nativeReceiptCore }

type nativeJournalRecord struct {
	Version                                  uint64
	Domain                                   string
	Tuple                                    nativeReceiptTuple
	TupleDigest                              string
	EvidenceTupleDigest                      string
	HoldEpoch                                uint64
	Response                                 []byte
	State                                    string
	Held, OperationGateClosed, HoldUncertain bool
	Receipt                                  *nativeReceiptCore
	ReceiptDigest                            string
}

type nativeJournalWire struct {
	Record   nativeJournalRecord
	Checksum string
}

type nativeReceiptJournal struct {
	path   string
	record nativeJournalRecord
	poison error
	// Test-only operation-boundary injection. Nil in ordinary use. Failure at or
	// after rename poisons this handle even when publication cannot be determined.
	fault func(string) error
}

func nativeDigest(domain string, raw []byte) string {
	sum := sha256.Sum256(append(append([]byte(domain), 0), raw...))
	return hex.EncodeToString(sum[:])
}

func nativeObjectDigest(domain string, v any) string {
	raw, _ := json.Marshal(v) // Only fixed, JSON-safe internal structs are passed.
	return nativeDigest(domain, raw)
}

func nativeHash(s string) bool {
	if len(s) != 2*sha256.Size {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && hex.EncodeToString(b) == s
}

func nativeText(s string) bool { return len(s) > 0 && len(s) <= 256 && utf8.ValidString(s) }

// Reuse the offline codec's strict parser (duplicate keys, Unicode, number,
// depth and node bounds). The digest remains over the original exact bytes.
func nativeResponseValid(raw []byte) bool {
	_, err := strictEvidenceValue(raw, nativeResponseCap)
	return err == nil
}

// Preserve the existing TS/Go terminal-evidence digest convention. The journal
// tuple additionally binds current trust/owner/action/disposition, not just the
// controller terminal-evidence tuple.
func nativeJournalEvidenceTuple(t nativeReceiptTuple) nativeEvidenceTuple {
	return nativeEvidenceTuple{Domain: nativeEvidenceTupleDomain, HostID: t.Host, JobID: t.Job, RequestID: t.Request, CommandSequence: t.Sequence, IdempotencyKey: t.Idempotency, AuthorizationRequestDigest: t.AuthDigest, StoredQueueDigest: t.QueueDigest, TerminalState: t.TerminalState, TerminalRevision: t.TerminalRevision, ResponseDigest: t.ResponseDigest, ResponseByteLength: t.Length, EvidenceKind: t.EvidenceKind, HoldClass: t.HoldClass}
}

// nativeTuplePreflight bounds every caller-owned field before any marshal,
// digest, or response ownership. Enum membership also bounds enum strings.
func nativeTuplePreflight(t nativeReceiptTuple, responseLength int) bool {
	for _, s := range []string{t.Host, t.Job, t.Request, t.Idempotency, t.Serial, t.Binding, t.Owner, t.Session, t.Action, t.TerminalRevision} {
		if !nativeText(s) {
			return false
		}
	}
	for _, s := range []string{t.AuthDigest, t.QueueDigest, t.ResponseDigest, t.CertFingerprint} {
		if !nativeHash(s) {
			return false
		}
	}
	switch t.TerminalState {
	case "timed-out", "failed", "succeeded", "cancelled":
	default:
		return false
	}
	switch t.EvidenceKind {
	case "failed", "succeeded", "cancelled":
	default:
		return false
	}
	switch t.HoldClass {
	case "unknown", "in_flight", "retained", "pending_uncertain":
	default:
		return false
	}
	if (t.HoldClass == "pending_uncertain") != (t.Disposition == "pending_uncertain") {
		return false
	}
	return t.Sequence > 0 && t.Length == uint64(responseLength) &&
		(t.Disposition == "ordinary" || t.Disposition == "pending_uncertain")
}

func nativeRecordValid(r nativeJournalRecord) bool {
	t := r.Tuple
	if len(r.Response) == 0 || len(r.Response) > nativeResponseCap || !nativeTuplePreflight(t, len(r.Response)) {
		return false
	}
	evidenceDigest, err := nativeTupleDigest(nativeJournalEvidenceTuple(t))
	if err != nil || r.EvidenceTupleDigest != evidenceDigest {
		return false
	}
	if r.Version != 1 || r.Domain != nativeJournalDomain || !r.Held || !r.OperationGateClosed || r.HoldEpoch == 0 || t.Sequence == 0 || !nativeText(t.TerminalRevision) ||
		(t.Disposition != "ordinary" && t.Disposition != "pending_uncertain") || r.HoldUncertain != (t.Disposition == "pending_uncertain") ||
		!nativeResponseValid(r.Response) || t.Length != uint64(len(r.Response)) || t.ResponseDigest != domainDigest(nativeEvidenceResponseDomain, r.Response) ||
		r.TupleDigest != nativeObjectDigest("lan-model-manager/exact-tuple/v1", t) {
		return false
	}
	if r.State == nativeHeld {
		return r.Receipt == nil && r.ReceiptDigest == ""
	}
	if r.State != nativeEvidence && r.State != nativeACK && r.State != nativeRetired {
		return false
	}
	if r.State == nativeRetired && r.HoldUncertain {
		return false
	}
	c := r.Receipt
	return c != nil && c.Domain == nativeReceiptDomain && nativeText(c.ReceiptID) && c.ControllerCommitted && c.TupleDigest == r.TupleDigest &&
		c.HoldEpoch == r.HoldEpoch && c.ResponseDigest == t.ResponseDigest && c.Disposition == t.Disposition && r.ReceiptDigest == nativeObjectDigest(nativeReceiptDomain, *c)
}

func nativeEncode(r nativeJournalRecord) ([]byte, error) {
	if !nativeRecordValid(r) {
		return nil, errNativeJournal
	}
	b, err := json.Marshal(nativeJournalWire{r, nativeObjectDigest(nativeJournalDomain, r)})
	if err != nil || len(b) > nativeJournalCap {
		return nil, errNativeJournal
	}
	return b, nil
}

func nativeDecode(b []byte) (nativeJournalRecord, error) {
	var w nativeJournalWire
	if len(b) > nativeJournalCap || json.Unmarshal(b, &w) != nil {
		return w.Record, errNativeJournal
	}
	// The only accepted encoding is the fixed schema's canonical encoding. This
	// also rejects missing, duplicate, case-aliased and unknown fields at any depth.
	canonical, err := nativeEncode(w.Record)
	if err != nil || !bytes.Equal(canonical, b) {
		return w.Record, errNativeJournal
	}
	return w.Record, nil
}

func nativeJournalPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "native-receipt-hold.v1.json" {
		return errNativeJournal
	}
	if privatefile.Directory(filepath.Dir(path)) != nil {
		return errNativeJournal
	}
	return nativeJournalPlatformPath(path)
}

func nativeRead(path string) (nativeJournalRecord, error) {
	var zero nativeJournalRecord
	if err := nativeJournalPath(path); err != nil {
		return zero, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return zero, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() > nativeJournalCap {
		return zero, errNativeJournal
	}
	f, err := os.Open(path)
	if err != nil {
		return zero, errNativeJournal
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || privatefile.Check(f, 0600) != nil {
		return zero, errNativeJournal
	}
	b, err := io.ReadAll(io.LimitReader(f, nativeJournalCap+1))
	if err != nil {
		return zero, errNativeJournal
	}
	return nativeDecode(b)
}

// openNativeReceiptJournal never creates a missing record or resumes execution.
// Even ACK and retirement markers recover Held=true, OperationGateClosed=true.
func openNativeReceiptJournal(path string, tuple nativeReceiptTuple, epoch uint64) (*nativeReceiptJournal, error) {
	nativeJournalMu.Lock()
	defer nativeJournalMu.Unlock()
	r, err := nativeRead(path)
	if err != nil || r.Tuple != tuple || r.HoldEpoch != epoch {
		return nil, errNativeJournal
	}
	return &nativeReceiptJournal{path: path, record: r}, nil
}

func createNativeReceiptJournal(path string, tuple nativeReceiptTuple, epoch uint64, response []byte) (*nativeReceiptJournal, error) {
	return createNativeReceiptJournalWithFault(path, tuple, epoch, response, nil)
}

// fault is a per-call test-only boundary injection; ordinary callers use nil.
// It runs after all preflight checks and before any copy or digest.
func createNativeReceiptJournalWithFault(path string, tuple nativeReceiptTuple, epoch uint64, response []byte, fault func(string) error) (*nativeReceiptJournal, error) {
	if len(response) == 0 || len(response) > nativeResponseCap {
		return nil, errNativeJournal
	}
	if !nativeTuplePreflight(tuple, len(response)) {
		return nil, errNativeJournal
	}
	if fault != nil {
		if err := fault("before_copy_and_digest"); err != nil {
			return nil, err
		}
	}
	nativeJournalMu.Lock()
	defer nativeJournalMu.Unlock()
	if nativeJournalPath(path) != nil {
		return nil, errNativeJournal
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return nil, errNativeJournal
	}
	r := nativeJournalRecord{Version: 1, Domain: nativeJournalDomain, Tuple: tuple, TupleDigest: nativeObjectDigest("lan-model-manager/exact-tuple/v1", tuple), HoldEpoch: epoch, Response: append([]byte(nil), response...), State: nativeHeld, Held: true, OperationGateClosed: true, HoldUncertain: tuple.Disposition == "pending_uncertain"}
	r.EvidenceTupleDigest, _ = nativeTupleDigest(nativeJournalEvidenceTuple(tuple))
	j := &nativeReceiptJournal{path: path, record: r}
	raw, err := nativeEncode(r)
	if err != nil {
		return nil, err
	}
	if err = j.publish(raw); err != nil {
		j.poison = errNativeJournal
		return nil, errNativeJournal
	}
	return j, nil
}

// advance is an exact state/tuple/epoch CAS. Retirement is only a local evidence
// marker; it neither clears an owner field nor deletes any ordinary outbox. In
// particular uncertain operations cannot advance past ACK_DURABLE.
func (j *nativeReceiptJournal) advance(tuple nativeReceiptTuple, epoch uint64, from, to string, receipt nativeValidatedReceipt) error {
	nativeJournalMu.Lock()
	defer nativeJournalMu.Unlock()
	if j.poison != nil {
		return j.poison
	}
	if tuple != j.record.Tuple || epoch != j.record.HoldEpoch || from != j.record.State {
		return errNativeJournal
	}
	disk, err := nativeRead(j.path)
	if err != nil || nativeObjectDigest(nativeJournalDomain, disk) != nativeObjectDigest(nativeJournalDomain, j.record) {
		j.poison = errNativeJournal
		return j.poison
	}
	next := j.record
	switch {
	case from == nativeHeld && to == nativeEvidence:
		c := receipt.Core
		next.Receipt = &c
		next.ReceiptDigest = nativeObjectDigest(nativeReceiptDomain, c)
	case from == nativeEvidence && to == nativeACK, from == nativeACK && to == nativeRetired && !j.record.HoldUncertain:
		if j.record.Receipt == nil || receipt.Core != *j.record.Receipt {
			return errNativeJournal
		}
	default:
		return errNativeJournal
	}
	next.State = to
	raw, err := nativeEncode(next)
	if err != nil {
		return err
	}
	if err = j.publish(raw); err != nil {
		j.poison = errNativeJournal
		return j.poison
	}
	j.record = next
	return nil
}

// snapshot returns detached bytes/pointers; callers cannot mutate journal state.
func (j *nativeReceiptJournal) snapshot() nativeJournalRecord {
	nativeJournalMu.Lock()
	defer nativeJournalMu.Unlock()
	r := j.record
	r.Response = append([]byte(nil), r.Response...)
	if r.Receipt != nil {
		c := *r.Receipt
		r.Receipt = &c
	}
	return r
}

func (j *nativeReceiptJournal) step(name string) error {
	if j.fault != nil {
		return j.fault(name)
	}
	return nil
}

// Publication success means only the qualified platform APIs completed. A
// failure is sticky on this handle; no rollback after rename is attempted.
func (j *nativeReceiptJournal) publish(raw []byte) error {
	if nativeJournalPath(j.path) != nil {
		return errNativeJournal
	}
	if err := j.step("before_create"); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(j.path), ".native-held-receipt-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer func() { _ = f.Close(); _ = os.Remove(name) }()
	if err = j.step("after_create"); err != nil {
		return err
	}
	if err = f.Chmod(0600); err != nil {
		return err
	}
	if privatefile.Check(f, 0600) != nil {
		return errNativeJournal
	}
	if err = j.step("before_write"); err != nil {
		return err
	}
	n, err := f.Write(raw)
	if err != nil {
		return err
	}
	if n != len(raw) {
		return io.ErrShortWrite
	}
	if err = j.step("after_write"); err != nil {
		return err
	}
	if err = j.step("before_sync"); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = j.step("after_sync"); err != nil {
		return err
	}
	if err = j.step("before_close"); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = j.step("after_close"); err != nil {
		return err
	}
	if nativeJournalPath(j.path) != nil {
		return errNativeJournal
	}
	if err = j.step("before_rename"); err != nil {
		return err
	}
	if err = os.Rename(name, j.path); err != nil {
		return err
	}
	if err = j.step("after_rename"); err != nil {
		return err
	}
	if err = j.step("before_finish"); err != nil {
		return err
	}
	if err = finishNativeJournalPublication(filepath.Dir(j.path)); err != nil {
		return err
	}
	return j.step("after_finish")
}
