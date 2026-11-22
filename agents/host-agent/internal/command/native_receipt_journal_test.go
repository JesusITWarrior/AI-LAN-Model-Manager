package command

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func nativeFixture(t *testing.T, disposition string) (string, nativeReceiptTuple, []byte) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"status":"ADAPTER_FAILED","observation":{"progress":1,"error":"stopped","time":"2026-11-22"}}`)
	hash := strings.Repeat("a", 64)
	tuple := nativeReceiptTuple{Host: "host", Job: "job", Request: "request", Sequence: 1, Idempotency: "key", AuthDigest: hash, QueueDigest: hash, ResponseDigest: domainDigest(nativeEvidenceResponseDomain, raw), Length: uint64(len(raw)), TerminalRevision: "history-1", TerminalState: "failed", EvidenceKind: "failed", HoldClass: "retained", CertFingerprint: hash, Serial: "serial", Binding: "binding", Owner: "owner", Session: "session", Action: "supplemental_evidence", Disposition: disposition}
	if disposition == "pending_uncertain" {
		tuple.HoldClass = "pending_uncertain"
	}
	return filepath.Join(dir, "native-receipt-hold.v1.json"), tuple, raw
}

func nativeCreate(t *testing.T, disposition string) (*nativeReceiptJournal, nativeReceiptTuple, nativeValidatedReceipt) {
	t.Helper()
	path, tuple, raw := nativeFixture(t, disposition)
	j, err := createNativeReceiptJournal(path, tuple, 7, raw)
	if err != nil {
		t.Fatal(err)
	}
	c := nativeValidatedReceipt{nativeReceiptCore{Domain: nativeReceiptDomain, ReceiptID: "receipt-1", TupleDigest: j.record.TupleDigest, HoldEpoch: 7, ResponseDigest: tuple.ResponseDigest, Disposition: disposition, ControllerCommitted: true}}
	return j, tuple, c
}

func nativeAssertHeld(t *testing.T, r nativeJournalRecord) {
	t.Helper()
	if !r.Held || !r.OperationGateClosed || !nativeRecordValid(r) {
		t.Fatalf("not held: %+v", r)
	}
}

func nativeAssertNoTemps(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".native-held-receipt-") {
			t.Fatalf("leaked temp %s", e.Name())
		}
	}
}

func TestNativeReceiptJournalReopenEveryState(t *testing.T) {
	for _, disposition := range []string{"ordinary", "pending_uncertain"} {
		t.Run(disposition, func(t *testing.T) {
			j, tuple, c := nativeCreate(t, disposition)
			states := []string{nativeHeld, nativeEvidence, nativeACK}
			if disposition == "ordinary" {
				states = append(states, nativeRetired)
			}
			for i, state := range states {
				if i > 0 {
					if err := j.advance(tuple, 7, states[i-1], state, c); err != nil {
						t.Fatal(err)
					}
				}
				reopened, err := openNativeReceiptJournal(j.path, tuple, 7)
				if err != nil {
					t.Fatal(err)
				}
				r := reopened.snapshot()
				nativeAssertHeld(t, r)
				if r.State != state || !bytes.Equal(r.Response, j.record.Response) {
					t.Fatal("recovery changed evidence")
				}
				if disposition == "pending_uncertain" && !r.HoldUncertain {
					t.Fatal("uncertain hold lost")
				}
				nativeAssertNoTemps(t, j.path)
			}
			if disposition == "pending_uncertain" && j.advance(tuple, 7, nativeACK, nativeRetired, c) == nil {
				t.Fatal("uncertain retirement admitted")
			}
		})
	}
}

func TestNativeReceiptJournalEveryTupleAndEpochMismatchDenies(t *testing.T) {
	j, tuple, c := nativeCreate(t, "ordinary")
	before := j.snapshot()
	typ := reflect.TypeOf(tuple)
	for i := 0; i < typ.NumField(); i++ {
		t.Run(typ.Field(i).Name, func(t *testing.T) {
			changed := tuple
			field := reflect.ValueOf(&changed).Elem().Field(i)
			if field.Kind() == reflect.String {
				field.SetString(field.String() + "x")
			} else {
				field.SetUint(field.Uint() + 1)
			}
			if j.advance(changed, 7, nativeHeld, nativeEvidence, c) == nil {
				t.Fatal("tuple mismatch accepted")
			}
			if _, err := openNativeReceiptJournal(j.path, changed, 7); err == nil {
				t.Fatal("reopened foreign tuple")
			}
		})
	}
	if j.advance(tuple, 8, nativeHeld, nativeEvidence, c) == nil {
		t.Fatal("epoch mismatch accepted")
	}
	if _, err := openNativeReceiptJournal(j.path, tuple, 8); err == nil {
		t.Fatal("reopened foreign epoch")
	}
	if !reflect.DeepEqual(before, j.snapshot()) {
		t.Fatal("denial mutated evidence")
	}
}

func TestNativeReceiptJournalReceiptIsNotGenericACK(t *testing.T) {
	j, tuple, c := nativeCreate(t, "ordinary")
	before := j.snapshot()
	changes := []func(*nativeReceiptCore){
		func(c *nativeReceiptCore) { c.Domain = "ok" }, func(c *nativeReceiptCore) { c.ReceiptID = "" },
		func(c *nativeReceiptCore) { c.TupleDigest = strings.Repeat("b", 64) }, func(c *nativeReceiptCore) { c.HoldEpoch++ },
		func(c *nativeReceiptCore) { c.ResponseDigest = strings.Repeat("b", 64) }, func(c *nativeReceiptCore) { c.Disposition = "pending_uncertain" },
		func(c *nativeReceiptCore) { c.ControllerCommitted = false },
	}
	for _, change := range changes {
		bad := c
		change(&bad.Core)
		if j.advance(tuple, 7, nativeHeld, nativeEvidence, bad) == nil {
			t.Fatal("invalid receipt accepted")
		}
	}
	if j.advance(tuple, 7, nativeHeld, nativeACK, c) == nil || j.advance(tuple, 7, nativeHeld, nativeRetired, c) == nil {
		t.Fatal("skipped controller evidence")
	}
	if !reflect.DeepEqual(before, j.snapshot()) {
		t.Fatal("receipt denial mutated hold")
	}
	if err := j.advance(tuple, 7, nativeHeld, nativeEvidence, c); err != nil {
		t.Fatal(err)
	}
	bad := c
	bad.Core.ReceiptID = "other"
	if j.advance(tuple, 7, nativeEvidence, nativeACK, bad) == nil {
		t.Fatal("changed receipt core")
	}
	if j.advance(tuple, 7, nativeEvidence, nativeRetired, c) == nil {
		t.Fatal("retired before native ACK")
	}
}

func TestNativeReceiptJournalPublicationFaultMatrix(t *testing.T) {
	steps := []string{"before_create", "after_create", "before_write", "after_write", "before_sync", "after_sync", "before_close", "after_close", "before_rename", "after_rename", "before_finish", "after_finish"}
	for _, disposition := range []string{"ordinary", "pending_uncertain"} {
		for _, from := range []string{nativeHeld, nativeEvidence, nativeACK} {
			if disposition == "pending_uncertain" && from == nativeACK {
				continue
			}
			for _, step := range steps {
				t.Run(disposition+"/"+from+"/"+step, func(t *testing.T) {
					j, tuple, c := nativeCreate(t, disposition)
					if from != nativeHeld {
						if err := j.advance(tuple, 7, nativeHeld, nativeEvidence, c); err != nil {
							t.Fatal(err)
						}
					}
					if from == nativeACK {
						if err := j.advance(tuple, 7, nativeEvidence, nativeACK, c); err != nil {
							t.Fatal(err)
						}
					}
					to := map[string]string{nativeHeld: nativeEvidence, nativeEvidence: nativeACK, nativeACK: nativeRetired}[from]
					before := j.snapshot()
					oldBytes, err := os.ReadFile(j.path)
					if err != nil {
						t.Fatal(err)
					}
					j.fault = func(at string) error {
						if at == step {
							return errors.New("injected publication failure")
						}
						return nil
					}
					if j.advance(tuple, 7, from, to, c) == nil {
						t.Fatal("fault accepted")
					}
					if !reflect.DeepEqual(before, j.snapshot()) || j.poison == nil {
						t.Fatal("failure changed memory or lost poison")
					}
					j.fault = nil
					if j.advance(tuple, 7, from, to, c) == nil {
						t.Fatal("sticky poison cleared")
					}
					reopened, err := openNativeReceiptJournal(j.path, tuple, 7)
					if err != nil {
						t.Fatal(err)
					}
					want := from
					published := step == "after_rename" || step == "before_finish" || step == "after_finish"
					if published {
						want = to
					}
					r := reopened.snapshot()
					nativeAssertHeld(t, r)
					if r.State != want || !bytes.Equal(r.Response, before.Response) {
						t.Fatal("wrong durable state")
					}
					if !published {
						current, _ := os.ReadFile(j.path)
						if !bytes.Equal(current, oldBytes) {
							t.Fatal("partial publication")
						}
					}
					if disposition == "pending_uncertain" && !r.HoldUncertain {
						t.Fatal("pending barrier cleared")
					}
					nativeAssertNoTemps(t, j.path)
				})
			}
		}
	}
}

func TestNativeReceiptJournalStrictDecodeAndCaps(t *testing.T) {
	j, tuple, c := nativeCreate(t, "ordinary")
	if err := j.advance(tuple, 7, nativeHeld, nativeEvidence, c); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(j.path)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"truncated": raw[:len(raw)-1], "cap+1": bytes.Repeat([]byte("x"), nativeJournalCap+1), "unknown": append([]byte(`{"Unknown":1,`), raw[1:]...),
		"duplicate":        bytes.Replace(raw, []byte(`"Version":1`), []byte(`"Version":1,"Version":1`), 1),
		"nested_duplicate": bytes.Replace(raw, []byte(`"Host":"host"`), []byte(`"Host":"host","Host":"host"`), 1),
		"checksum":         bytes.Replace(raw, []byte(`"Checksum":"`), []byte(`"Checksum":"0`), 1),
		"generic_ack":      []byte(`{"ok":true}`), "trailing": append(append([]byte(nil), raw...), []byte(`{}`)...),
	}
	for name, b := range tests {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(j.path, b, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := openNativeReceiptJournal(j.path, tuple, 7); err == nil {
				t.Fatal("corruption accepted")
			}
		})
	}
	// Correctly recomputed checksums must not legitimize invalid semantics.
	changes := []func(*nativeJournalRecord){
		func(r *nativeJournalRecord) { r.Version++ }, func(r *nativeJournalRecord) { r.Domain = "foreign" },
		func(r *nativeJournalRecord) { r.Held = false }, func(r *nativeJournalRecord) { r.OperationGateClosed = false },
		func(r *nativeJournalRecord) { r.State = "RELEASED" }, func(r *nativeJournalRecord) { r.TupleDigest = strings.Repeat("b", 64) },
		func(r *nativeJournalRecord) { r.HoldEpoch++ }, func(r *nativeJournalRecord) { r.ReceiptDigest = strings.Repeat("b", 64) },
		func(r *nativeJournalRecord) { r.Tuple.Disposition = "unknown" }, func(r *nativeJournalRecord) { r.HoldUncertain = true },
	}
	for _, change := range changes {
		r := j.snapshot()
		change(&r)
		b, _ := json.Marshal(nativeJournalWire{r, nativeObjectDigest(nativeJournalDomain, r)})
		if _, err := nativeDecode(b); err == nil {
			t.Fatal("semantic corruption accepted")
		}
	}
}

func TestNativeReceiptJournalPrivacyAndPathEscape(t *testing.T) {
	j, tuple, _ := nativeCreate(t, "ordinary")
	if _, err := createNativeReceiptJournal(j.path, tuple, 7, j.record.Response); err == nil {
		t.Fatal("overwrote journal")
	}
	if _, err := openNativeReceiptJournal(filepath.Join(filepath.Dir(j.path), "command-status.json"), tuple, 7); err == nil {
		t.Fatal("diagnostic path accepted")
	}
	if nativeJournalPath("relative/native-receipt-hold.v1.json") == nil {
		t.Fatal("relative path accepted")
	}
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission/symlink cases; Windows uses DACL/reparse checks")
	}
	if err := os.Chmod(j.path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := openNativeReceiptJournal(j.path, tuple, 7); err == nil {
		t.Fatal("public file accepted")
	}
	if err := os.Chmod(j.path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(j.path), 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := openNativeReceiptJournal(j.path, tuple, 7); err == nil {
		t.Fatal("writable directory accepted")
	}
	if err := os.Chmod(filepath.Dir(j.path), 0700); err != nil {
		t.Fatal(err)
	}
	target := j.path + ".saved"
	if err := os.Rename(j.path, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, j.path); err != nil {
		t.Fatal(err)
	}
	if _, err := openNativeReceiptJournal(j.path, tuple, 7); err == nil {
		t.Fatal("symlink accepted")
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(filepath.Dir(j.path), alias); err != nil {
		t.Fatal(err)
	}
	if nativeJournalPath(filepath.Join(alias, "native-receipt-hold.v1.json")) == nil {
		t.Fatal("ancestor symlink accepted")
	}
}

func TestNativeReceiptJournalEntireResponseBytes(t *testing.T) {
	base := []byte(`{"observation":{"progress":1,"error":"x","time":"t"},"ok":true}`)
	digest := domainDigest(nativeEvidenceResponseDomain, base)
	variants := []string{
		`{"observation":{"progress":2,"error":"x","time":"t"},"ok":true}`,
		`{"observation":{"progress":1,"error":"y","time":"t"},"ok":true}`,
		`{"observation":{"progress":1,"error":"x","time":"u"},"ok":true}`,
		`{"observation":{"progress":1.0,"error":"x","time":"t"},"ok":true}`,
		`{"observation":{"progress":1,"error":"\u0078","time":"t"},"ok":true}`,
		`{"ok":true,"observation":{"progress":1,"error":"x","time":"t"}}`,
	}
	for _, s := range variants {
		if domainDigest(nativeEvidenceResponseDomain, []byte(s)) == digest {
			t.Fatal("response bytes normalized")
		}
	}
	if domainDigest(nativeEvidenceResponseDomain, append([]byte(nil), base...)) != digest {
		t.Fatal("retransmission changed")
	}
	for _, s := range []string{`{"x":1,"x":2}`, `{"x":{"a":1,"\u0061":1}}`, `[1,]`, `{} {}`, strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66)} {
		if nativeResponseValid([]byte(s)) {
			t.Fatalf("invalid response accepted: %s", s)
		}
	}
	if nativeResponseValid(bytes.Repeat([]byte(" "), nativeResponseCap+1)) {
		t.Fatal("oversized response accepted")
	}
}

func TestNativeReceiptJournalConcurrentCASAndStaleOwner(t *testing.T) {
	j, tuple, c := nativeCreate(t, "ordinary")
	stale, err := openNativeReceiptJournal(j.path, tuple, 7)
	if err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if j.advance(tuple, 7, nativeHeld, nativeEvidence, c) == nil {
				wins.Add(1)
			}
			nativeAssertHeld(t, j.snapshot())
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("CAS winners: %d", wins.Load())
	}
	if stale.advance(tuple, 7, nativeHeld, nativeEvidence, c) == nil || stale.poison == nil {
		t.Fatal("stale owner overwrote disk")
	}
	r := j.snapshot()
	r.Response[0] = 'x'
	r.Receipt.ReceiptID = "mutated"
	if !nativeRecordValid(j.snapshot()) {
		t.Fatal("snapshot aliases internal state")
	}
	nativeAssertNoTemps(t, j.path)
}

// The child kills itself without deferred cleanup after a real namespace
// replacement, exercising recovery across process death (not an in-memory mock).
func TestNativeReceiptJournalProcessKillRecovery(t *testing.T) {
	if path := os.Getenv("LMM_NATIVE_JOURNAL_KILL_PATH"); path != "" {
		r, err := nativeRead(path)
		if err != nil {
			os.Exit(80)
		}
		j, err := openNativeReceiptJournal(path, r.Tuple, r.HoldEpoch)
		if err != nil {
			os.Exit(81)
		}
		core := nativeReceiptCore{Domain: nativeReceiptDomain, ReceiptID: "receipt-1", TupleDigest: r.TupleDigest, HoldEpoch: r.HoldEpoch, ResponseDigest: r.Tuple.ResponseDigest, Disposition: r.Tuple.Disposition, ControllerCommitted: true}
		target := os.Getenv("LMM_NATIVE_JOURNAL_KILL_TARGET")
		j.fault = func(at string) error {
			if at == "after_rename" {
				p, _ := os.FindProcess(os.Getpid())
				_ = p.Kill()
				os.Exit(82)
			}
			return nil
		}
		_ = j.advance(r.Tuple, r.HoldEpoch, r.State, target, nativeValidatedReceipt{core})
		os.Exit(83)
	}
	for _, target := range []string{nativeEvidence, nativeACK, nativeRetired} {
		t.Run(target, func(t *testing.T) {
			j, tuple, c := nativeCreate(t, "ordinary")
			if target != nativeEvidence {
				if err := j.advance(tuple, 7, nativeHeld, nativeEvidence, c); err != nil {
					t.Fatal(err)
				}
			}
			if target == nativeRetired {
				if err := j.advance(tuple, 7, nativeEvidence, nativeACK, c); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestNativeReceiptJournalProcessKillRecovery$")
			cmd.Env = append(os.Environ(), "LMM_NATIVE_JOURNAL_KILL_PATH="+j.path, "LMM_NATIVE_JOURNAL_KILL_TARGET="+target)
			if err := cmd.Run(); err == nil {
				t.Fatal("child did not die")
			}
			recovered, err := openNativeReceiptJournal(j.path, tuple, 7)
			if err != nil {
				t.Fatal(err)
			}
			r := recovered.snapshot()
			nativeAssertHeld(t, r)
			if r.State != target {
				t.Fatal("child did not publish target")
			}
			nativeAssertNoTemps(t, j.path)
		})
	}
}

// Structural capability check, stronger than unused zero-valued spy counters:
// production journal source has no dependency or call into any execution path.
func TestNativeReceiptJournalHasNoExecutionOrReleaseCapability(t *testing.T) {
	for _, name := range []string{"native_receipt_journal.go", "native_receipt_journal_unix.go", "native_receipt_journal_windows.go"} {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{".Execute(", ".ExecuteStream(", "NewPersistent(", ".Run(", ".Quiesce(", ".persistenceErr", "writeReplayStore(", "net/http", "internal/adapter", "internal/provider", "internal/peer"} {
			if bytes.Contains(raw, []byte(forbidden)) {
				t.Fatalf("%s has forbidden capability %s", name, forbidden)
			}
		}
	}
}

// Reuse the frozen fixture consumed by the TypeScript and Go evidence codecs;
// this journal must not silently invent a different response hash domain.
func TestNativeReceiptJournalTSGoGoldenVectors(t *testing.T) {
	fixture := loadNativeEvidenceFixture(t)
	for _, v := range fixture.Vectors {
		raw, err := base64.StdEncoding.DecodeString(v.ResponseBase64)
		if err != nil || !nativeResponseValid(raw) || domainDigest(nativeEvidenceResponseDomain, raw) != v.ResponseDigest {
			t.Fatalf("golden vector %s rejected or changed", v.Name)
		}
	}
}

// All inputs are constructed outside the measured call. Zero allocations rules
// out even a cap+1 slice copy or a JSON marshal before rejecting these inputs.
func nativeAssertPreflightRejectsWithoutAllocation(t *testing.T, path string, tuple nativeReceiptTuple, response []byte) {
	t.Helper()
	allocs := testing.AllocsPerRun(20, func() {
		j, err := createNativeReceiptJournal(path, tuple, 7, response)
		if j != nil || err != errNativeJournal {
			t.Fatal("invalid input accepted")
		}
	})
	if allocs != 0 {
		t.Fatalf("rejection allocated: %v allocations/call", allocs)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("preflight rejection touched journal")
	}
}

func TestNativeReceiptJournalOversizedResponseRejectsBeforeAllocation(t *testing.T) {
	path, tuple, raw := nativeFixture(t, "ordinary")
	// Whitespace preserves a valid strict JSON response at the exact byte cap.
	boundary := append(append([]byte(nil), raw...), bytes.Repeat([]byte(" "), nativeResponseCap-len(raw))...)
	tuple.Length = uint64(len(boundary))
	tuple.ResponseDigest = domainDigest(nativeEvidenceResponseDomain, boundary)
	j, err := createNativeReceiptJournal(path, tuple, 7, boundary)
	if err != nil || j == nil {
		t.Fatalf("exact-cap response rejected: %v", err)
	}
	if !bytes.Equal(j.record.Response, boundary) || !nativeRecordValid(j.record) {
		t.Fatal("boundary response bytes changed")
	}
	boundary[0] = '!'
	if j.record.Response[0] == '!' {
		t.Fatal("accepted response not owned")
	}
	for _, size := range []int{0, nativeResponseCap + 1, 4 * 1024 * 1024} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			path, tuple, _ := nativeFixture(t, "ordinary")
			response := bytes.Repeat([]byte(" "), size)
			tuple.Length = uint64(size)
			nativeAssertPreflightRejectsWithoutAllocation(t, path, tuple, response)
		})
	}
}

func TestNativeReceiptJournalOversizedTupleFieldRejectsBeforeDigest(t *testing.T) {
	fields := []string{"Host", "Job", "Request", "Idempotency", "Serial", "Binding", "Owner", "Session", "Action", "TerminalRevision"}
	values := []struct{ name, value string }{
		{"257-bytes", strings.Repeat("x", 257)},
		{"empty", ""},
		{"invalid-utf8", string([]byte{0xff})},
		{"4MiB", strings.Repeat("x", 4*1024*1024)},
	}
	for _, field := range fields {
		for _, value := range values {
			t.Run(field+"/"+value.name, func(t *testing.T) {
				path, tuple, raw := nativeFixture(t, "ordinary")
				reflect.ValueOf(&tuple).Elem().FieldByName(field).SetString(value.value)
				nativeAssertPreflightRejectsWithoutAllocation(t, path, tuple, raw)
				called := false
				_, err := createNativeReceiptJournalWithFault(path, tuple, 7, raw, func(string) error {
					called = true
					return errors.New("digest boundary reached")
				})
				if err != errNativeJournal || called {
					t.Fatal("invalid field reached copy/digest boundary")
				}
				r := nativeJournalRecord{Tuple: tuple, Response: raw}
				if allocs := testing.AllocsPerRun(20, func() {
					if nativeRecordValid(r) {
						t.Fatal("invalid record accepted")
					}
				}); allocs != 0 {
					t.Fatalf("record validator hashed/marshaled invalid field: %v allocations", allocs)
				}
			})
		}
	}
}

func TestNativeReceiptJournalPreflightOrder(t *testing.T) {
	path, tuple, raw := nativeFixture(t, "ordinary")
	oversized := bytes.Repeat([]byte("x"), 4*1024*1024)
	badTuple := tuple
	badTuple.Host = strings.Repeat("x", 4*1024*1024)
	// Independently remove each defect so a single guard cannot hide the other.
	for _, tc := range []struct {
		name     string
		tuple    nativeReceiptTuple
		response []byte
	}{
		{"both", badTuple, oversized},
		{"tuple-only", badTuple, raw},
		{"response-only", tuple, oversized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nativeAssertPreflightRejectsWithoutAllocation(t, path, tc.tuple, tc.response)
			called := false
			_, err := createNativeReceiptJournalWithFault(path, tc.tuple, 7, tc.response, func(string) error {
				called = true
				return errors.New("unexpected copy/digest")
			})
			if err != errNativeJournal || called {
				t.Fatal("preflight did not precede copy/digest")
			}
		})
	}
	// Positive control: the same injected fault must fire for a valid tuple.
	injected := errors.New("stop before copy/digest")
	calls := 0
	_, err := createNativeReceiptJournalWithFault(path, tuple, 7, raw, func(at string) error {
		calls++
		if at != "before_copy_and_digest" {
			t.Fatalf("unexpected boundary %q", at)
		}
		return injected
	})
	if err != injected || calls != 1 {
		t.Fatal("copy/digest fault injection not exercised")
	}
	// Include every remaining tuple field: hash format/length, enum membership,
	// sequence and exact response length must all precede the same boundary.
	badValues := map[string][]string{
		"AuthDigest":      {"", strings.Repeat("a", 65), strings.Repeat("g", 64), strings.Repeat("a", 4*1024*1024)},
		"QueueDigest":     {strings.Repeat("a", 63), strings.Repeat("g", 64)},
		"ResponseDigest":  {strings.Repeat("a", 65), strings.Repeat("g", 64)},
		"CertFingerprint": {strings.Repeat("a", 65), strings.Repeat("g", 64)},
		"TerminalState":   {"", "unknown", string([]byte{0xff}), strings.Repeat("x", 257)},
		"EvidenceKind":    {"", "unknown"},
		"HoldClass":       {"", "invalid", "pending_uncertain"},
		"Disposition":     {"", "invalid", "pending_uncertain"},
	}
	assertReject := func(t *testing.T, bad nativeReceiptTuple) {
		t.Helper()
		called := false
		j, err := createNativeReceiptJournalWithFault(path, bad, 7, raw, func(string) error {
			called = true
			return injected
		})
		if j != nil || err != errNativeJournal || called {
			t.Fatal("malformed tuple reached digest boundary")
		}
		if nativeRecordValid(nativeJournalRecord{Tuple: bad, Response: raw}) {
			t.Fatal("malformed record accepted")
		}
	}
	for field, values := range badValues {
		for i, value := range values {
			t.Run(fmt.Sprintf("%s/%d", field, i), func(t *testing.T) {
				bad := tuple
				reflect.ValueOf(&bad).Elem().FieldByName(field).SetString(value)
				assertReject(t, bad)
			})
		}
	}
	bad := tuple
	bad.Sequence = 0
	assertReject(t, bad)
	bad = tuple
	bad.Length++
	assertReject(t, bad)
	oversizedHash := string(oversized)
	if allocs := testing.AllocsPerRun(20, func() {
		if nativeHash(oversizedHash) {
			t.Fatal("oversized hash accepted")
		}
	}); allocs != 0 {
		t.Fatalf("oversized hash allocated before length check: %v", allocs)
	}
}
