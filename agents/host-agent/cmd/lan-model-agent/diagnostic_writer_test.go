package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestDiagnosticWriterAcceptsOnlyFixedStatusNames(t *testing.T) {
	root := diagnosticTestRoot(t)
	for _, name := range []string{"enrollment-status.json", "inventory-status.json", "command-status.json"} {
		for _, raw := range [][]byte{[]byte(`{"stage":"first"}`), []byte(`{"stage":"replaced"}`)} {
			if err := saveDiagnostic(root, name, raw); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			got, err := os.ReadFile(filepath.Join(root, name))
			if err != nil || !bytes.Equal(got, append(append([]byte(nil), raw...), '\n')) {
				t.Fatalf("%s: unexpected replacement %q, %v", name, got, err)
			}
		}
	}
	before, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", ".", "diagnostic.json", "COMMAND-status.json", "command-status.json/child", "../command-status.json", filepath.Join(root, "absolute.json"), filepath.Join(root, "command-status.json"), `..\command-status.json`} {
		if err := saveDiagnostic(root, name, []byte(`{}`)); err == nil {
			t.Errorf("unlisted target accepted: %q", name)
		}
	}
	after, err := os.ReadDir(root)
	if err != nil || len(before) != len(after) {
		t.Fatalf("rejected target created files: %v", err)
	}
}

func TestDiagnosticWriterByteBoundAndJSONValidationBeforeCreation(t *testing.T) {
	root := diagnosticTestRoot(t)
	const name = "command-status.json"
	// A JSON string of 16KiB-1 bytes plus exactly one newline is accepted.
	boundary := append([]byte{'"'}, bytes.Repeat([]byte{'x'}, 16*1024-3)...)
	boundary = append(boundary, '"')
	if len(boundary) != 16*1024-1 {
		t.Fatal("bad boundary fixture")
	}
	if err := saveDiagnostic(root, name, boundary); err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(filepath.Join(root, name))
	if err != nil || len(old) != 16*1024 || !json.Valid(old) {
		t.Fatal("boundary record invalid", err)
	}
	tooLarge := append([]byte{'"'}, bytes.Repeat([]byte{'x'}, 16*1024-2)...)
	tooLarge = append(tooLarge, '"')
	for _, raw := range [][]byte{nil, {}, []byte("not json"), []byte(`{"partial":`), []byte(`{} {}`), {0xff}, tooLarge} {
		if err := saveDiagnostic(root, name, raw); err == nil {
			t.Errorf("invalid/oversize payload accepted: length=%d", len(raw))
		}
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || !bytes.Equal(got, old) {
			t.Fatal("rejected input changed old record", err)
		}
		entries, err := os.ReadDir(root)
		if err != nil || len(entries) != 1 {
			t.Fatal("rejected input created temporary file", err)
		}
		// Invalid input is rejected before even attempting to create a temporary file.
		if err := saveDiagnostic(filepath.Join(root, "missing"), name, raw); err == nil || err.Error() != "enrollment diagnostic failed" {
			t.Fatalf("validation did not precede filesystem access: %v", err)
		}
	}
}

func TestDiagnosticWriterRenameFailureCleansTemporaryAndPreservesTarget(t *testing.T) {
	root := diagnosticTestRoot(t)
	target := filepath.Join(root, "inventory-status.json")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(target, "previous-record")
	if err := os.WriteFile(marker, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := saveDiagnostic(root, "inventory-status.json", []byte(`{"next":true}`)); err == nil {
		t.Fatal("directory replacement accepted")
	}
	got, err := os.ReadFile(marker)
	if err != nil || string(got) != "unchanged" {
		t.Fatal("failed replacement damaged target", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 {
		t.Fatal("failed replacement leaked temporary file", err)
	}
}

func TestDiagnosticWriterAtomicJSONReplacement(t *testing.T) {
	root := diagnosticTestRoot(t)
	const name = "command-status.json"
	if err := saveDiagnostic(root, name, []byte(`{"generation":0}`)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	failures := make(chan error, 3)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			raw, err := os.ReadFile(filepath.Join(root, name))
			if err != nil || !json.Valid(raw) || len(raw) > 16*1024 {
				failures <- fmt.Errorf("partial replacement: %q, %v", raw, err)
				return
			}
		}
	}()
	var writers sync.WaitGroup
	for worker := 0; worker < 2; worker++ {
		writers.Add(1)
		go func(worker int) {
			defer writers.Done()
			for generation := 1; generation <= 24; generation++ {
				raw := []byte(fmt.Sprintf(`{"generation":%d,"worker":%d,"padding":"%s"}`, generation, worker, bytes.Repeat([]byte{'x'}, 1024)))
				if err := saveDiagnostic(root, name, raw); err != nil {
					failures <- err
					return
				}
			}
		}(worker)
	}
	writers.Wait()
	close(stop)
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 {
		t.Fatal("temporary files retained", err)
	}
}
