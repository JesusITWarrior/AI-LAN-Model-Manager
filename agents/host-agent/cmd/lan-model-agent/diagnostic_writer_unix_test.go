//go:build !windows

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func diagnosticTestRoot(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

func TestDiagnosticWriterUnixPrivateModeAndLinkTraversal(t *testing.T) {
	root := t.TempDir()
	protected := filepath.Join(root, "protected")
	if err := os.Mkdir(protected, 0700); err != nil {
		t.Fatal(err)
	}
	const name = "command-status.json"
	if err := saveDiagnostic(protected, name, []byte(`{"private":true}`)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(protected, name))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("status file is not private", err)
	}
	if err := os.Mkdir(filepath.Join(protected, "child"), 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(protected, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, filepath.Join(link, "child"), "relative-state-tree"} {
		if err := saveDiagnostic(path, name, []byte(`{}`)); err == nil {
			t.Errorf("unsafe state path accepted: %s", path)
		}
	}
	if err := os.Chmod(protected, 0770); err != nil {
		t.Fatal(err)
	}
	if err := saveDiagnostic(protected, name, []byte(`{}`)); err == nil {
		t.Fatal("group-writable state directory accepted")
	}
}

func TestDiagnosticWriterUnixWriteFailurePreservesOldRecord(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}
	root := t.TempDir()
	const name = "enrollment-status.json"
	raw := []byte(`{"previous":"intact"}`)
	if err := saveDiagnostic(root, name, raw); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(root, 0700)
	if err := saveDiagnostic(root, name, []byte(`{"replacement":true}`)); err == nil {
		t.Fatal("read-only directory accepted a replacement")
	}
	got, err := os.ReadFile(filepath.Join(root, name))
	if err != nil || !bytes.Equal(got, append(raw, '\n')) {
		t.Fatal("write failure damaged old record", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 {
		t.Fatal("failed write left temporary file", err)
	}
}
