//go:build !windows

// Package privatefile contains the shared POSIX permission-mode contract tested
// on Linux and selected-on-Darwin. These tests exercise the current, Linux
// runnable implementation directly and change no production files.

package privatefile

import (
	"os"
	"path/filepath"
	"testing"
)

// privateParent returns a unique, private (0700) directory for a per-test file.
func privateParent(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestCheckAcceptsExactMode: Check accepts a temp file at the exact requested mode.
func TestCheckAcceptsExactMode(t *testing.T) {
	dir := privateParent(t)
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte("fixture-not-a-key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := Check(f, 0600); err != nil {
		t.Fatalf("Check rejected a file at the exact requested mode: %v", err)
	}
}

// TestCheckRejectsModeMismatch: Check rejects with ErrPermissions when the
// requested mode differs from the file's real mode.
//
// The fixture is a private 0600 file; requesting 0777 must be rejected.
func TestCheckRejectsModeMismatch(t *testing.T) {
	dir := privateParent(t)
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte("fixture-not-a-key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	const requested os.FileMode = 0777
	checkErr := Check(f, requested)
	if checkErr == nil {
		t.Fatalf("Check accepted a 0600 file when requested mode was %04o", requested)
	}
	if checkErr != ErrPermissions {
		t.Fatalf("expected ErrPermissions, got %v", checkErr)
	}
}

// TestDirectoryAcceptsPrivateDir: Directory accepts a private (0700) temp directory.
func TestDirectoryAcceptsPrivateDir(t *testing.T) {
	root := t.TempDir()
	if err := Directory(root); err != nil {
		t.Fatalf("Directory rejected a private directory: %v", err)
	}
}

// TestDirectoryRejectsGroupWorldWritable: Directory rejects group/world-writable modes.
func TestDirectoryRejectsGroupWorldWritable(t *testing.T) {
	grp := t.TempDir()
	if err := os.Chmod(grp, 0773); err != nil { // 0020 group-writable
		t.Fatal(err)
	}
	if err := Directory(grp); err == nil {
		t.Fatal("Directory accepted a group-writable directory")
	} else if err != ErrPermissions {
		t.Fatalf("expected ErrPermissions for group-writable dir, got %v", err)
	}

	world := t.TempDir()
	if err := os.Chmod(world, 0707); err != nil { // 0002 world-writable
		t.Fatal(err)
	}
	if err := Directory(world); err == nil {
		t.Fatal("Directory accepted a world-writable directory")
	} else if err != ErrPermissions {
		t.Fatalf("expected ErrPermissions for world-writable dir, got %v", err)
	}
}
