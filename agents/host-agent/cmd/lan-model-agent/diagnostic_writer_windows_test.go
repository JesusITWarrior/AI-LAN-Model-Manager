//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/privatefile"
)

func diagnosticTestSID(t *testing.T) string {
	t.Helper()
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid, err := user.User.Sid.String()
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

// Synthetic TEMP fixtures only; never inspect or repair an installed state tree.
func diagnosticSetTestACL(t *testing.T, path, sddl string) {
	t.Helper()
	security := syscall.NewLazyDLL("advapi32.dll")
	convert := security.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	set := security.NewProc("SetFileSecurityW")
	input, _ := syscall.UTF16PtrFromString(sddl)
	name, _ := syscall.UTF16PtrFromString(path)
	var descriptor uintptr
	ok, _, err := convert.Call(uintptr(unsafe.Pointer(input)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
	if ok == 0 {
		t.Fatal(err)
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	ok, _, err = set.Call(uintptr(unsafe.Pointer(name)), 4|0x80000000, descriptor)
	if ok == 0 {
		t.Fatal(err)
	}
}

func diagnosticTrustedACL(t *testing.T) string {
	return "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + diagnosticTestSID(t) + ")"
}

func diagnosticTestRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	diagnosticSetTestACL(t, root, diagnosticTrustedACL(t))
	return root
}

func TestDiagnosticWriterWindowsTEMPReplacementAndInheritedDACL(t *testing.T) {
	root := diagnosticTestRoot(t)
	assertNoDiagnosticTemps := func() {
		t.Helper()
		matches, err := filepath.Glob(filepath.Join(root, ".diagnostic-*"))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 0 {
			t.Fatalf("diagnostic temporary files remain: %v", matches)
		}
	}
	for index, raw := range []string{`{"generation":1}`, `{"generation":2}`} {
		if err := saveDiagnostic(root, "command-status.json", []byte(raw)); err != nil {
			t.Fatal(err)
		}
		assertNoDiagnosticTemps()
		f, err := os.Open(filepath.Join(root, "command-status.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := privatefile.Check(f, 0600); err != nil {
			f.Close()
			t.Fatal(err)
		}
		var record struct {
			Generation int `json:"generation"`
		}
		err = json.NewDecoder(f).Decode(&record)
		f.Close()
		if err != nil {
			t.Fatal("invalid replacement", err)
		}
		if record.Generation != index+1 {
			t.Fatalf("replacement generation = %d, want %d", record.Generation, index+1)
		}
	}
	prior, err := os.ReadFile(filepath.Join(root, "command-status.json"))
	if err != nil {
		t.Fatal(err)
	}
	assertPriorPreserved := func() {
		t.Helper()
		current, err := os.ReadFile(filepath.Join(root, "command-status.json"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(current, prior) {
			t.Fatalf("ACL rejection changed prior command status: got %q, want %q", current, prior)
		}
	}
	// Granting Everyone read access to a synthetic directory must fail closed.
	diagnosticSetTestACL(t, root, diagnosticTrustedACL(t)+"(A;OICI;GR;;;WD)")
	if err := saveDiagnostic(root, "command-status.json", []byte(`{}`)); err == nil {
		t.Fatal("Everyone-readable directory accepted")
	}
	assertNoDiagnosticTemps()
	assertPriorPreserved()
	// A private leaf whose children inherit Everyone access must also fail the
	// tempfile Check. Chmod is not an ACL repair and must not make this pass.
	diagnosticSetTestACL(t, root, diagnosticTrustedACL(t)+"(A;OICIIO;GR;;;WD)")
	if err := privatefile.Directory(root); err != nil {
		t.Fatal("inherit-only fixture rejected at directory", err)
	}
	if err := saveDiagnostic(root, "inventory-status.json", []byte(`{}`)); err == nil {
		t.Fatal("Everyone-readable inherited temporary file accepted")
	}
	assertNoDiagnosticTemps()
	assertPriorPreserved()
	if _, err := os.Stat(filepath.Join(root, "inventory-status.json")); !os.IsNotExist(err) {
		t.Fatal("failed tempfile validation published a target", err)
	}
}
