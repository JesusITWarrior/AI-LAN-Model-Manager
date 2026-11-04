//go:build windows

package main

import (
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
	for _, raw := range []string{`{"generation":1}`, `{"generation":2}`} {
		if err := saveDiagnostic(root, "command-status.json", []byte(raw)); err != nil {
			t.Fatal(err)
		}
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
		if err != nil || record.Generation == 0 {
			t.Fatal("invalid replacement", err)
		}
	}
	// Granting Everyone read access to a synthetic directory must fail closed.
	diagnosticSetTestACL(t, root, diagnosticTrustedACL(t)+"(A;OICI;GR;;;WD)")
	if err := saveDiagnostic(root, "command-status.json", []byte(`{}`)); err == nil {
		t.Fatal("Everyone-readable directory accepted")
	}
	// A private leaf whose children inherit Everyone access must also fail the
	// tempfile Check. Chmod is not an ACL repair and must not make this pass.
	diagnosticSetTestACL(t, root, diagnosticTrustedACL(t)+"(A;OICIIO;GR;;;WD)")
	if err := privatefile.Directory(root); err != nil {
		t.Fatal("inherit-only fixture rejected at directory", err)
	}
	if err := saveDiagnostic(root, "inventory-status.json", []byte(`{}`)); err == nil {
		t.Fatal("Everyone-readable inherited temporary file accepted")
	}
	if _, err := os.Stat(filepath.Join(root, "inventory-status.json")); !os.IsNotExist(err) {
		t.Fatal("failed tempfile validation published a target", err)
	}
}
