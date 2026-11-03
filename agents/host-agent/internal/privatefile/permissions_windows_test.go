//go:build windows

package privatefile

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"
)

func setTestACL(t *testing.T, path, sddl string) {
	t.Helper()
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
func TestWindowsDACLNotPOSIXMode(t *testing.T) {
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
	root := t.TempDir()
	trusted := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + sid + ")"
	setTestACL(t, root, trusted)
	if err := Directory(root); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "key")
	if err := os.WriteFile(path, []byte("fixture-not-a-key"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, _ := f.Stat()
	if info.Mode().Perm() == 0600 {
		t.Fatal("fixture did not expose native Windows mode semantics")
	}
	if err := Check(f, 0600); err != nil {
		t.Fatal("protected native Windows key rejected", err)
	}
	setTestACL(t, path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;"+sid+")(A;;GR;;;WD)")
	if Check(f, 0600) == nil {
		t.Fatal("Everyone-readable key accepted")
	}
	setTestACL(t, path, trusted)
	setTestACL(t, root, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;"+sid+")(A;OICI;GR;;;WD)")
	if Directory(root) == nil {
		t.Fatal("Everyone-readable private directory accepted")
	}
}
