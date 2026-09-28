package certificate

import (
	"os"
	"path/filepath"
	"testing"
)

func binding() Binding {
	return Binding{CandidateID: "agent-1", Address: "192.168.1.20", Port: 7443, ProtocolMajor: 1}
}
func TestGenerateAndVerifyRequest(t *testing.T) {
	r, err := GenerateRequest(binding())
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyRequest(r.CSRPEM, binding()); err != nil {
		t.Fatal(err)
	}
	bad := binding()
	bad.Address = "192.168.1.21"
	if VerifyRequest(r.CSRPEM, bad) == nil {
		t.Fatal("accepted mismatched binding")
	}
}
func TestSecureIdentityStorage(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "identity")
	if err := StoreIdentity(dir, []byte("key"), []byte("cert"), []byte("ca")); err != nil {
		t.Fatal(err)
	}
	k, c, a, err := LoadIdentity(dir)
	if err != nil || string(k) != "key" || string(c) != "cert" || string(a) != "ca" {
		t.Fatalf("load %q %q %q %v", k, c, a, err)
	}
	if err = StoreIdentity(dir, []byte("new"), []byte("new"), []byte("new")); err == nil {
		t.Fatal("overwrote identity")
	}
	if os.Chmod(filepath.Join(dir, "host-key.pem"), 0644) != nil {
		t.Fatal("chmod")
	}
	if _, _, _, err = LoadIdentity(dir); err == nil {
		t.Fatal("accepted insecure key")
	}
}
func TestStorageRejectsSymlinkDirectory(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if os.Mkdir(target, 0700) != nil {
		t.Fatal("mkdir")
	}
	link := filepath.Join(root, "link")
	if os.Symlink(target, link) != nil {
		t.Skip("symlink unavailable")
	}
	if err := StoreIdentity(link, []byte("k"), []byte("c"), []byte("a")); err == nil {
		t.Fatal("accepted symlink")
	}
}
