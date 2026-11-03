//go:build windows

package privatefile

import (
	"os"
	"syscall"
	"unsafe"
)

var security = syscall.NewLazyDLL("advapi32.dll")
var getSecurityInfo = security.NewProc("GetSecurityInfo")
var getAce = security.NewProc("GetAce")

type aclHeader struct {
	Revision, Reserved     byte
	Size, Count, Reserved2 uint16
}
type aceHeader struct {
	Type, Flags byte
	Size        uint16
}

// Check accepts only SYSTEM, built-in Administrators, the process account and
// the installed agent's virtual account as owners or allowed ACE trustees.
// A missing/null DACL, unsupported ACE, or untrusted allow fails closed. It
// never rewrites an existing ACL or treats chmod(0600) as Windows protection.
func Check(file *os.File, _ os.FileMode) error {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return ErrPermissions
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return ErrPermissions
	}
	userSID, err := user.User.Sid.String()
	if err != nil {
		return ErrPermissions
	}
	allowed := map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true, userSID: true}
	if sid, _, _, err := syscall.LookupSID("", `NT SERVICE\LANModelAgent`); err == nil {
		if value, err := sid.String(); err == nil {
			allowed[value] = true
		}
	}
	var owner *syscall.SID
	var dacl *aclHeader
	var descriptor uintptr
	result, _, _ := getSecurityInfo.Call(file.Fd(), 1, 5, uintptr(unsafe.Pointer(&owner)), 0, uintptr(unsafe.Pointer(&dacl)), 0, uintptr(unsafe.Pointer(&descriptor)))
	if result != 0 {
		return ErrPermissions
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	if owner == nil || dacl == nil {
		return ErrPermissions
	}
	ownerSID, err := owner.String()
	if err != nil || !allowed[ownerSID] {
		return ErrPermissions
	}
	for i := uint16(0); i < dacl.Count; i++ {
		var ace *aceHeader
		ok, _, _ := getAce.Call(uintptr(unsafe.Pointer(dacl)), uintptr(i), uintptr(unsafe.Pointer(&ace)))
		if ok == 0 || ace == nil || ace.Size < 16 {
			return ErrPermissions
		}
		// INHERIT_ONLY does not grant access to this object.
		if ace.Flags&8 != 0 {
			continue
		}
		if ace.Type == 1 {
			continue
		} // ACCESS_DENIED_ACE only restricts access.
		if ace.Type != 0 {
			return ErrPermissions
		}
		sid := (*syscall.SID)(unsafe.Add(unsafe.Pointer(ace), 8))
		trustee, err := sid.String()
		if err != nil || !allowed[trustee] {
			return ErrPermissions
		}
	}
	return nil
}

func checkDirectory(file *os.File) error { return Check(file, 0700) }
