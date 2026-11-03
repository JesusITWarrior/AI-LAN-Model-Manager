// Package privatefile checks private file permissions without confusing Windows
// DOS read-only bits with access control. Windows uses the opened handle's DACL.
package privatefile

import (
	"errors"
	"os"
	"path/filepath"
)

var ErrPermissions = errors.New("private file permissions rejected")

// Directory rejects link/reparse traversal before checking the leaf's ACL.
// Callers must check it before creating any secret beneath it.
func Directory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrPermissions
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrPermissions
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	before, err := os.Lstat(path)
	if err != nil {
		return ErrPermissions
	}
	f, err := os.Open(path)
	if err != nil {
		return ErrPermissions
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return ErrPermissions
	}
	return checkDirectory(f)
}
