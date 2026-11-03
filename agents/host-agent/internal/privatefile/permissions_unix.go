//go:build !windows

package privatefile

import "os"

func Check(file *os.File, mode os.FileMode) error {
	info, err := file.Stat()
	if err != nil || info.Mode().Perm() != mode {
		return ErrPermissions
	}
	return nil
}

func checkDirectory(file *os.File) error {
	info, err := file.Stat()
	if err != nil || info.Mode().Perm()&0022 != 0 {
		return ErrPermissions
	}
	return nil
}
