//go:build linux

package service

import (
	"os"
	"path/filepath"
	"strings"
)

// directoryMode is the mode applied to every directory the service creates.
func directoryMode() os.FileMode { return 0o700 }

// ensureContainment walks directory p and creates any missing components so the
// canonical state tree (state/cert/cache/runtime) exists with restrictive
// permissions where supported. Every component resolves through no symlink and
// contains no ".."; a symlink anywhere along the path is a breach. A redacted
// containment sentinel is returned on any breach.
func ensureContainment(directory string) error {
	if directory == "" || strings.ContainsRune(directory, '\x00') || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return ErrStateContainment
	}
	volume := filepath.VolumeName(directory)
	current := volume + string(filepath.Separator)
	rest := strings.TrimPrefix(directory, current)
	for _, component := range strings.Split(rest, string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return ErrStateContainment
			}
			continue
		}
		if !os.IsNotExist(err) {
			return ErrStateContainment
		}
		if err := os.Mkdir(current, directoryMode()); err != nil {
			return ErrStateContainment
		}
	}
	return nil
}

// errorContainment returns a redacted containment sentinel so callers never
// see the filesystem internals that justified rejection.
func errorContainment(_ string) error { return ErrStateContainment }
