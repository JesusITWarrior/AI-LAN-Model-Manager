//go:build !windows

package command

import "os"

// Keep the directory fsync on Unix: file Sync alone does not persist the
// replacement's directory entry. Unsupported fsync remains an explicit error.
func finishReplayPublication(directory string) error {
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
