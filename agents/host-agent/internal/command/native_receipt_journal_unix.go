//go:build !windows

package command

import "os"

func nativeJournalPlatformPath(_ string) error { return nil }

func finishNativeJournalPublication(directory string) error {
	d, err := os.Open(directory)
	if err != nil {
		return err
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
