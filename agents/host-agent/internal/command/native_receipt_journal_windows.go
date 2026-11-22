package command

import (
	"os"
	"path/filepath"
	"syscall"
)

// Reject ALL reparse points, including junctions in ancestors. ACL validation is
// performed separately using privatefile on the opened directory/file handles.
func nativeJournalPlatformPath(path string) error {
	for p := path; ; p = filepath.Dir(p) {
		ptr, err := syscall.UTF16PtrFromString(p)
		if err != nil {
			return errNativeJournal
		}
		attrs, err := syscall.GetFileAttributes(ptr)
		if err != nil {
			if p != path || !os.IsNotExist(err) {
				return errNativeJournal
			}
		} else if attrs&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errNativeJournal
		}
		if filepath.Dir(p) == p {
			return nil
		}
	}
}

// File Sync (FlushFileBuffers), Close and os.Rename (MoveFileEx replacement)
// have completed. This is NOT a claim of directory fsync, atomic replacement on
// every filesystem, or survival of namespace changes after sudden power loss.
func finishNativeJournalPublication(_ string) error { return nil }
