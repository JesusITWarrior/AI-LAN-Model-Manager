//go:build windows

package command

// Windows publication uses the writable temp file's Sync (FlushFileBuffers),
// Close, then os.Rename (Go's MoveFileEx with MOVEFILE_REPLACE_EXISTING). Do not
// FlushFileBuffers an os.Open directory: that read-only handle lacks the
// GENERIC_WRITE access required by the API. No ACL or privilege changes apply.
//
// Successful return guarantees the file flush and replacement APIs completed,
// NOT Unix-style directory fsync durability, atomic replacement on all Windows
// filesystems, or survival of namespace changes across sudden power loss.
func finishReplayPublication(_ string) error { return nil }
