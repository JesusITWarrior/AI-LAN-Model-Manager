package command

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
)

// replayPersistenceError distinguishes publication from durability. Publication
// means replacement returned success; a later finish failure cannot undo it.
// Do not expose raw filesystem paths/errors through command diagnostics.
type replayPersistenceError struct{ published bool }

func (*replayPersistenceError) Error() string { return ErrReplayPersistence.Error() }
func (*replayPersistenceError) Unwrap() error { return ErrReplayPersistence }

func (e *Executor) persist() error {
	if e.persistenceErr != nil {
		return e.persistenceErr
	}
	if e.store == "" {
		return nil
	}
	raw, err := json.Marshal(e.seen)
	published := false
	if err == nil && len(raw) <= maxReplayStoreBytes {
		write := e.writeReplay
		if write == nil {
			write = writeReplayStore
		}
		published, err = write(e.store, append(raw, '\n'))
	} else {
		err = ErrReplayPersistence
	}
	if err != nil {
		e.persistenceErr = &replayPersistenceError{published: published}
		slog.Info("command-stage", "code", "REPLAY_PERSIST_FAILED", "httpStatus", 0)
		return e.persistenceErr
	}
	return nil
}

func writeReplayStore(path string, raw []byte) (bool, error) {
	return writeReplayStoreWithFinish(path, raw, finishReplayPublication)
}

// The finish argument allows tests to fail immediately after real replacement.
// There is deliberately no rollback of the target after publication.
func writeReplayStoreWithFinish(path string, raw []byte, finish func(string) error) (published bool, err error) {
	directory := filepath.Dir(path)
	if err = os.MkdirAll(directory, 0o700); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(directory, ".command-replay-")
	if err != nil {
		return false, err
	}
	name := tmp.Name()
	defer func() {
		_ = tmp.Close()
		if !published {
			_ = os.Remove(name)
		}
	}()
	if err = tmp.Chmod(0o600); err != nil {
		return false, err
	}
	if _, err = tmp.Write(raw); err != nil {
		return false, err
	}
	if err = tmp.Sync(); err != nil {
		return false, err
	}
	if err = tmp.Close(); err != nil {
		return false, err
	}
	if err = os.Rename(name, path); err != nil {
		return false, err
	}
	return true, finish(directory)
}
