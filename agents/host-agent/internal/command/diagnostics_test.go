package command

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReplayPersistenceDiagnosticDoesNotExposePathOrError(t *testing.T) {
	var output bytes.Buffer
	prior := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	defer slog.SetDefault(prior)
	// A directory cannot be replaced by the replay file; the failure is entirely
	// inside a synthetic temp directory and requires no permission manipulation.
	executor := New("synthetic-host", &adapter{}, nil)
	executor.store = filepath.Join(t.TempDir(), "private-model-prompt-path", "replay.json")
	// The existing directory itself is the replay target, forcing rename failure.
	executor.store = filepath.Dir(executor.store)
	if err := os.MkdirAll(executor.store, 0700); err != nil {
		t.Fatal(err)
	}
	if executor.persist() == nil {
		t.Fatal("expected persistence failure")
	}
	text := output.String()
	if !strings.Contains(text, "REPLAY_PERSIST_FAILED") {
		t.Fatal("missing fixed stage")
	}
	for _, secret := range []string{executor.store, "private-model-prompt-path", "synthetic-host", "rename", "permission"} {
		if strings.Contains(text, secret) {
			t.Fatal("private persistence detail escaped")
		}
	}
}
