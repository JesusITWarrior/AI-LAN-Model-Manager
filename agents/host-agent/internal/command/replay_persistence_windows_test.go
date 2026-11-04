//go:build windows

package command

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Native qualification only: real writable file flush, close, first publication
// and replacement in t.TempDir, under the invoking account's existing temp ACLs.
// This neither changes ACLs nor qualifies installed SCM replay-directory DACLs.
func TestWindowsReplayPersistenceTempCreateReplaceAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.json")
	a := &adapter{fail: true}
	e, err := NewPersistent("host-1", a, replayClock, path)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"first", "replacement"} {
		response, err := e.Execute(context.Background(), freshReplayRequest(key))
		if err != nil || response.ErrorCode == nil || *response.ErrorCode != "ADAPTER_FAILED" {
			t.Fatal(response, err)
		}
	}
	if e.persistenceErr != nil || a.calls != 2 {
		t.Fatal("supported persistence failed", e.persistenceErr, a.calls)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var disk map[string]entry
	if err := json.Unmarshal(raw, &disk); err != nil || len(disk) != 2 {
		t.Fatal("replacement lost entries", err)
	}
	replayAdapter := &adapter{}
	reopened, err := NewPersistent("host-1", replayAdapter, replayClock, path)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"first", "replacement"} {
		response, err := reopened.Execute(context.Background(), freshReplayRequest(key))
		if err != nil || response.ErrorCode == nil || *response.ErrorCode != "ADAPTER_FAILED" {
			t.Fatal(response, err)
		}
	}
	if replayAdapter.calls != 0 {
		t.Fatal("replay executed adapter", replayAdapter.calls)
	}
	leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".command-replay-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatal("temp leaked", leftovers, err)
	}
}
