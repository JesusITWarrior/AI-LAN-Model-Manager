package snapshot

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validState(t *testing.T) State {
	t.Helper()
	s, err := New(Record{
		HostID: "host-1", Platform: "linux", NAccelerators: 1,
		ObservedAt: "2026-09-29T12:00:00Z", ProvidersHealthy: 2, ProvidersFailed: 1,
	}, time.Date(2026, 9, 29, 12, 0, 1, 0, time.UTC))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestSaveReadExactAndPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "snapshot")
	store := FileStore{Dir: dir}
	want := validState(t)
	if err := store.Save(context.Background(), want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, err := os.ReadFile(Path(dir))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	exact := `{"version":1,"savedAt":"2026-09-29T12:00:01Z","record":{"hostId":"host-1","platform":"linux","accelerators":1,"observedAt":"2026-09-29T12:00:00Z","safeErr":"","providersHealthy":2,"providersFailed":1}}` + "\n"
	if string(raw) != exact {
		t.Fatalf("wire mismatch\n got: %s\nwant: %s", raw, exact)
	}
	info, err := os.Stat(Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	got, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Fresh {
		t.Fatal("disk-loaded state must be stale")
	}
	if got.Record != want.Record || got.SavedAt != want.SavedAt {
		t.Fatalf("round trip = %+v", got)
	}
}

func TestLoadCleansCrashTemps(t *testing.T) {
	dir := t.TempDir()
	store := FileStore{Dir: dir}
	if err := store.Save(context.Background(), validState(t)); err != nil {
		t.Fatal(err)
	}
	temp := filepath.Join(dir, ".observation-snapshot.json.tmp-abandoned")
	if err := os.WriteFile(temp, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(temp); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temp remains: %v", err)
	}
}

func TestCorruptionQuarantinedAndNotReplayed(t *testing.T) {
	dir := t.TempDir()
	store := FileStore{Dir: dir}
	if err := os.WriteFile(Path(dir), []byte(`{"version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background()); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Load = %v", err)
	}
	if _, err := os.Stat(Path(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("primary still present: %v", err)
	}
	info, err := os.Stat(QuarantinePath(dir))
	if err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("quarantine mode = %o", info.Mode().Perm())
	}
	if _, err := store.Load(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replay Load = %v", err)
	}
}

func TestOversizeQuarantinedWithBoundedRead(t *testing.T) {
	dir := t.TempDir()
	store := FileStore{Dir: dir}
	if err := os.WriteFile(Path(dir), make([]byte, MaxBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background()); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Load = %v", err)
	}
	if info, err := os.Stat(QuarantinePath(dir)); err != nil || info.Size() != MaxBytes+1 {
		t.Fatalf("quarantine size/info = %v, %v", info, err)
	}
}

func TestExactDecoderRejectsDuplicateUnknownAndMissingKeys(t *testing.T) {
	valid := `{"version":1,"savedAt":"2026-09-29T12:00:01Z","record":{"hostId":"host-1","platform":"linux","accelerators":1,"observedAt":"2026-09-29T12:00:00Z","safeErr":"","providersHealthy":2,"providersFailed":1}}`
	cases := map[string]string{
		"duplicate top":    strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1),
		"duplicate nested": strings.Replace(valid, `"hostId":"host-1"`, `"hostId":"host-1","hostId":"host-2"`, 1),
		"unknown":          strings.Replace(valid, `"savedAt"`, `"extra":0,"savedAt"`, 1),
		"missing":          strings.Replace(valid, `,"savedAt":"2026-09-29T12:00:01Z"`, ``, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeExact([]byte(raw)); err == nil {
				t.Fatal("accepted invalid JSON")
			}
		})
	}
}

func TestFailedSavePreservesPrimary(t *testing.T) {
	dir := t.TempDir()
	store := FileStore{Dir: dir}
	original := validState(t)
	if err := store.Save(context.Background(), original); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(Path(dir))
	invalid := original
	invalid.Record.Platform = "plan9"
	if err := store.Save(context.Background(), invalid); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Save invalid = %v", err)
	}
	after, _ := os.ReadFile(Path(dir))
	if string(after) != string(before) {
		t.Fatal("failed save replaced primary")
	}
}

func TestPreRenameFailurePreservesPrimaryAndCleansTemp(t *testing.T) {
	dir := t.TempDir()
	store := FileStore{Dir: dir}
	original := validState(t)
	if err := store.Save(context.Background(), original); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(Path(dir))
	store.beforeRename = func() error { return errors.New("injected sync boundary failure") }
	changed := original
	changed.Record.ProvidersHealthy = 8
	if err := store.Save(context.Background(), changed); err == nil {
		t.Fatal("injected pre-rename failure succeeded")
	}
	after, _ := os.ReadFile(Path(dir))
	if string(after) != string(before) {
		t.Fatal("pre-rename failure replaced primary")
	}
	matches, _ := filepath.Glob(filepath.Join(dir, tempPattern))
	if len(matches) != 0 {
		t.Fatalf("temps remain: %v", matches)
	}
}

func TestCancelledSavePreservesPrimaryAndCreatesNothing(t *testing.T) {
	dir := t.TempDir()
	store := FileStore{Dir: dir}
	original := validState(t)
	if err := store.Save(context.Background(), original); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(Path(dir))
	ctx, cancel := context.WithCancel(context.Background())
	store.beforeRename = func() error { cancel(); return nil }
	changed := original
	changed.Record.ProvidersHealthy = 9
	if err := store.Save(ctx, changed); !errors.Is(err, context.Canceled) {
		t.Fatalf("Save cancelled = %v", err)
	}
	after, _ := os.ReadFile(Path(dir))
	if string(after) != string(before) {
		t.Fatal("cancelled save replaced primary")
	}
	matches, _ := filepath.Glob(filepath.Join(dir, tempPattern))
	if len(matches) != 0 {
		t.Fatalf("temps remain: %v", matches)
	}
}
