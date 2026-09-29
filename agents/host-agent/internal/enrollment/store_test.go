package enrollment

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileStorePreservesCommittedStateOnFailedWrite(t *testing.T) {
	cfg, _, result, _ := fixture(t)
	store := FileStore{CertDir: cfg.CertDir}
	if err := store.Save(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	oversize := result
	oversize.CertificatePEM = strings.Repeat("x", maxState)
	if err := store.Save(context.Background(), oversize); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("oversize: %v", err)
	}
	loaded, err := store.Load(context.Background())
	if err != nil || loaded.ChallengeID != result.ChallengeID {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	raw, err := os.ReadFile(filepath.Join(cfg.CertDir, stateName))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"23456789", "privateKey", "proof"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("persisted forbidden %q", forbidden)
		}
	}
}

func TestFileStoreStrictJSONAndCorruptionQuarantine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, stateName)
	if err := os.WriteFile(path, []byte(`{"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	store := FileStore{CertDir: dir}
	if _, err := store.Load(context.Background()); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("load: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("original remains: %v", err)
	}
	matches, err := filepath.Glob(path + ".corrupt-*")
	if err != nil || len(matches) != 1 {
		t.Fatalf("quarantine=%v err=%v", matches, err)
	}
}
