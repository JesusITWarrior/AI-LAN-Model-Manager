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

type quarantineReader struct {
	*strings.Reader
	closed   bool
	closeErr error
}

func (r *quarantineReader) Close() error { r.closed = true; return r.closeErr }

func TestCorruptStateClosedBeforeQuarantine(t *testing.T) {
	for _, raw := range []string{"", `{"unknown":true}`, `{} {}`, strings.Repeat("x", maxState+1)} {
		reader := &quarantineReader{Reader: strings.NewReader(raw)}
		calls := 0
		_, err := loadEnrollmentState(reader, "not-a-real-state-path", func(string) error {
			calls++
			if !reader.closed {
				t.Fatal("rename attempted with live handle")
			}
			return ErrCorrupt
		})
		if !errors.Is(err, ErrCorrupt) || calls != 1 || !reader.closed {
			t.Fatalf("unexpected corruption result: %v", err)
		}
	}
}
func TestStateCloseAndQuarantineFailuresAreTerminalAndRedacted(t *testing.T) {
	reader := &quarantineReader{Reader: strings.NewReader("bad"), closeErr: errors.New("secret path")}
	_, err := loadEnrollmentState(reader, "secret path", func(string) error { t.Fatal("quarantine after failed close"); return nil })
	if err != ErrStateClose || strings.Contains(err.Error(), "secret") {
		t.Fatal("unbounded close failure")
	}
	reader = &quarantineReader{Reader: strings.NewReader("bad")}
	_, err = loadEnrollmentState(reader, "secret path", func(string) error { return ErrQuarantine })
	if err != ErrQuarantine || errors.Is(err, ErrCorrupt) {
		t.Fatal("failed quarantine treated as recoverable")
	}
	dir := t.TempDir()
	store := FileStore{CertDir: dir}
	if err := store.quarantine(filepath.Join(dir, "absent-secret")); err != ErrQuarantine {
		t.Fatalf("rename failure hidden: %v", err)
	}
	cfg, _, _, transport := fixture(t)
	if _, err := New(cfg, transport, terminalStateStore{}); !errors.Is(err, ErrUnavailable) || transport.begins != 0 {
		t.Fatal("quarantine failure allowed enrollment")
	}
}

type terminalStateStore struct{}

func (terminalStateStore) Load(context.Context) (Result, error) { return Result{}, ErrQuarantine }
func (terminalStateStore) Save(context.Context, Result) error   { return nil }
