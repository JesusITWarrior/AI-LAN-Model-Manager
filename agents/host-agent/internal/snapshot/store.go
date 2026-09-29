// Package snapshot provides bounded, exact, atomic persistence for the host
// service's public observation summary. It never stores provider endpoints,
// credentials, or provider-specific payloads.
package snapshot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const (
	Version     = 1
	MaxBytes    = 1 << 20
	fileName    = "observation-snapshot.json"
	quarantine  = "observation-snapshot.corrupt"
	tempPattern = ".observation-snapshot.json.tmp-*"
)

var (
	ErrNotFound = errors.New("snapshot not found")
	ErrCorrupt  = errors.New("snapshot corrupt")
	ErrInvalid  = errors.New("invalid snapshot")
	ErrTooLarge = errors.New("snapshot exceeds maximum size")
)

// Record is the public, provider-neutral observation persisted between starts.
// SafeErr is already redacted by service; Err and all provider details are
// intentionally absent.
type Record struct {
	HostID           string `json:"hostId"`
	Platform         string `json:"platform"`
	NAccelerators    int    `json:"accelerators"`
	ObservedAt       string `json:"observedAt"`
	SafeErr          string `json:"safeErr"`
	ProvidersHealthy int    `json:"providersHealthy"`
	ProvidersFailed  int    `json:"providersFailed"`
}

// State is a validated snapshot. Fresh is runtime-only: a newly observed state
// is fresh, while every state loaded from disk is explicitly stale.
type State struct {
	Version int    `json:"version"`
	SavedAt string `json:"savedAt"`
	Record  Record `json:"record"`
	Fresh   bool   `json:"-"`
}

// New validates record and constructs a fresh state with a canonical UTC time.
func New(record Record, now time.Time) (State, error) {
	s := State{Version: Version, SavedAt: canonicalTime(now), Record: record, Fresh: true}
	if err := s.validate(); err != nil {
		return State{}, err
	}
	return s, nil
}

func canonicalTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

var hostID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func validUTC(value string) bool {
	if value == "" || !strings.HasSuffix(value, "Z") {
		return false
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && t.Location() == time.UTC
}

// Valid reports whether every persisted field satisfies the current version's
// structural and semantic constraints.
func (s State) Valid() bool { return s.validate() == nil }

func (s State) validate() error {
	if s.Version != Version || !validUTC(s.SavedAt) || !hostID.MatchString(s.Record.HostID) ||
		!validUTC(s.Record.ObservedAt) || s.Record.NAccelerators < 0 || s.Record.NAccelerators > 32 ||
		s.Record.ProvidersHealthy < 0 || s.Record.ProvidersFailed < 0 ||
		s.Record.ProvidersHealthy+s.Record.ProvidersFailed > 1024 || len(s.Record.SafeErr) > 128 {
		return ErrInvalid
	}
	switch s.Record.Platform {
	case "linux", "darwin", "windows":
	default:
		return ErrInvalid
	}
	for _, r := range s.Record.SafeErr {
		if r < 0x20 || r == 0x7f {
			return ErrInvalid
		}
	}
	return nil
}

// FileStore persists one snapshot in Dir. Its zero value is invalid.
type FileStore struct {
	Dir string

	// beforeRename is a package-test fault injection point. Production stores
	// leave it nil.
	beforeRename func() error
}

func Path(dir string) string           { return filepath.Join(dir, fileName) }
func QuarantinePath(dir string) string { return filepath.Join(dir, quarantine) }

// Save validates before touching disk, then writes a unique private temporary
// file in the destination directory, syncs it, and atomically renames it over
// the primary. Every pre-rename failure preserves the previous primary.
func (s FileStore) Save(ctx context.Context, state State) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := state.validate(); err != nil {
		return err
	}
	wire := state
	wire.Fresh = false
	raw, err := json.Marshal(wire)
	if err != nil {
		return ErrInvalid
	}
	raw = append(raw, '\n')
	if len(raw) > MaxBytes {
		return ErrTooLarge
	}
	if s.Dir == "" {
		return ErrInvalid
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("save snapshot: %w", err)
	}
	if err := os.Chmod(s.Dir, 0o700); err != nil && runtime.GOOS != "windows" {
		return fmt.Errorf("save snapshot: %w", err)
	}

	f, err := os.CreateTemp(s.Dir, tempPattern)
	if err != nil {
		return fmt.Errorf("save snapshot: %w", err)
	}
	temp := f.Name()
	committed := false
	defer func() {
		if !committed {
			_ = f.Close()
			_ = os.Remove(temp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("save snapshot: %w", err)
	}
	if _, err := f.Write(raw); err != nil {
		return fmt.Errorf("save snapshot: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("save snapshot: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("save snapshot: %w", err)
	}
	if s.beforeRename != nil {
		if err := s.beforeRename(); err != nil {
			return fmt.Errorf("save snapshot: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(temp, Path(s.Dir)); err != nil {
		return fmt.Errorf("save snapshot: %w", err)
	}
	committed = true
	if err := syncDir(s.Dir); err != nil {
		return fmt.Errorf("sync snapshot directory: %w", err)
	}
	return nil
}

// Load removes abandoned crash temps, performs a stat-first bounded read, and
// exact-decodes the primary. Corrupt input is moved to one fixed, redacted
// quarantine filename and is never returned for replay.
func (s FileStore) Load(ctx context.Context) (State, error) {
	if err := ctx.Err(); err != nil {
		return State{}, err
	}
	if s.Dir == "" {
		return State{}, ErrInvalid
	}
	if err := cleanupTemps(s.Dir); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return State{}, err
	}
	f, err := os.Open(Path(s.Dir))
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, ErrNotFound
	}
	if err != nil {
		return State{}, ErrCorrupt
	}
	bad := func() (State, error) {
		_ = f.Close()
		return State{}, s.quarantine()
	}
	info, err := f.Stat()
	if err != nil {
		return bad()
	}
	if info.Size() < 1 || info.Size() > MaxBytes {
		return bad()
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil || len(raw) > MaxBytes {
		return bad()
	}
	if err := f.Close(); err != nil {
		return State{}, s.quarantine()
	}
	if err := ctx.Err(); err != nil {
		return State{}, err
	}
	state, err := decodeExact(raw)
	if err != nil {
		return State{}, s.quarantine()
	}
	state.Fresh = false
	return state, nil
}

func cleanupTemps(dir string) error {
	matches, err := filepath.Glob(filepath.Join(dir, tempPattern))
	if err != nil {
		return err
	}
	for _, name := range matches {
		if err := os.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (s FileStore) quarantine() error {
	primary, target := Path(s.Dir), QuarantinePath(s.Dir)
	_ = os.Remove(target)
	if err := os.Rename(primary, target); err == nil {
		_ = os.Chmod(target, 0o600)
		_ = syncDir(s.Dir)
	}
	return ErrCorrupt
}

func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	err = f.Sync()
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EBADF) {
		return nil
	}
	return err
}

func decodeExact(raw []byte) (State, error) {
	if len(raw) > MaxBytes {
		return State{}, ErrTooLarge
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return State{}, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return State{}, err
	}
	if !exactKeys(top, "version", "savedAt", "record") {
		return State{}, ErrInvalid
	}
	var rec map[string]json.RawMessage
	if err := json.Unmarshal(top["record"], &rec); err != nil {
		return State{}, err
	}
	if !exactKeys(rec, "hostId", "platform", "accelerators", "observedAt", "safeErr", "providersHealthy", "providersFailed") {
		return State{}, ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var state State
	if err := dec.Decode(&state); err != nil {
		return State{}, err
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return State{}, ErrInvalid
	}
	if err := state.validate(); err != nil {
		return State{}, err
	}
	return state, nil
}

func exactKeys(m map[string]json.RawMessage, keys ...string) bool {
	if len(m) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := m[key]; !ok {
			return false
		}
	}
	return true
}

// rejectDuplicateKeys walks every JSON object so aliases cannot hide in nested
// values, even if a future format adds a nested structure.
func rejectDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyTok.(string)
				if !ok {
					return ErrInvalid
				}
				if _, exists := seen[key]; exists {
					return ErrInvalid
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim('}') {
				return ErrInvalid
			}
		case '[':
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim(']') {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrInvalid
	}
	return nil
}
