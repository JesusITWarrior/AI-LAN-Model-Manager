package enrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	ErrNotFound = errors.New("enrollment state not found")
	ErrCorrupt  = errors.New("enrollment state corrupt")
)

const (
	stateName = "enrollment.json"
	maxState  = 1 << 20
)

// FileStore keeps the complete public result, including certificate and public
// CA PEM, in one atomically replaced JSON file beneath CertDir. Keeping these
// public fields in one commit unit prevents a certificate/result mismatch.
type FileStore struct {
	CertDir string
}

func (s FileStore) Load(ctx context.Context) (Result, error) {
	if ctx.Err() != nil {
		return Result{}, ErrCorrupt
	}
	path := filepath.Join(s.CertDir, stateName)
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return Result{}, ErrNotFound
	}
	if err != nil {
		return Result{}, ErrCorrupt
	}
	defer f.Close()
	limited := io.LimitReader(f, maxState+1)
	raw, err := io.ReadAll(limited)
	if err != nil || len(raw) == 0 || len(raw) > maxState {
		s.quarantine(path)
		return Result{}, ErrCorrupt
	}
	var result Result
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		s.quarantine(path)
		return Result{}, ErrCorrupt
	}
	if err := requireEOF(decoder); err != nil || !validStoredResult(result) {
		s.quarantine(path)
		return Result{}, ErrCorrupt
	}
	return result, nil
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return ErrCorrupt
		}
		return err
	}
	return nil
}

func (s FileStore) Save(ctx context.Context, result Result) error {
	if ctx.Err() != nil || strings.TrimSpace(s.CertDir) != s.CertDir || s.CertDir == "" || !validStoredResult(result) {
		return ErrCorrupt
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) == 0 || len(raw) > maxState {
		return ErrCorrupt
	}
	raw = append(raw, '\n')
	if len(raw) > maxState {
		return ErrCorrupt
	}
	if err := os.MkdirAll(s.CertDir, 0o700); err != nil {
		return ErrCorrupt
	}
	tmp, err := os.CreateTemp(s.CertDir, ".enrollment-*")
	if err != nil {
		return ErrCorrupt
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return ErrCorrupt
	}
	if _, err := tmp.Write(raw); err != nil {
		return ErrCorrupt
	}
	if err := tmp.Sync(); err != nil {
		return ErrCorrupt
	}
	if err := tmp.Close(); err != nil {
		return ErrCorrupt
	}
	if ctx.Err() != nil {
		return ErrCorrupt
	}
	if err := os.Rename(tmpName, filepath.Join(s.CertDir, stateName)); err != nil {
		return ErrCorrupt
	}
	committed = true
	if dir, err := os.Open(s.CertDir); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func (s FileStore) quarantine(path string) {
	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	_ = os.Rename(path, fmt.Sprintf("%s.corrupt-%s", path, stamp))
}
