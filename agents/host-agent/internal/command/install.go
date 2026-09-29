package command

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
)

var (
	ErrArtifactInstall        = errors.New("artifact install failed")
	ErrArtifactUnauthorized   = errors.New("artifact install unauthorized")
	ErrArtifactDigestMismatch = errors.New("artifact digest mismatch")
)

const maximumArtifactBytes int64 = 1 << 40

var modelNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
var signaturePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{80,128}$`)

type ArtifactDigest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}
type ArtifactProvenance struct {
	Kind           string  `json:"kind"`
	SourceID       string  `json:"sourceId"`
	SourceRevision *string `json:"sourceRevision"`
	ObservedAt     string  `json:"observedAt"`
}
type ArtifactSignature struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}
type ArtifactManifest struct {
	SchemaVersion int                `json:"schemaVersion"`
	ArtifactID    string             `json:"artifactId"`
	ModelID       string             `json:"modelId"`
	Revision      string             `json:"revision"`
	Format        string             `json:"format"`
	SizeBytes     int64              `json:"sizeBytes"`
	Digest        ArtifactDigest     `json:"digest"`
	Provenance    ArtifactProvenance `json:"provenance"`
	IssuedAt      string             `json:"issuedAt"`
	ExpiresAt     string             `json:"expiresAt"`
	SignerID      string             `json:"signerId"`
	Signature     ArtifactSignature  `json:"signature"`
}
type ArtifactInstallParams struct {
	ProviderID     string           `json:"providerId"`
	Model          string           `json:"model"`
	Manifest       ArtifactManifest `json:"manifest"`
	ManifestDigest string           `json:"manifestDigest"`
	DownloadTicket string           `json:"downloadTicket"`
}
type ArtifactInstallResult struct {
	ProviderID     string `json:"providerId"`
	ArtifactID     string `json:"artifactId"`
	ModelID        string `json:"modelId"`
	CanonicalModel string `json:"canonicalModelName"`
	Digest         string `json:"digest"`
	ManifestDigest string `json:"manifestDigest"`
	SizeBytes      int64  `json:"sizeBytes"`
	Installed      bool   `json:"installed"`
}

// ManifestVerifier authorizes a signer and verifies the exact canonical signed
// manifest payload. Implementations normally pin controller signing keys.
type ManifestVerifier interface {
	AuthorizedSigner(string) bool
	VerifyManifest(signerID string, payload, signature []byte) bool
}

// ArtifactFetch is a fixed-origin download result. Offset and Total must be
// independently derived from the HTTP response by the fetcher.
type ArtifactFetch struct {
	Body   io.ReadCloser
	Offset int64
	Total  int64
	Length int64
}
type ArtifactFetcher interface {
	FetchArtifact(context.Context, string, int64) (ArtifactFetch, error)
}

// VerifiedArtifactImporter receives only a fully verified, atomically published
// local path. It cannot influence acquisition or cache paths.
type VerifiedArtifactImporter interface {
	ImportVerified(context.Context, string, string, string, string, string) error
	Inventory(context.Context, string) ([]provider.InstalledModel, error)
}

type VerifiedArtifactInstaller struct {
	cacheDir string
	fetcher  ArtifactFetcher
	verifier ManifestVerifier
	importer VerifiedArtifactImporter
	now      func() time.Time
	mu       sync.Mutex
}

func NewVerifiedArtifactInstaller(cacheDir string, fetcher ArtifactFetcher, verifier ManifestVerifier, importer VerifiedArtifactImporter, now func() time.Time) (*VerifiedArtifactInstaller, error) {
	if !filepath.IsAbs(cacheDir) || filepath.Clean(cacheDir) != cacheDir || fetcher == nil || verifier == nil || importer == nil {
		return nil, ErrArtifactInstall
	}
	if now == nil {
		now = time.Now
	}
	return &VerifiedArtifactInstaller{cacheDir: cacheDir, fetcher: fetcher, verifier: verifier, importer: importer, now: now}, nil
}

func ParseArtifactInstallParams(raw json.RawMessage) (ArtifactInstallParams, error) {
	var value ArtifactInstallParams
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF || len(raw) > 32768 || !validInstallParams(value) {
		return ArtifactInstallParams{}, provider.ErrInvalidCommand
	}
	canonical, ok := provider.CanonicalOllamaModelName(value.Model)
	if !ok || canonical != value.Model {
		return ArtifactInstallParams{}, provider.ErrInvalidCommand
	}
	return value, nil
}

func validInstallParams(v ArtifactInstallParams) bool {
	m := v.Manifest
	if !provider.ValidateProviderID(v.ProviderID) || !modelNamePattern.MatchString(v.Model) || !digestPattern.MatchString(v.ManifestDigest) || !digestPattern.MatchString(v.DownloadTicket) || m.SchemaVersion != 1 || !identifier.MatchString(m.ArtifactID) || !modelNamePattern.MatchString(m.ModelID) || !identifier.MatchString(m.Revision) || m.SizeBytes < 1 || m.SizeBytes > maximumArtifactBytes || m.Digest.Algorithm != "sha256" || !digestPattern.MatchString(m.Digest.Value) || m.Provenance.Kind != "approved-source" || !identifier.MatchString(m.Provenance.SourceID) || m.SignerID == "" || !identifier.MatchString(m.SignerID) || m.Signature.Algorithm != "ecdsa-p256-sha256" || !signaturePattern.MatchString(m.Signature.Value) {
		return false
	}
	if m.Provenance.SourceRevision != nil && !identifier.MatchString(*m.Provenance.SourceRevision) {
		return false
	}
	if m.Format != "gguf" {
		return false
	}
	observed, e1 := parseExactTime(m.Provenance.ObservedAt)
	issued, e2 := parseExactTime(m.IssuedAt)
	expires, e3 := parseExactTime(m.ExpiresAt)
	return e1 == nil && e2 == nil && e3 == nil && !observed.After(issued) && expires.After(issued) && expires.Sub(issued) <= 30*24*time.Hour
}
func parseExactTime(value string) (time.Time, error) {
	if len(value) != 24 || value[23] != 'Z' {
		return time.Time{}, ErrArtifactInstall
	}
	t, err := time.Parse("2006-01-02T15:04:05.000Z", value)
	if err != nil || t.UTC().Format("2006-01-02T15:04:05.000Z") != value {
		return time.Time{}, ErrArtifactInstall
	}
	return t, nil
}

func (i *VerifiedArtifactInstaller) Install(ctx context.Context, p ArtifactInstallParams) (ArtifactInstallResult, error) {
	if i == nil {
		return ArtifactInstallResult{}, ErrArtifactInstall
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return ArtifactInstallResult{}, err
	}
	payload, err := manifestPayload(p.Manifest)
	if err != nil {
		return ArtifactInstallResult{}, ErrArtifactUnauthorized
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != p.ManifestDigest {
		return ArtifactInstallResult{}, ErrArtifactUnauthorized
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(p.Manifest.Signature.Value)
	if err != nil || len(sig) < 64 || len(sig) > 96 || !i.verifier.AuthorizedSigner(p.Manifest.SignerID) || !i.verifier.VerifyManifest(p.Manifest.SignerID, payload, sig) {
		return ArtifactInstallResult{}, ErrArtifactUnauthorized
	}
	now := i.now().UTC()
	issued, _ := parseExactTime(p.Manifest.IssuedAt)
	expires, _ := parseExactTime(p.Manifest.ExpiresAt)
	if now.Before(issued.Add(-30*time.Second)) || !now.Before(expires) {
		return ArtifactInstallResult{}, ErrArtifactUnauthorized
	}
	for _, dir := range []string{i.cacheDir, filepath.Join(i.cacheDir, "partial"), filepath.Join(i.cacheDir, "objects"), filepath.Join(i.cacheDir, "quarantine")} {
		if err := ensureCacheDir(dir); err != nil {
			return ArtifactInstallResult{}, err
		}
	}
	part := filepath.Join(i.cacheDir, "partial", p.ManifestDigest+".part")
	meta := filepath.Join(i.cacheDir, "partial", p.ManifestDigest+".json")
	object := filepath.Join(i.cacheDir, "objects", p.Manifest.Digest.Value)
	binding := partialMetadata{ManifestDigest: p.ManifestDigest, ContentDigest: p.Manifest.Digest.Value, SizeBytes: p.Manifest.SizeBytes, TicketDigest: ticketDigest(p.DownloadTicket)}
	if _, err := os.Stat(object); errors.Is(err, os.ErrNotExist) {
		if err := i.preparePartial(part, meta, binding); err != nil {
			return ArtifactInstallResult{}, err
		}
		if err = i.download(ctx, p.DownloadTicket, part, meta, binding); err != nil {
			if errors.Is(err, context.Canceled) {
				_ = os.Remove(part)
				_ = os.Remove(meta)
			}
			return ArtifactInstallResult{}, err
		}
		if err = os.Rename(part, object); err != nil {
			return ArtifactInstallResult{}, ErrArtifactInstall
		}
		if os.Chmod(object, 0o400) != nil || os.Remove(meta) != nil || syncDirectory(filepath.Dir(object)) != nil {
			return ArtifactInstallResult{}, ErrArtifactInstall
		}
	} else if err != nil || verifyFile(object, p.Manifest.SizeBytes, p.Manifest.Digest.Value) != nil {
		return ArtifactInstallResult{}, ErrArtifactInstall
	}
	if err := ctx.Err(); err != nil {
		return ArtifactInstallResult{}, err
	}
	if err := i.importer.ImportVerified(ctx, p.ProviderID, p.Model, p.Manifest.Format, object, p.Manifest.Digest.Value); err != nil {
		return ArtifactInstallResult{}, ErrArtifactInstall
	}
	models, err := i.importer.Inventory(ctx, p.ProviderID)
	if err != nil {
		return ArtifactInstallResult{}, ErrArtifactInstall
	}
	proved := false
	for _, model := range models {
		if model.ProviderID == p.ProviderID && model.CanonicalName == p.Model {
			proved = true
			break
		}
	}
	if !proved {
		return ArtifactInstallResult{}, ErrRuntimeStateMismatch
	}
	return ArtifactInstallResult{ProviderID: p.ProviderID, ArtifactID: p.Manifest.ArtifactID, ModelID: p.Manifest.ModelID, CanonicalModel: p.Model, Digest: p.Manifest.Digest.Value, ManifestDigest: p.ManifestDigest, SizeBytes: p.Manifest.SizeBytes, Installed: true}, nil
}

type partialMetadata struct {
	ManifestDigest string `json:"manifestDigest"`
	ContentDigest  string `json:"contentDigest"`
	SizeBytes      int64  `json:"sizeBytes"`
	TicketDigest   string `json:"ticketDigest"`
	ReceivedBytes  int64  `json:"receivedBytes"`
}

func ticketDigest(ticket string) string {
	s := sha256.Sum256([]byte(ticket))
	return hex.EncodeToString(s[:])
}
func (i *VerifiedArtifactInstaller) preparePartial(part, meta string, want partialMetadata) error {
	st, err := os.Stat(part)
	if errors.Is(err, os.ErrNotExist) {
		want.ReceivedBytes = 0
		return writeMetadata(meta, want)
	}
	if err != nil || !st.Mode().IsRegular() || st.Size() > want.SizeBytes {
		i.quarantine(part, meta, "invalid-partial")
		return ErrArtifactInstall
	}
	raw, err := os.ReadFile(meta)
	var got partialMetadata
	if err != nil || len(raw) > 2048 || json.Unmarshal(raw, &got) != nil || got.ManifestDigest != want.ManifestDigest || got.ContentDigest != want.ContentDigest || got.SizeBytes != want.SizeBytes || got.TicketDigest != want.TicketDigest || got.ReceivedBytes != st.Size() {
		i.quarantine(part, meta, "binding-mismatch")
		return ErrArtifactInstall
	}
	return nil
}
func (i *VerifiedArtifactInstaller) download(ctx context.Context, ticket, part, meta string, binding partialMetadata) error {
	f, err := os.OpenFile(part, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return ErrArtifactInstall
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return ErrArtifactInstall
	}
	offset := st.Size()
	h := sha256.New()
	if offset > 0 {
		if _, err = io.CopyN(h, f, offset); err != nil {
			return ErrArtifactInstall
		}
	}
	if offset < binding.SizeBytes {
		result, err := i.fetcher.FetchArtifact(ctx, ticket, offset)
		if err != nil {
			return classifyContext(ctx, err)
		}
		if result.Body == nil {
			return ErrArtifactInstall
		}
		defer result.Body.Close()
		if result.Offset != offset || result.Total != binding.SizeBytes || result.Length != binding.SizeBytes-offset {
			i.quarantine(part, meta, "range-mismatch")
			return ErrArtifactInstall
		}
		if _, err = f.Seek(offset, io.SeekStart); err != nil {
			return ErrArtifactInstall
		}
		written, err := copyExact(ctx, io.MultiWriter(f, h), result.Body, result.Length)
		binding.ReceivedBytes = offset + written
		if syncErr := f.Sync(); syncErr != nil {
			return ErrArtifactInstall
		}
		if metaErr := writeMetadata(meta, binding); metaErr != nil {
			return ErrArtifactInstall
		}
		if err != nil {
			return classifyContext(ctx, err)
		}
	}
	if binding.ReceivedBytes == 0 {
		binding.ReceivedBytes = binding.SizeBytes
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if actual != binding.ContentDigest {
		i.quarantine(part, meta, "digest-mismatch")
		return ErrArtifactDigestMismatch
	}
	return nil
}
func classifyContext(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.Join(ErrArtifactInstall, err)
}
func copyExact(ctx context.Context, dst io.Writer, src io.Reader, n int64) (int64, error) {
	buf := make([]byte, 128<<10)
	var total int64
	for total < n {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		want := int64(len(buf))
		if n-total < want {
			want = n - total
		}
		read, err := src.Read(buf[:want])
		if read > 0 {
			w, werr := dst.Write(buf[:read])
			total += int64(w)
			if werr != nil {
				return total, werr
			}
			if w != read {
				return total, io.ErrShortWrite
			}
		}
		if err != nil {
			if err == io.EOF && total == n {
				break
			}
			return total, err
		}
		if read == 0 {
			return total, io.ErrNoProgress
		}
	}
	var one [1]byte
	if read, _ := src.Read(one[:]); read != 0 {
		return total, ErrArtifactInstall
	}
	return total, nil
}
func writeMetadata(path string, value partialMetadata) error {
	raw, _ := json.Marshal(value)
	tmp, err := os.CreateTemp(filepath.Dir(path), ".partial-meta-")
	if err != nil {
		return ErrArtifactInstall
	}
	name := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if tmp.Chmod(0o600) != nil {
		return ErrArtifactInstall
	}
	if _, err = tmp.Write(append(raw, '\n')); err != nil || tmp.Sync() != nil || tmp.Close() != nil {
		return ErrArtifactInstall
	}
	if os.Rename(name, path) != nil {
		return ErrArtifactInstall
	}
	ok = true
	return nil
}
func (i *VerifiedArtifactInstaller) quarantine(part, meta, reason string) {
	suffix := "." + reason + "." + strconv.FormatInt(i.now().UnixNano(), 10)
	if _, err := os.Stat(part); err == nil {
		_ = os.Rename(part, filepath.Join(i.cacheDir, "quarantine", filepath.Base(part)+suffix))
	}
	if _, err := os.Stat(meta); err == nil {
		_ = os.Rename(meta, filepath.Join(i.cacheDir, "quarantine", filepath.Base(meta)+suffix))
	}
}
func ensureCacheDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return ErrArtifactInstall
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrArtifactInstall
	}
	return nil
}
func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func verifyFile(path string, size int64, digest string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() != size {
		return ErrArtifactInstall
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != digest {
		return ErrArtifactDigestMismatch
	}
	return nil
}

func manifestPayload(m ArtifactManifest) ([]byte, error) {
	// Marshal to an untyped tree, remove the signature, then use the same sorted
	// canonical JSON domain as packages/core.
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var value map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&value) != nil {
		return nil, ErrArtifactInstall
	}
	delete(value, "signature")
	var b strings.Builder
	b.WriteString("lanmm-artifact-manifest-v1\n")
	if canonicalJSON(&b, value) != nil {
		return nil, ErrArtifactInstall
	}
	return []byte(b.String()), nil
}
func canonicalJSON(w *strings.Builder, v any) error {
	switch x := v.(type) {
	case nil:
		w.WriteString("null")
	case bool:
		if x {
			w.WriteString("true")
		} else {
			w.WriteString("false")
		}
	case string:
		b, _ := json.Marshal(x)
		w.Write(b)
	case json.Number:
		n, err := strconv.ParseInt(string(x), 10, 64)
		if err != nil || n < 0 {
			return ErrArtifactInstall
		}
		w.WriteString(strconv.FormatInt(n, 10))
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		w.WriteByte('{')
		for j, k := range keys {
			if j > 0 {
				w.WriteByte(',')
			}
			b, _ := json.Marshal(k)
			w.Write(b)
			w.WriteByte(':')
			if err := canonicalJSON(w, x[k]); err != nil {
				return err
			}
		}
		w.WriteByte('}')
	default:
		return ErrArtifactInstall
	}
	return nil
}
