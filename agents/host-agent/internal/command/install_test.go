package command

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
)

type testVerifier struct {
	key        *ecdsa.PublicKey
	authorized bool
}

func (v testVerifier) AuthorizedSigner(string) bool { return v.authorized }
func (v testVerifier) VerifyManifest(_ string, payload, signature []byte) bool {
	return ecdsa.VerifyASN1(v.key, sha256Bytes(payload), signature)
}
func sha256Bytes(v []byte) []byte { s := sha256.Sum256(v); return s[:] }

type testImporter struct {
	imported int
	prove    bool
}

func (i *testImporter) ImportVerified(_ context.Context, _, _, _, path, digest string) error {
	i.imported++
	return verifyFile(path, int64(len(testContent)), digest)
}
func (i *testImporter) Inventory(_ context.Context, providerID string) ([]provider.InstalledModel, error) {
	if !i.prove {
		return nil, nil
	}
	return []provider.InstalledModel{{ProviderID: providerID, CanonicalName: "library/model:latest"}}, nil
}

type fetchFunc func(context.Context, string, int64) (ArtifactFetch, error)

func (f fetchFunc) FetchArtifact(c context.Context, t string, o int64) (ArtifactFetch, error) {
	return f(c, t, o)
}

type errorReader struct {
	data []byte
	done bool
}

func (r *errorReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, errors.New("network")
	}
	r.done = true
	return copy(p, r.data), errors.New("network")
}
func (r *errorReader) Close() error { return nil }

const testContent = "verified artifact bytes"

func signedParams(t *testing.T, content []byte) (ArtifactInstallParams, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	m := ArtifactManifest{SchemaVersion: 1, ArtifactID: "artifact-1", ModelID: "model-1", Revision: "rev-1", Format: "gguf", SizeBytes: int64(len(content)), Digest: ArtifactDigest{Algorithm: "sha256", Value: hex.EncodeToString(digest[:])}, Provenance: ArtifactProvenance{Kind: "approved-source", SourceID: "source-1", ObservedAt: "2026-09-29T15:00:00.000Z"}, IssuedAt: "2026-09-29T15:01:00.000Z", ExpiresAt: "2026-09-30T15:01:00.000Z", SignerID: "controller-1", Signature: ArtifactSignature{Algorithm: "ecdsa-p256-sha256"}}
	payload, err := manifestPayload(m)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, key, sha256Bytes(payload))
	if err != nil {
		t.Fatal(err)
	}
	m.Signature.Value = base64.RawURLEncoding.EncodeToString(sig)
	payload, _ = manifestPayload(m)
	manifestSum := sha256.Sum256(payload)
	return ArtifactInstallParams{ProviderID: "ollama-main", Model: "library/model:latest", Manifest: m, ManifestDigest: hex.EncodeToString(manifestSum[:]), DownloadTicket: "a" + string(bytes.Repeat([]byte{'b'}, 63))}, key
}
func rawParams(t *testing.T, p ArtifactInstallParams) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func newInstaller(t *testing.T, p ArtifactInstallParams, key *ecdsa.PrivateKey, fetcher ArtifactFetcher, importer *testImporter) *VerifiedArtifactInstaller {
	t.Helper()
	x, err := NewVerifiedArtifactInstaller(t.TempDir(), fetcher, testVerifier{&key.PublicKey, true}, importer, func() time.Time { return time.Date(2026, 9, 29, 16, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func TestVerifiedArtifactInstallSuccessAndInventoryProof(t *testing.T) {
	p, key := signedParams(t, []byte(testContent))
	fetches := 0
	fetcher := fetchFunc(func(_ context.Context, ticket string, offset int64) (ArtifactFetch, error) {
		fetches++
		if ticket != p.DownloadTicket || offset != 0 {
			t.Fatalf("unexpected fetch %q %d", ticket, offset)
		}
		return ArtifactFetch{Body: io.NopCloser(bytes.NewReader([]byte(testContent))), Offset: 0, Total: int64(len(testContent)), Length: int64(len(testContent))}, nil
	})
	imp := &testImporter{prove: true}
	installer := newInstaller(t, p, key, fetcher, imp)
	result, err := installer.Install(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Installed || result.Digest != p.Manifest.Digest.Value || fetches != 1 || imp.imported != 1 {
		t.Fatalf("bad result %#v fetch=%d import=%d", result, fetches, imp.imported)
	}
	if err = verifyFile(filepath.Join(installer.cacheDir, "objects", p.Manifest.Digest.Value), p.Manifest.SizeBytes, p.Manifest.Digest.Value); err != nil {
		t.Fatal(err)
	}
}

func TestVerifiedArtifactInstallResumesExactOffset(t *testing.T) {
	p, key := signedParams(t, []byte(testContent))
	calls := []int64{}
	fail := true
	fetcher := fetchFunc(func(_ context.Context, _ string, offset int64) (ArtifactFetch, error) {
		calls = append(calls, offset)
		remaining := []byte(testContent)[offset:]
		var body io.ReadCloser = io.NopCloser(bytes.NewReader(remaining))
		if fail {
			fail = false
			body = &errorReader{data: remaining[:4]}
		}
		return ArtifactFetch{Body: body, Offset: offset, Total: int64(len(testContent)), Length: int64(len(remaining))}, nil
	})
	imp := &testImporter{prove: true}
	installer := newInstaller(t, p, key, fetcher, imp)
	if _, err := installer.Install(context.Background(), p); err == nil {
		t.Fatal("expected transient failure")
	}
	if _, err := installer.Install(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[0] != 0 || calls[1] != 4 {
		t.Fatalf("resume offsets %v", calls)
	}
}

func TestVerifiedArtifactInstallCancellationRemovesPartial(t *testing.T) {
	p, key := signedParams(t, []byte(testContent))
	ctx, cancel := context.WithCancel(context.Background())
	fetcher := fetchFunc(func(context.Context, string, int64) (ArtifactFetch, error) {
		cancel()
		return ArtifactFetch{Body: io.NopCloser(bytes.NewReader([]byte(testContent))), Offset: 0, Total: int64(len(testContent)), Length: int64(len(testContent))}, nil
	})
	installer := newInstaller(t, p, key, fetcher, &testImporter{prove: true})
	if _, err := installer.Install(ctx, p); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(filepath.Join(installer.cacheDir, "partial", p.ManifestDigest+".part")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial retained: %v", err)
	}
	if _, err := os.Stat(filepath.Join(installer.cacheDir, "partial", p.ManifestDigest+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("metadata retained: %v", err)
	}
}

func TestVerifiedArtifactInstallQuarantinesCorruption(t *testing.T) {
	p, key := signedParams(t, []byte(testContent))
	bad := bytes.Repeat([]byte{'x'}, len(testContent))
	fetcher := fetchFunc(func(context.Context, string, int64) (ArtifactFetch, error) {
		return ArtifactFetch{Body: io.NopCloser(bytes.NewReader(bad)), Offset: 0, Total: int64(len(bad)), Length: int64(len(bad))}, nil
	})
	installer := newInstaller(t, p, key, fetcher, &testImporter{prove: true})
	if _, err := installer.Install(context.Background(), p); !errors.Is(err, ErrArtifactDigestMismatch) {
		t.Fatalf("got %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(installer.cacheDir, "quarantine"))
	if err != nil || len(entries) < 1 {
		t.Fatalf("quarantine missing: %v %v", entries, err)
	}
}

func TestArtifactInstallStrictParamsAndGuard(t *testing.T) {
	p, _ := signedParams(t, []byte(testContent))
	if _, err := ParseArtifactInstallParams(rawParams(t, p)); err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if json.Unmarshal(rawParams(t, p), &object) != nil {
		t.Fatal("decode")
	}
	for name, mutate := range map[string]func(map[string]any){"url": func(v map[string]any) { v["url"] = "https://evil" }, "ticket": func(v map[string]any) { v["downloadTicket"] = "../escape" }, "model": func(v map[string]any) { v["model"] = "../escape" }, "manifest-extra": func(v map[string]any) { v["manifest"].(map[string]any)["path"] = "/tmp/x" }} {
		t.Run(name, func(t *testing.T) {
			copyRaw, _ := json.Marshal(object)
			var value map[string]any
			_ = json.Unmarshal(copyRaw, &value)
			mutate(value)
			raw, _ := json.Marshal(value)
			if _, err := ParseArtifactInstallParams(raw); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	registry := NewRegistry(nil)
	if _, err := registry.Execute(context.Background(), "install", rawParams(t, p)); !errors.Is(err, ErrGuardedOperation) {
		t.Fatalf("guard: %v", err)
	}
}

func TestArtifactInstallRejectsUnauthorizedManifestBeforeFetch(t *testing.T) {
	p, key := signedParams(t, []byte(testContent))
	called := false
	fetcher := fetchFunc(func(context.Context, string, int64) (ArtifactFetch, error) {
		called = true
		return ArtifactFetch{}, nil
	})
	installer, err := NewVerifiedArtifactInstaller(t.TempDir(), fetcher, testVerifier{&key.PublicKey, false}, &testImporter{}, func() time.Time { return time.Date(2026, 9, 29, 16, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	if _, err = installer.Install(context.Background(), p); !errors.Is(err, ErrArtifactUnauthorized) {
		t.Fatalf("got %v", err)
	}
	if called {
		t.Fatal("unauthorized request fetched")
	}
}
