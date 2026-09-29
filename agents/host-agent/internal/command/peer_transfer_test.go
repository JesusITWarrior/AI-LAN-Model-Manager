package command

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var peerNow = time.Date(2026, 9, 29, 17, 0, 0, 0, time.UTC)

func signedPeerTicket(t *testing.T, data []byte) (PeerTransferTicket, *ecdsa.PrivateKey) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(data)
	v := PeerTransferTicket{Version: 1, TransferID: "transfer-1", ArtifactID: "artifact-1", ManifestDigest: string(make([]byte, 0)), ContentDigest: hex.EncodeToString(sum[:]), SourceHostID: "source-1", DestinationHostID: "destination-1", SizeBytes: int64(len(data)), ChunkBytes: 4, IssuedAt: "2026-09-29T17:00:00.000Z", ExpiresAt: "2026-09-29T17:30:00.000Z", SignerID: "controller-1", Signature: PeerTransferSignature{Algorithm: "ecdsa-p256-sha256"}}
	v.ManifestDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digest := sha256.Sum256(peerTicketPayload(v))
	sig, e := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if e != nil {
		t.Fatal(e)
	}
	v.Signature.Value = base64.RawURLEncoding.EncodeToString(sig)
	return v, key
}
func TestPeerTransferSourceIsTicketBoundAndDestinationResumesAtomically(t *testing.T) {
	data := []byte("abcdefghij")
	ticket, key := signedPeerTicket(t, data)
	root := t.TempDir()
	sourceObjects := filepath.Join(root, "source", "objects")
	if e := os.MkdirAll(sourceObjects, 0o700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(sourceObjects, ticket.ContentDigest)
	if e := os.WriteFile(path, data, 0o400); e != nil {
		t.Fatal(e)
	}
	source := PeerArtifactSource{HostID: "source-1", SignerID: "controller-1", PublicKey: &key.PublicKey, ObjectsDir: sourceObjects, Artifacts: map[string]VerifiedPeerArtifact{"artifact-1": {ArtifactID: "artifact-1", ManifestDigest: ticket.ManifestDigest, ContentDigest: ticket.ContentDigest, Path: path, SizeBytes: int64(len(data))}}, Now: func() time.Time { return peerNow }}
	destination := PeerArtifactDestination{HostID: "destination-1", SignerID: "controller-1", PublicKey: &key.PublicKey, CacheDir: filepath.Join(root, "destination"), Now: func() time.Time { return peerNow }}
	for offset := int64(0); offset < ticket.SizeBytes; {
		length := ticket.ChunkBytes
		if left := ticket.SizeBytes - offset; left < length {
			length = left
		}
		chunk, e := source.Read(ticket, offset, length)
		if e != nil {
			t.Fatal(e)
		}
		state, e := destination.Accept(ticket, chunk)
		if e != nil {
			t.Fatal(e)
		}
		offset = state.NextOffset
	}
	object := filepath.Join(destination.CacheDir, "objects", ticket.ContentDigest)
	if e := verifyFile(object, ticket.SizeBytes, ticket.ContentDigest); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(destination.CacheDir, "peer-partial")); e != nil {
		t.Fatal(e)
	}
	replaySum := sha256.Sum256(data[:4])
	if state, e := destination.Accept(ticket, PeerTransferChunk{Offset: 0, Bytes: data[:4], Digest: hex.EncodeToString(replaySum[:])}); !errors.Is(e, ErrPeerTransfer) || state.Status != "received" {
		t.Fatalf("completed ticket replay accepted: %#v %v", state, e)
	}
	wrong := ticket
	wrong.SourceHostID = "other"
	if _, e := source.Read(wrong, 0, 4); !errors.Is(e, ErrPeerTransfer) {
		t.Fatalf("wrong source accepted: %v", e)
	}
	if _, e := source.Read(ticket, 0, 5); !errors.Is(e, ErrPeerTransfer) {
		t.Fatalf("oversize accepted: %v", e)
	}
}
func TestPeerTransferCorruptionExpiryReplayAndNoPathFields(t *testing.T) {
	data := []byte("abcdefghij")
	ticket, key := signedPeerTicket(t, data)
	raw, _ := json.Marshal(ticket)
	decoded, parseErr := ParsePeerTransferTicket(raw)
	if parseErr != nil || decoded.TransferID != ticket.TransferID {
		t.Fatalf("parse: %#v %v", decoded, parseErr)
	}
	if string(raw) == "" || containsSensitivePeerField(string(raw)) {
		t.Fatalf("ticket leaks path or endpoint: %s", raw)
	}
	destination := PeerArtifactDestination{HostID: "destination-1", SignerID: "controller-1", PublicKey: &key.PublicKey, CacheDir: t.TempDir(), Now: func() time.Time { return peerNow }}
	bad := PeerTransferChunk{Offset: 0, Bytes: []byte("abcd"), Digest: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}
	state, e := destination.Accept(ticket, bad)
	if !errors.Is(e, ErrPeerTransfer) || state.Status != "failed" || state.TerminalCode == nil || *state.TerminalCode != "chunk-digest-mismatch" {
		t.Fatalf("corruption=%#v,%v", state, e)
	}
	goodSum := sha256.Sum256([]byte("abcd"))
	if terminal, retryErr := destination.Accept(ticket, PeerTransferChunk{Offset: 0, Bytes: []byte("abcd"), Digest: hex.EncodeToString(goodSum[:])}); !errors.Is(retryErr, ErrPeerTransfer) || terminal.Status != "failed" {
		t.Fatalf("corrupt transfer was not terminal: %#v %v", terminal, retryErr)
	}
	expired := destination
	expired.Now = func() time.Time { return peerNow.Add(time.Hour) }
	if _, e = expired.Accept(ticket, PeerTransferChunk{Offset: 0, Bytes: []byte("abcd"), Digest: hex.EncodeToString(goodSum[:])}); !errors.Is(e, ErrPeerTransfer) {
		t.Fatalf("expired accepted: %v", e)
	}
	wrong := destination
	wrong.HostID = "other"
	if _, e = wrong.Accept(ticket, PeerTransferChunk{Offset: 0, Bytes: []byte("abcd"), Digest: hex.EncodeToString(goodSum[:])}); !errors.Is(e, ErrPeerTransfer) {
		t.Fatalf("wrong destination accepted: %v", e)
	}
}
func containsSensitivePeerField(v string) bool {
	return bytesContains(v, "path") || bytesContains(v, "endpoint") || bytesContains(v, "url")
}
func TestCrossLanguagePeerTransferHelper(t *testing.T) {
	ticketPath, publicPath, sourcePath, destinationDir := os.Getenv("LANMM_CROSS_PEER_TICKET"), os.Getenv("LANMM_CROSS_PEER_PUBLIC"), os.Getenv("LANMM_CROSS_PEER_SOURCE"), os.Getenv("LANMM_CROSS_PEER_DESTINATION")
	if ticketPath == "" || publicPath == "" || sourcePath == "" || destinationDir == "" {
		t.Skip("cross-language fixture not configured")
	}
	raw, e := os.ReadFile(ticketPath)
	if e != nil {
		t.Fatal(e)
	}
	ticket, e := ParsePeerTransferTicket(raw)
	if e != nil {
		t.Fatal(e)
	}
	publicPEM, e := os.ReadFile(publicPath)
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode(publicPEM)
	if block == nil {
		t.Fatal("public pem")
	}
	parsed, e := x509.ParsePKIXPublicKey(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	public, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("public key type")
	}
	source := PeerArtifactSource{HostID: ticket.SourceHostID, SignerID: ticket.SignerID, PublicKey: public, ObjectsDir: filepath.Dir(sourcePath), Artifacts: map[string]VerifiedPeerArtifact{ticket.ArtifactID: {ArtifactID: ticket.ArtifactID, ManifestDigest: ticket.ManifestDigest, ContentDigest: ticket.ContentDigest, Path: sourcePath, SizeBytes: ticket.SizeBytes}}, Now: func() time.Time { return peerNow }}
	destination := PeerArtifactDestination{HostID: ticket.DestinationHostID, SignerID: ticket.SignerID, PublicKey: public, CacheDir: destinationDir, Now: func() time.Time { return peerNow }}
	offset := int64(0)
	first := true
	for offset < ticket.SizeBytes {
		length := ticket.ChunkBytes
		if ticket.SizeBytes-offset < length {
			length = ticket.SizeBytes - offset
		}
		chunk, readErr := source.Read(ticket, offset, length)
		if readErr != nil {
			t.Fatal(readErr)
		}
		state, acceptErr := destination.Accept(ticket, chunk)
		if acceptErr != nil {
			t.Fatal(acceptErr)
		}
		offset = state.NextOffset
		if first {
			destination = PeerArtifactDestination{HostID: ticket.DestinationHostID, SignerID: ticket.SignerID, PublicKey: public, CacheDir: destinationDir, Now: func() time.Time { return peerNow }}
			first = false
		}
	}
	if e = verifyFile(filepath.Join(destinationDir, "objects", ticket.ContentDigest), ticket.SizeBytes, ticket.ContentDigest); e != nil {
		t.Fatal(e)
	}
	fmt.Printf("LANMM_CROSS_PEER_RESULT=received:bytes:%d:digest:%s\n", ticket.SizeBytes, ticket.ContentDigest)
}

func bytesContains(v, part string) bool {
	for i := 0; i+len(part) <= len(v); i++ {
		if v[i:i+len(part)] == part {
			return true
		}
	}
	return false
}
