package command

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPeerDestinationRecoversACKCrashWithoutDuplicate(t *testing.T) {
	data := []byte("abcdefgh")
	ticket, key := signedPeerTicket(t, data)
	d := &PeerArtifactDestination{HostID: ticket.DestinationHostID, SignerID: ticket.SignerID, PublicKey: &key.PublicKey, CacheDir: t.TempDir(), Now: func() time.Time { return peerNow }}
	first := data[:4]
	sum := sha256.Sum256(first)
	chunk := PeerTransferChunk{Offset: 0, Bytes: first, Digest: hex.EncodeToString(sum[:])}
	state, err := d.Accept(ticket, chunk)
	if err != nil {
		t.Fatal(err)
	}
	// Model the durable bytes / stale ACK checkpoint crash window.
	rawDigest, _ := AuthenticatePeerTransferTicket(ticket, &key.PublicKey, ticket.SignerID, ticket.DestinationHostID, "destination", peerNow)
	meta := filepath.Join(d.CacheDir, "peer-partial", rawDigest+".json")
	pending := int64(0)
	stale := state
	stale.NextOffset, stale.ChunkCount, stale.ChainDigest = 0, 0, string(make([]byte, 0))
	stale.ChainDigest = "0000000000000000000000000000000000000000000000000000000000000000"
	stale.LastLength, stale.LastDigest = 0, ""
	stale.PendingOffset, stale.PendingLength, stale.PendingDigest = &pending, 4, chunk.Digest
	if err = writePeerCheckpoint(meta, stale); err != nil {
		t.Fatal(err)
	}
	replayed, err := d.Accept(ticket, chunk)
	if err != nil || replayed.NextOffset != 4 || replayed.ChunkCount != 1 {
		t.Fatalf("recovery %#v %v", replayed, err)
	}
	part := filepath.Join(d.CacheDir, "peer-partial", rawDigest+".part")
	if st, _ := os.Stat(part); st.Size() != 4 {
		t.Fatalf("duplicated bytes: %d", st.Size())
	}
}

func TestPeerRelayPollWireReadWriteAndExplicitCommit(t *testing.T) {
	data := []byte("abcd")
	ticket, key := signedPeerTicket(t, data)
	root := t.TempDir()
	objects := filepath.Join(root, "source", "objects")
	if err := os.MkdirAll(objects, 0o700); err != nil {
		t.Fatal(err)
	}
	object := filepath.Join(objects, ticket.ContentDigest)
	if err := os.WriteFile(object, data, 0o400); err != nil {
		t.Fatal(err)
	}
	source := &PeerArtifactSource{HostID: ticket.SourceHostID, SignerID: ticket.SignerID, PublicKey: &key.PublicKey, ObjectsDir: objects, Artifacts: map[string]VerifiedPeerArtifact{ticket.ArtifactID: {ArtifactID: ticket.ArtifactID, ManifestDigest: ticket.ManifestDigest, ContentDigest: ticket.ContentDigest, Path: object, SizeBytes: int64(len(data))}}, Now: func() time.Time { return peerNow }}
	destination := &PeerArtifactDestination{HostID: ticket.DestinationHostID, SignerID: ticket.SignerID, PublicKey: &key.PublicKey, CacheDir: filepath.Join(root, "destination"), Now: func() time.Time { return peerNow }}
	relay := &PeerRelay{Source: source, Destination: destination}
	readRaw, _ := json.Marshal(PeerRelayDirective{Version: 1, Action: "read", TransferID: ticket.TransferID, Role: "source", Ticket: ticket, Offset: 0, Length: ticket.SizeBytes})
	readResult, err := relay.ExecuteDirective(context.Background(), readRaw)
	if err != nil || readResult.ChunkBase64 == nil || readResult.ChunkDigest == nil || readResult.Status != "transferring" {
		t.Fatalf("read %#v %v", readResult, err)
	}
	decoded, err := base64.StdEncoding.DecodeString(*readResult.ChunkBase64)
	if err != nil || string(decoded) != string(data) {
		t.Fatalf("bytes %q %v", decoded, err)
	}
	writeRaw, _ := json.Marshal(PeerRelayDirective{Version: 1, Action: "write", TransferID: ticket.TransferID, Role: "destination", Ticket: ticket, Offset: 0, Length: ticket.SizeBytes, ChunkBase64: readResult.ChunkBase64, ChunkDigest: readResult.ChunkDigest})
	writeResult, err := relay.ExecuteDirective(context.Background(), writeRaw)
	if err != nil || writeResult.Status != "transferring" || writeResult.NextOffset != ticket.SizeBytes || writeResult.Receipt != nil {
		t.Fatalf("write %#v %v", writeResult, err)
	}
	commitRaw, _ := json.Marshal(PeerRelayDirective{Version: 1, Action: "commit", TransferID: ticket.TransferID, Role: "destination", Ticket: ticket, Offset: ticket.SizeBytes})
	commitResult, err := relay.ExecuteDirective(context.Background(), commitRaw)
	if err != nil || commitResult.Status != "received" || commitResult.Receipt == nil || commitResult.Receipt.ContentDigest != ticket.ContentDigest || commitResult.Receipt.ChainDigest != writeResult.ChainDigest {
		t.Fatalf("commit %#v %v", commitResult, err)
	}
	if bytesContains(string(commitRaw), "path") || bytesContains(string(commitRaw), "endpoint") || bytesContains(string(commitRaw), "url") {
		t.Fatalf("directive leaked location: %s", commitRaw)
	}
}

func TestPeerRelayClosedRoleRevocationAndCommitReceipt(t *testing.T) {
	data := []byte("abcd")
	ticket, key := signedPeerTicket(t, data)
	registry := NewRegistry(nil)
	if _, err := registry.Execute(context.Background(), PeerDestinationOperation, json.RawMessage(`{}`)); !errors.Is(err, ErrGuardedOperation) {
		t.Fatalf("not closed: %v", err)
	}
	d := &PeerArtifactDestination{HostID: ticket.DestinationHostID, SignerID: ticket.SignerID, PublicKey: &key.PublicKey, CacheDir: t.TempDir(), Now: func() time.Time { return peerNow }}
	relay := &PeerRelay{Destination: d}
	registry.ConfigurePeerRelay(relay)
	sum := sha256.Sum256(data)
	directive := peerDestinationDirective{Ticket: ticket, Chunk: PeerTransferChunk{Offset: 0, Bytes: data, Digest: hex.EncodeToString(sum[:])}}
	raw, _ := json.Marshal(directive)
	value, err := registry.Execute(context.Background(), PeerDestinationOperation, raw)
	result, ok := value.(PeerDestinationResult)
	if err != nil || !ok || result.Receipt == nil || result.Receipt.ContentDigest != ticket.ContentDigest || result.Receipt.SizeBytes != int64(len(data)) {
		t.Fatalf("receipt %#v %v", value, err)
	}
	wrong := ticket
	wrong.DestinationHostID = "source-1"
	bad, _ := json.Marshal(peerDestinationDirective{Ticket: wrong, Chunk: directive.Chunk})
	if _, err = relay.Execute(context.Background(), PeerDestinationOperation, bad); !errors.Is(err, ErrPeerTransfer) {
		t.Fatalf("wrong role: %v", err)
	}
	d.Revoked = func(PeerTransferTicket) bool { return true }
	if _, err = d.Receipt(ticket); !errors.Is(err, ErrPeerTransfer) {
		t.Fatalf("revoked receipt: %v", err)
	}
	if bytesContains(string(raw), "path") || bytesContains(string(raw), "endpoint") || bytesContains(string(raw), "url") {
		t.Fatalf("directive leaked location: %s", raw)
	}
}
