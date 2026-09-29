package command

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

var ErrPeerTransfer = errors.New("peer transfer rejected")

type PeerTransferSignature struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}
type PeerTransferTicket struct {
	Version           int                   `json:"version"`
	TransferID        string                `json:"transferId"`
	ArtifactID        string                `json:"artifactId"`
	ManifestDigest    string                `json:"manifestDigest"`
	ContentDigest     string                `json:"contentDigest"`
	SourceHostID      string                `json:"sourceHostId"`
	DestinationHostID string                `json:"destinationHostId"`
	SizeBytes         int64                 `json:"sizeBytes"`
	ChunkBytes        int64                 `json:"chunkBytes"`
	IssuedAt          string                `json:"issuedAt"`
	ExpiresAt         string                `json:"expiresAt"`
	SignerID          string                `json:"signerId"`
	Signature         PeerTransferSignature `json:"signature"`
}
type PeerTransferChunk struct {
	Offset int64  `json:"offset"`
	Bytes  []byte `json:"bytes"`
	Digest string `json:"digest"`
}
type PeerTransferCheckpoint struct {
	TransferID    string  `json:"transferId"`
	TicketDigest  string  `json:"ticketDigest"`
	NextOffset    int64   `json:"nextOffset"`
	ChunkCount    uint64  `json:"chunkCount"`
	ChainDigest   string  `json:"chainDigest"`
	Status        string  `json:"status"`
	TerminalCode  *string `json:"terminalCode"`
	LastOffset    int64   `json:"lastOffset,omitempty"`
	LastLength    int64   `json:"lastLength,omitempty"`
	LastDigest    string  `json:"lastDigest,omitempty"`
	PendingOffset *int64  `json:"pendingOffset,omitempty"`
	PendingLength int64   `json:"pendingLength,omitempty"`
	PendingDigest string  `json:"pendingDigest,omitempty"`
	UpdatedAt     string  `json:"updatedAt"`
}

type PeerTransferReceipt struct {
	TransferID     string `json:"transferId"`
	ArtifactID     string `json:"artifactId"`
	ManifestDigest string `json:"manifestDigest"`
	ContentDigest  string `json:"contentDigest"`
	SizeBytes      int64  `json:"sizeBytes"`
	ObjectPath     string `json:"-"`
}

func ParsePeerTransferTicket(raw []byte) (PeerTransferTicket, error) {
	var t PeerTransferTicket
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > 8192 || d.Decode(&t) != nil || d.Decode(&struct{}{}) != io.EOF || !validPeerTicket(t) {
		return PeerTransferTicket{}, ErrPeerTransfer
	}
	return t, nil
}
func validPeerTicket(t PeerTransferTicket) bool {
	issued, e1 := parseExactTime(t.IssuedAt)
	expires, e2 := parseExactTime(t.ExpiresAt)
	return t.Version == 1 && identifier.MatchString(t.TransferID) && identifier.MatchString(t.ArtifactID) && identifier.MatchString(t.SourceHostID) && identifier.MatchString(t.DestinationHostID) && t.SourceHostID != t.DestinationHostID && identifier.MatchString(t.SignerID) && digestPattern.MatchString(t.ManifestDigest) && digestPattern.MatchString(t.ContentDigest) && t.SizeBytes > 0 && t.SizeBytes <= maximumArtifactBytes && t.ChunkBytes > 0 && t.ChunkBytes <= 384000 && t.ChunkBytes <= t.SizeBytes && e1 == nil && e2 == nil && expires.After(issued) && expires.Sub(issued) <= time.Hour && t.Signature.Algorithm == "ecdsa-p256-sha256" && signaturePattern.MatchString(t.Signature.Value)
}
func peerTicketPayload(t PeerTransferTicket) []byte {
	return []byte(fmt.Sprintf("lanmm-peer-transfer-v1\n{\"artifactId\":%q,\"chunkBytes\":%d,\"contentDigest\":%q,\"destinationHostId\":%q,\"expiresAt\":%q,\"issuedAt\":%q,\"manifestDigest\":%q,\"signerId\":%q,\"sizeBytes\":%d,\"sourceHostId\":%q,\"transferId\":%q,\"version\":1}", t.ArtifactID, t.ChunkBytes, t.ContentDigest, t.DestinationHostID, t.ExpiresAt, t.IssuedAt, t.ManifestDigest, t.SignerID, t.SizeBytes, t.SourceHostID, t.TransferID))
}
func AuthenticatePeerTransferTicket(t PeerTransferTicket, public *ecdsa.PublicKey, authorizedSigner, hostID, role string, now time.Time) (string, error) {
	if public == nil || !validPeerTicket(t) || t.SignerID != authorizedSigner || (role == "source" && t.SourceHostID != hostID) || (role == "destination" && t.DestinationHostID != hostID) || (role != "source" && role != "destination") {
		return "", ErrPeerTransfer
	}
	issued, _ := parseExactTime(t.IssuedAt)
	expires, _ := parseExactTime(t.ExpiresAt)
	if now.Before(issued.Add(-30*time.Second)) || !now.Before(expires) {
		return "", ErrPeerTransfer
	}
	sig, e := base64.RawURLEncoding.Strict().DecodeString(t.Signature.Value)
	payload := peerTicketPayload(t)
	sum := sha256.Sum256(payload)
	if e != nil || !ecdsa.VerifyASN1(public, sum[:], sig) {
		return "", ErrPeerTransfer
	}
	return hex.EncodeToString(sum[:]), nil
}

type VerifiedPeerArtifact struct {
	ArtifactID, ManifestDigest, ContentDigest, Path string
	SizeBytes                                       int64
}
type PeerArtifactSource struct {
	HostID, SignerID string
	PublicKey        *ecdsa.PublicKey
	ObjectsDir       string
	Artifacts        map[string]VerifiedPeerArtifact
	Now              func() time.Time
	Revoked          func(PeerTransferTicket) bool
}

func (s *PeerArtifactSource) Read(ticket PeerTransferTicket, offset, length int64) (PeerTransferChunk, error) {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	if _, e := AuthenticatePeerTransferTicket(ticket, s.PublicKey, s.SignerID, s.HostID, "source", now()); e != nil || s.Revoked != nil && s.Revoked(ticket) || offset < 0 || length < 1 || length > ticket.ChunkBytes || offset+length > ticket.SizeBytes {
		return PeerTransferChunk{}, ErrPeerTransfer
	}
	a, ok := s.Artifacts[ticket.ArtifactID]
	clean := filepath.Clean(a.Path)
	root := filepath.Clean(s.ObjectsDir)
	rel, e := filepath.Rel(root, clean)
	if !ok || !filepath.IsAbs(root) || e != nil || rel == "." || rel == ".." || len(rel) > 2 && rel[:3] == ".."+string(os.PathSeparator) || a.ArtifactID != ticket.ArtifactID || a.ManifestDigest != ticket.ManifestDigest || a.ContentDigest != ticket.ContentDigest || a.SizeBytes != ticket.SizeBytes {
		return PeerTransferChunk{}, ErrPeerTransfer
	}
	f, e := os.Open(clean)
	if e != nil {
		return PeerTransferChunk{}, ErrPeerTransfer
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() != ticket.SizeBytes {
		return PeerTransferChunk{}, ErrPeerTransfer
	}
	b := make([]byte, length)
	if _, e = f.ReadAt(b, offset); e != nil {
		return PeerTransferChunk{}, ErrPeerTransfer
	}
	sum := sha256.Sum256(b)
	return PeerTransferChunk{Offset: offset, Bytes: b, Digest: hex.EncodeToString(sum[:])}, nil
}

type PeerArtifactDestination struct {
	HostID, SignerID string
	PublicKey        *ecdsa.PublicKey
	CacheDir         string
	Now              func() time.Time
	Revoked          func(PeerTransferTicket) bool
}

func (d *PeerArtifactDestination) Accept(ticket PeerTransferTicket, chunk PeerTransferChunk) (PeerTransferCheckpoint, error) {
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	at := now().UTC()
	digest, e := AuthenticatePeerTransferTicket(ticket, d.PublicKey, d.SignerID, d.HostID, "destination", at)
	if e != nil || d.Revoked != nil && d.Revoked(ticket) {
		return PeerTransferCheckpoint{}, ErrPeerTransfer
	}
	if !filepath.IsAbs(d.CacheDir) || filepath.Clean(d.CacheDir) != d.CacheDir {
		return PeerTransferCheckpoint{}, ErrPeerTransfer
	}
	partial := filepath.Join(d.CacheDir, "peer-partial")
	objects := filepath.Join(d.CacheDir, "objects")
	if ensureCacheDir(d.CacheDir) != nil || ensureCacheDir(partial) != nil || ensureCacheDir(objects) != nil {
		return PeerTransferCheckpoint{}, ErrPeerTransfer
	}
	part := filepath.Join(partial, digest+".part")
	meta := filepath.Join(partial, digest+".json")
	target := filepath.Join(objects, ticket.ContentDigest)
	cp := PeerTransferCheckpoint{TransferID: ticket.TransferID, TicketDigest: digest, ChainDigest: string(bytes.Repeat([]byte{'0'}, 64)), Status: "authorized", UpdatedAt: at.Format("2006-01-02T15:04:05.000Z")}
	raw, metaErr := os.ReadFile(meta)
	if metaErr == nil {
		if len(raw) > 4096 || json.Unmarshal(raw, &cp) != nil || cp.TransferID != ticket.TransferID || cp.TicketDigest != digest {
			return PeerTransferCheckpoint{}, ErrPeerTransfer
		}
		if cp.Status == "failed" || cp.Status == "received" {
			return cp, ErrPeerTransfer
		}
		if cp.Status != "transferring" || recoverPeerCheckpoint(part, target, meta, ticket, &cp) != nil {
			return PeerTransferCheckpoint{}, ErrPeerTransfer
		}
		if cp.Status == "received" {
			if cp.LastLength > 0 && chunk.Offset == cp.LastOffset && int64(len(chunk.Bytes)) == cp.LastLength && chunk.Digest == cp.LastDigest {
				return cp, nil
			}
			return cp, ErrPeerTransfer
		}
	} else if !errors.Is(metaErr, os.ErrNotExist) {
		return PeerTransferCheckpoint{}, ErrPeerTransfer
	} else if _, statErr := os.Stat(part); !errors.Is(statErr, os.ErrNotExist) {
		return PeerTransferCheckpoint{}, ErrPeerTransfer
	}
	if cp.LastLength > 0 && chunk.Offset == cp.LastOffset && int64(len(chunk.Bytes)) == cp.LastLength && chunk.Digest == cp.LastDigest && chunk.Offset+int64(len(chunk.Bytes)) == cp.NextOffset {
		return cp, nil
	}
	if chunk.Offset != cp.NextOffset || len(chunk.Bytes) < 1 || int64(len(chunk.Bytes)) > ticket.ChunkBytes || chunk.Offset+int64(len(chunk.Bytes)) > ticket.SizeBytes {
		return PeerTransferCheckpoint{}, ErrPeerTransfer
	}
	sum := sha256.Sum256(chunk.Bytes)
	if hex.EncodeToString(sum[:]) != chunk.Digest {
		code := "chunk-digest-mismatch"
		cp.Status = "failed"
		cp.TerminalCode = &code
		cp.UpdatedAt = at.Format("2006-01-02T15:04:05.000Z")
		_ = writePeerCheckpoint(meta, cp)
		return cp, ErrPeerTransfer
	}
	pending := chunk.Offset
	cp.PendingOffset, cp.PendingLength, cp.PendingDigest, cp.Status = &pending, int64(len(chunk.Bytes)), chunk.Digest, "transferring"
	if e = writePeerCheckpoint(meta, cp); e != nil {
		return PeerTransferCheckpoint{}, e
	}
	f, e := os.OpenFile(part, os.O_CREATE|os.O_WRONLY, 0o600)
	if e != nil {
		return PeerTransferCheckpoint{}, ErrPeerTransfer
	}
	if _, e = f.Seek(cp.NextOffset, io.SeekStart); e == nil {
		_, e = f.Write(chunk.Bytes)
	}
	if e == nil {
		e = f.Sync()
	}
	_ = f.Close()
	if e != nil {
		return PeerTransferCheckpoint{}, ErrPeerTransfer
	}
	chain := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%d:%s", cp.ChainDigest, chunk.Offset, len(chunk.Bytes), chunk.Digest)))
	cp.NextOffset += int64(len(chunk.Bytes))
	cp.ChunkCount++
	cp.ChainDigest = hex.EncodeToString(chain[:])
	cp.LastOffset, cp.LastLength, cp.LastDigest = chunk.Offset, int64(len(chunk.Bytes)), chunk.Digest
	cp.PendingOffset, cp.PendingLength, cp.PendingDigest = nil, 0, ""
	cp.Status = "transferring"
	cp.UpdatedAt = at.Format("2006-01-02T15:04:05.000Z")
	if cp.NextOffset == ticket.SizeBytes {
		if verifyFile(part, ticket.SizeBytes, ticket.ContentDigest) != nil {
			code := "content-digest-mismatch"
			cp.Status = "failed"
			cp.TerminalCode = &code
			_ = writePeerCheckpoint(meta, cp)
			return cp, ErrPeerTransfer
		}
		if e = os.Rename(part, target); e != nil {
			return PeerTransferCheckpoint{}, ErrPeerTransfer
		}
		if e = os.Chmod(target, 0o400); e != nil {
			return PeerTransferCheckpoint{}, ErrPeerTransfer
		}
		if e = syncDirectory(objects); e != nil {
			return PeerTransferCheckpoint{}, ErrPeerTransfer
		}
		cp.Status = "received"
		if e = writePeerCheckpoint(meta, cp); e != nil {
			return PeerTransferCheckpoint{}, ErrPeerTransfer
		}
		return cp, nil
	}
	if e = writePeerCheckpoint(meta, cp); e != nil {
		return PeerTransferCheckpoint{}, e
	}
	return cp, nil
}

func recoverPeerCheckpoint(part, target, meta string, ticket PeerTransferTicket, cp *PeerTransferCheckpoint) error {
	// Publication may have completed before its ACK checkpoint. The immutable
	// target is the authority only after full size+digest verification.
	if cp.PendingOffset != nil && *cp.PendingOffset+cp.PendingLength == ticket.SizeBytes && verifyFile(target, ticket.SizeBytes, ticket.ContentDigest) == nil {
		chain := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%d:%s", cp.ChainDigest, *cp.PendingOffset, cp.PendingLength, cp.PendingDigest)))
		cp.LastOffset, cp.LastLength, cp.LastDigest = *cp.PendingOffset, cp.PendingLength, cp.PendingDigest
		cp.NextOffset, cp.ChunkCount, cp.ChainDigest = ticket.SizeBytes, cp.ChunkCount+1, hex.EncodeToString(chain[:])
		cp.PendingOffset, cp.PendingLength, cp.PendingDigest, cp.Status = nil, 0, "", "received"
		return writePeerCheckpoint(meta, *cp)
	}
	if cp.PendingOffset == nil {
		st, err := os.Stat(part)
		if err == nil && st.Mode().IsRegular() && st.Size() == cp.NextOffset {
			return nil
		}
		if errors.Is(err, os.ErrNotExist) && cp.NextOffset == ticket.SizeBytes && verifyFile(target, ticket.SizeBytes, ticket.ContentDigest) == nil {
			cp.Status = "received"
			return writePeerCheckpoint(meta, *cp)
		}
		return ErrPeerTransfer
	}
	if *cp.PendingOffset != cp.NextOffset || cp.PendingLength < 1 || !digestPattern.MatchString(cp.PendingDigest) {
		return ErrPeerTransfer
	}
	st, err := os.Stat(part)
	if errors.Is(err, os.ErrNotExist) && cp.NextOffset == 0 {
		cp.PendingOffset, cp.PendingLength, cp.PendingDigest = nil, 0, ""
		return writePeerCheckpoint(meta, *cp)
	}
	if err != nil || !st.Mode().IsRegular() {
		return ErrPeerTransfer
	}
	if st.Size() == cp.NextOffset {
		cp.PendingOffset, cp.PendingLength, cp.PendingDigest = nil, 0, ""
		return writePeerCheckpoint(meta, *cp)
	}
	if st.Size() != cp.NextOffset+cp.PendingLength {
		return ErrPeerTransfer
	}
	f, err := os.Open(part)
	if err != nil {
		return ErrPeerTransfer
	}
	defer f.Close()
	b := make([]byte, cp.PendingLength)
	if _, err = f.ReadAt(b, cp.NextOffset); err != nil {
		return ErrPeerTransfer
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != cp.PendingDigest {
		return ErrPeerTransfer
	}
	chain := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%d:%s", cp.ChainDigest, cp.NextOffset, cp.PendingLength, cp.PendingDigest)))
	cp.LastOffset, cp.LastLength, cp.LastDigest = cp.NextOffset, cp.PendingLength, cp.PendingDigest
	cp.NextOffset += cp.PendingLength
	cp.ChunkCount++
	cp.ChainDigest = hex.EncodeToString(chain[:])
	cp.PendingOffset, cp.PendingLength, cp.PendingDigest = nil, 0, ""
	return writePeerCheckpoint(meta, *cp)
}

func (d *PeerArtifactDestination) Receipt(ticket PeerTransferTicket) (PeerTransferReceipt, error) {
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	digest, err := AuthenticatePeerTransferTicket(ticket, d.PublicKey, d.SignerID, d.HostID, "destination", now())
	if err != nil || d.Revoked != nil && d.Revoked(ticket) {
		return PeerTransferReceipt{}, ErrPeerTransfer
	}
	var cp PeerTransferCheckpoint
	raw, err := os.ReadFile(filepath.Join(d.CacheDir, "peer-partial", digest+".json"))
	object := filepath.Join(d.CacheDir, "objects", ticket.ContentDigest)
	if err != nil || json.Unmarshal(raw, &cp) != nil || cp.Status != "received" || cp.NextOffset != ticket.SizeBytes || verifyFile(object, ticket.SizeBytes, ticket.ContentDigest) != nil {
		return PeerTransferReceipt{}, ErrPeerTransfer
	}
	return PeerTransferReceipt{TransferID: ticket.TransferID, ArtifactID: ticket.ArtifactID, ManifestDigest: ticket.ManifestDigest, ContentDigest: ticket.ContentDigest, SizeBytes: ticket.SizeBytes, ObjectPath: object}, nil
}
func writePeerCheckpoint(path string, value PeerTransferCheckpoint) error {
	raw, e := json.Marshal(value)
	if e != nil {
		return ErrPeerTransfer
	}
	tmp, e := os.CreateTemp(filepath.Dir(path), ".peer-checkpoint-")
	if e != nil {
		return ErrPeerTransfer
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
		return ErrPeerTransfer
	}
	if _, e = tmp.Write(append(raw, '\n')); e != nil || tmp.Sync() != nil || tmp.Close() != nil {
		return ErrPeerTransfer
	}
	if os.Rename(name, path) != nil {
		return ErrPeerTransfer
	}
	ok = true
	return syncDirectory(filepath.Dir(path))
}
