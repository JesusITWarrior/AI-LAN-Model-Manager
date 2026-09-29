package command

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	PeerSourceOperation      = "peer-transfer.source"
	PeerDestinationOperation = "peer-transfer.destination"
)

type peerSourceDirective struct {
	Ticket PeerTransferTicket `json:"ticket"`
	Offset int64              `json:"offset"`
	Length int64              `json:"length"`
}
type peerDestinationDirective struct {
	Ticket PeerTransferTicket `json:"ticket"`
	Chunk  PeerTransferChunk  `json:"chunk"`
}
type PeerDestinationResult struct {
	Checkpoint PeerTransferCheckpoint `json:"checkpoint"`
	Receipt    *PeerTransferReceipt   `json:"receipt,omitempty"`
}

// PeerRelayDirective is the exact controller command-poll extension. It carries
// no URL, path, header, or trust-root input; transport remains the enrolled
// fixed-origin mTLS command channel.
type PeerRelayDirective struct {
	Version     int                `json:"version"`
	Action      string             `json:"action"`
	TransferID  string             `json:"transferId"`
	Role        string             `json:"role"`
	Ticket      PeerTransferTicket `json:"ticket"`
	Offset      int64              `json:"offset"`
	Length      int64              `json:"length"`
	ChunkBase64 *string            `json:"chunkBase64"`
	ChunkDigest *string            `json:"chunkDigest"`
}

type peerArtifactWireReceipt struct {
	Version           int    `json:"version"`
	TransferID        string `json:"transferId"`
	ArtifactID        string `json:"artifactId"`
	DestinationHostID string `json:"destinationHostId"`
	SizeBytes         int64  `json:"sizeBytes"`
	ContentDigest     string `json:"contentDigest"`
	ChainDigest       string `json:"chainDigest"`
	CommittedAt       string `json:"committedAt"`
}

type PeerRelayResult struct {
	Version     int                      `json:"version"`
	Action      string                   `json:"action"`
	TransferID  string                   `json:"transferId"`
	Role        string                   `json:"role"`
	Offset      int64                    `json:"offset"`
	Status      string                   `json:"status"`
	ChunkBase64 *string                  `json:"chunkBase64"`
	ChunkDigest *string                  `json:"chunkDigest"`
	NextOffset  int64                    `json:"nextOffset"`
	ChainDigest string                   `json:"chainDigest"`
	SizeBytes   *int64                   `json:"sizeBytes"`
	Receipt     *peerArtifactWireReceipt `json:"receipt"`
}

// PeerRelay handles only controller-signed, host-bound directives received by
// the existing fixed-origin mTLS command poll. It has no endpoint or header
// inputs and is disabled unless explicitly installed in Registry.
type PeerRelay struct {
	Source      *PeerArtifactSource
	Destination *PeerArtifactDestination
}

func decodePeerDirective(raw json.RawMessage, out any) error {
	if len(raw) == 0 || len(raw) > 768<<10 {
		return ErrPeerTransfer
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(&struct{}{}) != io.EOF {
		return ErrPeerTransfer
	}
	return nil
}

// ExecuteDirective handles the poll extension and emits the exact bounded
// result accepted by the controller relay. The final write ACK intentionally
// remains transferring; only a separate commit directive returns received.
func (p *PeerRelay) ExecuteDirective(ctx context.Context, raw json.RawMessage) (PeerRelayResult, error) {
	var v PeerRelayDirective
	if p == nil || ctx.Err() != nil || decodePeerDirective(raw, &v) != nil || v.Version != 1 || v.TransferID != v.Ticket.TransferID || v.Offset < 0 || v.Length < 0 || v.Length > 384000 {
		return PeerRelayResult{}, ErrPeerTransfer
	}
	base := PeerRelayResult{Version: 1, Action: v.Action, TransferID: v.TransferID, Role: v.Role, Offset: v.Offset, Status: "transferring", NextOffset: v.Offset, ChainDigest: string(bytes.Repeat([]byte{'0'}, 64))}
	switch v.Action {
	case "read":
		if v.Role != "source" || p.Source == nil || v.Length < 1 || v.ChunkBase64 != nil || v.ChunkDigest != nil {
			return PeerRelayResult{}, ErrPeerTransfer
		}
		chunk, err := p.Source.Read(v.Ticket, v.Offset, v.Length)
		if err != nil {
			return PeerRelayResult{}, err
		}
		encoded := base64.StdEncoding.EncodeToString(chunk.Bytes)
		base.ChunkBase64, base.ChunkDigest = &encoded, &chunk.Digest
		return base, nil
	case "write":
		if v.Role != "destination" || p.Destination == nil || v.Length < 1 || v.ChunkBase64 == nil || v.ChunkDigest == nil {
			return PeerRelayResult{}, ErrPeerTransfer
		}
		data, err := base64.StdEncoding.Strict().DecodeString(*v.ChunkBase64)
		if err != nil || int64(len(data)) != v.Length {
			return PeerRelayResult{}, ErrPeerTransfer
		}
		cp, err := p.Destination.Accept(v.Ticket, PeerTransferChunk{Offset: v.Offset, Bytes: data, Digest: *v.ChunkDigest})
		if err != nil {
			return PeerRelayResult{}, err
		}
		base.NextOffset, base.ChainDigest = cp.NextOffset, cp.ChainDigest
		return base, nil
	case "commit":
		if v.Role != "destination" || p.Destination == nil || v.Length != 0 || v.Offset != v.Ticket.SizeBytes || v.ChunkBase64 != nil || v.ChunkDigest != nil {
			return PeerRelayResult{}, ErrPeerTransfer
		}
		receipt, err := p.Destination.Receipt(v.Ticket)
		if err != nil {
			return PeerRelayResult{}, err
		}
		digest, err := AuthenticatePeerTransferTicket(v.Ticket, p.Destination.PublicKey, p.Destination.SignerID, p.Destination.HostID, "destination", p.Destination.now())
		if err != nil {
			return PeerRelayResult{}, err
		}
		var cp PeerTransferCheckpoint
		meta, err := os.ReadFile(filepath.Join(p.Destination.CacheDir, "peer-partial", digest+".json"))
		if err != nil || json.Unmarshal(meta, &cp) != nil || cp.Status != "received" {
			return PeerRelayResult{}, ErrPeerTransfer
		}
		at := p.Destination.now().UTC().Format("2006-01-02T15:04:05.000Z")
		wire := &peerArtifactWireReceipt{Version: 1, TransferID: receipt.TransferID, ArtifactID: receipt.ArtifactID, DestinationHostID: v.Ticket.DestinationHostID, SizeBytes: receipt.SizeBytes, ContentDigest: receipt.ContentDigest, ChainDigest: cp.ChainDigest, CommittedAt: at}
		size := receipt.SizeBytes
		base.Status, base.NextOffset, base.ChainDigest, base.SizeBytes, base.Receipt = "received", size, cp.ChainDigest, &size, wire
		return base, nil
	default:
		return PeerRelayResult{}, ErrPeerTransfer
	}
}

func (d *PeerArtifactDestination) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (p *PeerRelay) Execute(ctx context.Context, operation string, raw json.RawMessage) (any, error) {
	if p == nil || ctx.Err() != nil {
		return nil, ErrPeerTransfer
	}
	switch operation {
	case PeerSourceOperation:
		if p.Source == nil {
			return nil, ErrPeerTransfer
		}
		var v peerSourceDirective
		if decodePeerDirective(raw, &v) != nil {
			return nil, ErrPeerTransfer
		}
		return p.Source.Read(v.Ticket, v.Offset, v.Length)
	case PeerDestinationOperation:
		if p.Destination == nil {
			return nil, ErrPeerTransfer
		}
		var v peerDestinationDirective
		if decodePeerDirective(raw, &v) != nil {
			return nil, ErrPeerTransfer
		}
		checkpoint, err := p.Destination.Accept(v.Ticket, v.Chunk)
		if err != nil {
			return PeerDestinationResult{Checkpoint: checkpoint}, err
		}
		result := PeerDestinationResult{Checkpoint: checkpoint}
		if checkpoint.Status == "received" {
			receipt, e := p.Destination.Receipt(v.Ticket)
			if e != nil {
				return result, e
			}
			result.Receipt = &receipt
		}
		return result, nil
	default:
		return nil, ErrPeerTransfer
	}
}
