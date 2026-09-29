import { createHash } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import {
  applyPeerTransferChunk,
  authenticatePeerTransferTicket,
  createPeerTransferCheckpoint,
  finalizePeerTransferCommit,
  parsePeerRelayResult,
  parsePeerTransferCheckpoint,
  parsePeerTransferTicket,
  peerTransferTicketPayload,
  terminatePeerTransfer,
  type ArtifactAuthenticator,
  type ArtifactCacheRegistry,
  type CacheLease,
  type PeerArtifactReceipt,
  type PeerRelayDirective,
  type PeerRelayResult,
  type PeerTransferCheckpoint,
  type PeerTransferTicket,
} from "@lan-model-manager/core";

export const PEER_RELAY_CHUNK_LIMIT = 384_000;
export const PEER_RELAY_POLL_MS = 20;

export interface PeerChunkSource {
  prepare?(ticket: PeerTransferTicket): void;
  read(input: { readonly transferId: string; readonly sourceHostId: string; readonly destinationHostId: string; readonly artifactId?: string; readonly offset: number; readonly length: number; readonly signal: AbortSignal }): Promise<Readonly<{ bytes: Uint8Array; digest: string }>>;
}
export interface PeerChunkSink {
  write(input: { readonly transferId: string; readonly destinationHostId: string; readonly offset: number; readonly bytes: Uint8Array; readonly signal: AbortSignal }): Promise<boolean>;
  finalize(input: { readonly transferId: string; readonly destinationHostId: string; readonly artifactId: string; readonly sizeBytes: number; readonly contentDigest: string; readonly chainDigest: string; readonly signal: AbortSignal }): Promise<boolean>;
  receipt?(transferId: string): PeerArtifactReceipt | null;
  discard?(transferId: string): Promise<void> | void;
}
export interface PeerTransferCheckpointStore { load(transferId: string): PeerTransferCheckpoint | null; save(checkpoint: PeerTransferCheckpoint): void }

export class SqlitePeerTransferCheckpointStore implements PeerTransferCheckpointStore {
  constructor(private readonly db: DatabaseSync) {}
  load(transferId: string): PeerTransferCheckpoint | null {
    const row = this.db.prepare("SELECT checkpoint_json FROM peer_transfers WHERE transfer_id=?").get(transferId) as { checkpoint_json: string } | undefined;
    if (!row) return null;
    try { const parsed = parsePeerTransferCheckpoint(JSON.parse(row.checkpoint_json)); return parsed.ok ? parsed.value : null; } catch { return null; }
  }
  save(value: PeerTransferCheckpoint): void {
    const parsed = parsePeerTransferCheckpoint(value);
    if (!parsed.ok) throw new Error("ERR_TRANSFER_CHECKPOINT");
    this.db.prepare("INSERT INTO peer_transfers(transfer_id,checkpoint_json,status,updated_at) VALUES(?,?,?,?) ON CONFLICT(transfer_id) DO UPDATE SET checkpoint_json=excluded.checkpoint_json,status=excluded.status,updated_at=excluded.updated_at").run(value.transferId, JSON.stringify(value), value.status, value.updatedAt);
  }
  active(): PeerTransferCheckpoint[] {
    const rows = this.db.prepare("SELECT p.checkpoint_json FROM peer_transfers p LEFT JOIN peer_relay_chunks r ON r.transfer_id=p.transfer_id WHERE p.status IN ('authorized','transferring') AND (r.transfer_id IS NULL OR r.phase NOT IN ('failed','committed')) ORDER BY p.transfer_id").all() as Array<{ checkpoint_json: string }>;
    return rows.flatMap(row => { try { const parsed = parsePeerTransferCheckpoint(JSON.parse(row.checkpoint_json)); return parsed.ok ? [parsed.value] : []; } catch { return []; } });
  }
}

export interface PeerTransferCoordinatorOptions {
  readonly authenticator: ArtifactAuthenticator;
  readonly source: PeerChunkSource;
  readonly sink: PeerChunkSink;
  readonly checkpoints: PeerTransferCheckpointStore;
  readonly clock: () => string;
  readonly sourceCache?: ArtifactCacheRegistry;
  readonly destinationCache?: ArtifactCacheRegistry;
}

export class PeerTransferCoordinator {
  private readonly leases = new Map<string, Readonly<{ source: CacheLease | undefined; destination: CacheLease | undefined }>>();
  constructor(private readonly options: PeerTransferCoordinatorOptions) {}

  /** Reacquire both eviction leases after a controller restart before work is resumed. */
  reconstructLeases(): number {
    if (!(this.options.checkpoints instanceof SqlitePeerTransferCheckpointStore)) return 0;
    let count = 0;
    for (const state of this.options.checkpoints.active()) {
      try { this.hold(state.transferId, state.artifactId); count++; } catch { /* unavailable cache remains closed */ }
    }
    return count;
  }

  async run(ticketInput: unknown, signal: AbortSignal): Promise<PeerTransferCheckpoint | null> {
    const authorized = authenticatePeerTransferTicket(ticketInput, this.options.authenticator, this.now());
    if (!authorized.ok) return null;
    const ticket = authorized.ticket;
    let state = this.options.checkpoints.load(ticket.transferId);
    if (state) {
      const parsed = parsePeerTransferCheckpoint(state);
      if (!parsed.ok || parsed.value.ticketDigest !== authorized.ticketDigest || parsed.value.artifactId !== ticket.artifactId || parsed.value.sourceHostId !== ticket.sourceHostId || parsed.value.destinationHostId !== ticket.destinationHostId || parsed.value.expectedDigest !== ticket.contentDigest || parsed.value.sizeBytes !== ticket.sizeBytes || parsed.value.chunkBytes !== ticket.chunkBytes) return null;
      state = parsed.value;
    } else {
      state = createPeerTransferCheckpoint(ticket, this.options.authenticator, this.now());
      if (!state) return null;
      this.options.checkpoints.save(state);
    }
    if (state.status === "received") return state;
    if (!(["authorized", "transferring"] as const).includes(state.status as "authorized" | "transferring")) return null;
    try {
      this.hold(ticket.transferId, ticket.artifactId);
      this.options.source.prepare?.(ticket);
      while (state.nextOffset < ticket.sizeBytes) {
        const current = authenticatePeerTransferTicket(ticket, this.options.authenticator, this.now());
        if (!current.ok) {
          state = terminatePeerTransfer(state, current.error === "ERR_TRANSFER_EXPIRED" ? "expired" : "revoked", this.now())!;
          this.options.checkpoints.save(state); await this.options.sink.discard?.(ticket.transferId); return state;
        }
        if (signal.aborted) throw new DOMException("Aborted", "AbortError");
        const length = Math.min(ticket.chunkBytes, ticket.sizeBytes - state.nextOffset), offset = state.nextOffset;
        const chunk = await this.options.source.read({ transferId: ticket.transferId, sourceHostId: ticket.sourceHostId, destinationHostId: ticket.destinationHostId, artifactId: ticket.artifactId, offset, length, signal });
        if (!(chunk.bytes instanceof Uint8Array) || chunk.bytes.byteLength !== length || typeof chunk.digest !== "string") throw new Error("ERR_TRANSFER_CHUNK");
        const next = applyPeerTransferChunk(state, { offset, bytes: chunk.bytes, digest: chunk.digest, at: this.now() });
        if (!next) throw new Error("ERR_TRANSFER_CHECKPOINT");
        if (next.status === "failed") { state = next; this.options.checkpoints.save(state); await this.options.sink.discard?.(ticket.transferId); return state; }
        if (!await this.options.sink.write({ transferId: ticket.transferId, destinationHostId: ticket.destinationHostId, offset, bytes: chunk.bytes, signal })) throw new Error("ERR_TRANSFER_DESTINATION");
        state = next;
        this.options.checkpoints.save(state);
      }
      if (!await this.options.sink.finalize({ transferId: ticket.transferId, destinationHostId: ticket.destinationHostId, artifactId: ticket.artifactId, sizeBytes: ticket.sizeBytes, contentDigest: ticket.contentDigest, chainDigest: state.chainDigest, signal })) {
        state = terminatePeerTransfer(state, "content-digest-mismatch", this.now())!;
        this.options.checkpoints.save(state); await this.options.sink.discard?.(ticket.transferId); return state;
      }
      const committed = finalizePeerTransferCommit(state, { sizeBytes: ticket.sizeBytes, contentDigest: ticket.contentDigest, at: this.now() });
      if (!committed) throw new Error("ERR_TRANSFER_COMMIT");
      state = committed; this.options.checkpoints.save(state); return state;
    } catch (error) {
      if ((signal.aborted || error instanceof DOMException && error.name === "AbortError") && (state.status === "authorized" || state.status === "transferring")) {
        state = terminatePeerTransfer(state, "cancelled", this.now())!; this.options.checkpoints.save(state); await this.options.sink.discard?.(ticket.transferId);
      } else if (state.status === "authorized" || state.status === "transferring") {
        const current = authenticatePeerTransferTicket(ticket, this.options.authenticator, this.now());
        const relayFailed = this.options.source instanceof PeerChunkRelay && this.options.source.failed(ticket.transferId);
        if (!current.ok || relayFailed) {
          state = terminatePeerTransfer(state, !current.ok && current.error === "ERR_TRANSFER_EXPIRED" ? "expired" : relayFailed ? "relay-failed" : "revoked", this.now())!;
          this.options.checkpoints.save(state);
        }
      }
      return state;
    } finally { if (["received", "cancelled", "failed"].includes(state.status)) this.release(ticket.transferId); }
  }
  private hold(transferId: string, artifactId: string): void {
    if (this.leases.has(transferId)) return;
    let source: CacheLease | undefined, destination: CacheLease | undefined;
    try { source = this.options.sourceCache?.acquire(artifactId); destination = this.options.destinationCache?.acquire(artifactId); this.leases.set(transferId, Object.freeze({ source, destination })); }
    catch (error) { destination?.release(); source?.release(); throw error; }
  }
  private release(transferId: string): void { const value = this.leases.get(transferId); if (!value) return; this.leases.delete(transferId); value.destination?.release(); value.source?.release(); }
  private now(): string { const value = this.options.clock(); if (typeof value !== "string" || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) throw new Error("ERR_TRANSFER_CLOCK"); return value; }
}

export interface PeerTransferCompositionOptions { readonly enabled?: boolean; readonly db: DatabaseSync; readonly authenticator: ArtifactAuthenticator; readonly clock?: () => string; readonly sourceCache?: ArtifactCacheRegistry; readonly destinationCache?: ArtifactCacheRegistry }
export type PeerTransferComposition = Readonly<{ checkpoints: SqlitePeerTransferCheckpointStore; relay: PeerChunkRelay | null; coordinator: PeerTransferCoordinator | null }>;
/** Explicit production composition. Omitted/false enabled keeps relay execution closed. */
export function createPeerTransferComposition(options: PeerTransferCompositionOptions): PeerTransferComposition {
  const checkpoints = new SqlitePeerTransferCheckpointStore(options.db);
  if (options.enabled !== true) return Object.freeze({ checkpoints, relay: null, coordinator: null });
  const relay = new PeerChunkRelay(options.db, options.authenticator, options.clock);
  const coordinator = new PeerTransferCoordinator({ authenticator: options.authenticator, source: relay, sink: relay, checkpoints, clock: options.clock ?? (() => new Date().toISOString()), ...(options.sourceCache ? { sourceCache: options.sourceCache } : {}), ...(options.destinationCache ? { destinationCache: options.destinationCache } : {}) });
  coordinator.reconstructLeases();
  return Object.freeze({ checkpoints, relay, coordinator });
}

export interface PeerTransferTicketSigner { readonly signerId: string; sign(payload: Uint8Array): Uint8Array }
export function issuePeerTransferTicket(input: Omit<PeerTransferTicket, "version" | "signerId" | "signature">, signer: PeerTransferTicketSigner): PeerTransferTicket | null {
  const unsigned = { version: 1 as const, ...input, signerId: signer.signerId, signature: { algorithm: "ecdsa-p256-sha256" as const, value: "A".repeat(86) } };
  if (!parsePeerTransferTicket(unsigned).ok || input.chunkBytes > PEER_RELAY_CHUNK_LIMIT) return null;
  const payload = peerTransferTicketPayload(unsigned); if (!payload) return null;
  try { const ticket = { ...unsigned, signature: { algorithm: "ecdsa-p256-sha256" as const, value: Buffer.from(signer.sign(payload)).toString("base64url") } }; return parsePeerTransferTicket(ticket).ok ? Object.freeze(ticket) : null; } catch { return null; }
}

type RelayRow = { transfer_id: string; ticket_json: string; ticket_digest: string; source_host_id: string; destination_host_id: string; artifact_id: string; offset: number; length: number; phase: string; chunk_base64: string | null; chunk_digest: string | null; destination_chain_digest: string | null; receipt_json: string | null; expires_at: string; updated_at: string };

/** SQLite rendezvous used exclusively by the existing authenticated command poll/result channel. */
export class PeerChunkRelay implements PeerChunkSource, PeerChunkSink {
  constructor(private readonly db: DatabaseSync, private readonly authenticator: ArtifactAuthenticator, private readonly clock: () => string = () => new Date().toISOString(), private readonly pollMs = PEER_RELAY_POLL_MS) { if (!Number.isSafeInteger(pollMs) || pollMs < 5 || pollMs > 1000) throw new Error("ERR_TRANSFER_RELAY"); const now=this.now();this.db.prepare("UPDATE peer_relay_chunks SET phase='failed',updated_at=? WHERE expires_at<=? AND phase NOT IN ('committed','failed')").run(now,now); }
  prepare(ticket: PeerTransferTicket): void {
    const auth = authenticatePeerTransferTicket(ticket, this.authenticator, this.now()); if (!auth.ok || ticket.chunkBytes > PEER_RELAY_CHUNK_LIMIT) throw new Error("ERR_TRANSFER_RELAY");
    const existing = this.row(ticket.transferId);
    if (existing && (existing.ticket_digest !== auth.ticketDigest || existing.source_host_id !== ticket.sourceHostId || existing.destination_host_id !== ticket.destinationHostId || existing.artifact_id !== ticket.artifactId)) throw new Error("ERR_TRANSFER_RELAY");
    if (!existing) this.db.prepare("INSERT INTO peer_relay_chunks(transfer_id,ticket_json,ticket_digest,source_host_id,destination_host_id,artifact_id,offset,length,phase,chunk_base64,chunk_digest,destination_chain_digest,receipt_json,expires_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").run(ticket.transferId, JSON.stringify(ticket), auth.ticketDigest, ticket.sourceHostId, ticket.destinationHostId, ticket.artifactId, 0, 0, "idle", null, null, null, null, ticket.expiresAt, this.now());
  }
  async read(input: Parameters<PeerChunkSource["read"]>[0]): Promise<Readonly<{ bytes: Uint8Array; digest: string }>> {
    if (!input.artifactId || input.length < 1 || input.length > PEER_RELAY_CHUNK_LIMIT) throw new Error("ERR_TRANSFER_RELAY");
    const row = this.bound(input.transferId, input.sourceHostId, input.destinationHostId, input.artifactId);
    if (!row || Date.parse(this.now()) >= Date.parse(row.expires_at) || !["idle", "source-pending", "chunk-ready", "destination-pending"].includes(row.phase)) throw new Error("ERR_TRANSFER_RELAY");
    if (row.phase === "idle") this.db.prepare("UPDATE peer_relay_chunks SET offset=?,length=?,phase='source-pending',chunk_base64=NULL,chunk_digest=NULL,updated_at=? WHERE transfer_id=? AND phase='idle'").run(input.offset, input.length, this.now(), input.transferId);
    else if (row.offset !== input.offset || row.length !== input.length) throw new Error("ERR_TRANSFER_RELAY");
    const ready = await this.wait(input.transferId, input.signal, value => ["chunk-ready", "destination-pending"].includes(value.phase) && value.chunk_base64 !== null && value.chunk_digest !== null);
    const bytes = Buffer.from(ready.chunk_base64!, "base64");
    if (bytes.byteLength !== input.length || createHash("sha256").update(bytes).digest("hex") !== ready.chunk_digest) throw new Error("ERR_TRANSFER_RELAY");
    return Object.freeze({ bytes, digest: ready.chunk_digest! });
  }
  async write(input: Parameters<PeerChunkSink["write"]>[0]): Promise<boolean> {
    const row = this.row(input.transferId); if (!row || row.destination_host_id !== input.destinationHostId || row.offset !== input.offset || !row.chunk_base64 || Buffer.compare(Buffer.from(row.chunk_base64, "base64"), Buffer.from(input.bytes)) !== 0) return false;
    if (row.phase === "chunk-ready") this.db.prepare("UPDATE peer_relay_chunks SET phase='destination-pending',updated_at=? WHERE transfer_id=? AND phase='chunk-ready'").run(this.now(), input.transferId);
    const ack = await this.wait(input.transferId, input.signal, value => value.phase === "idle" || value.phase === "failed");
    return ack.phase === "idle";
  }
  async finalize(input: Parameters<PeerChunkSink["finalize"]>[0]): Promise<boolean> {
    const row = this.row(input.transferId); if (!row || row.destination_host_id !== input.destinationHostId || row.artifact_id !== input.artifactId || row.phase !== "idle") return false;
    this.db.prepare("UPDATE peer_relay_chunks SET offset=?,length=0,phase='commit-pending',destination_chain_digest=?,updated_at=? WHERE transfer_id=? AND phase='idle'").run(input.sizeBytes, input.chainDigest, this.now(), input.transferId);
    const committed = await this.wait(input.transferId, input.signal, value => value.phase === "committed" || value.phase === "failed");
    if (committed.phase !== "committed" || !committed.receipt_json) return false;
    try { const receipt = JSON.parse(committed.receipt_json) as PeerArtifactReceipt; return receipt.sizeBytes === input.sizeBytes && receipt.contentDigest === input.contentDigest; } catch { return false; }
  }
  receipt(transferId: string): PeerArtifactReceipt | null { const row = this.row(transferId); if (row?.phase !== "committed" || !row.receipt_json) return null; try { return JSON.parse(row.receipt_json) as PeerArtifactReceipt; } catch { return null; } }
  poll(hostId: string): PeerRelayDirective | null {
    const now = this.now();
    this.db.prepare("UPDATE peer_relay_chunks SET phase='failed',updated_at=? WHERE expires_at<=? AND phase NOT IN ('committed','failed')").run(now, now);
    const row = this.db.prepare("SELECT * FROM peer_relay_chunks WHERE (source_host_id=? AND phase='source-pending') OR (destination_host_id=? AND phase IN ('destination-pending','commit-pending')) ORDER BY updated_at,transfer_id LIMIT 1").get(hostId, hostId) as RelayRow | undefined;
    if (!row) return null;
    const ticket = JSON.parse(row.ticket_json) as PeerTransferTicket;
    if (row.phase === "source-pending") return Object.freeze({ version: 1, action: "read", transferId: row.transfer_id, role: "source", ticket, offset: row.offset, length: row.length, chunkBase64: null, chunkDigest: null });
    if (row.phase === "destination-pending") return Object.freeze({ version: 1, action: "write", transferId: row.transfer_id, role: "destination", ticket, offset: row.offset, length: row.length, chunkBase64: row.chunk_base64!, chunkDigest: row.chunk_digest! });
    return Object.freeze({ version: 1, action: "commit", transferId: row.transfer_id, role: "destination", ticket, offset: row.offset, length: 0, chunkBase64: null, chunkDigest: null });
  }
  complete(hostId: string, input: unknown): boolean {
    const parsed = parsePeerRelayResult(input); if (!parsed.ok) return false; const result = parsed.value, row = this.row(result.transferId); if (!row || Date.parse(this.now()) >= Date.parse(row.expires_at)) return false;
    if (result.action === "read") {
      if (row.phase !== "source-pending" || hostId !== row.source_host_id || result.role !== "source" || result.offset !== row.offset || !result.chunkBase64 || !result.chunkDigest) return false;
      const bytes = Buffer.from(result.chunkBase64, "base64"); if (bytes.byteLength !== row.length || createHash("sha256").update(bytes).digest("hex") !== result.chunkDigest) return false;
      return this.changed("UPDATE peer_relay_chunks SET phase='chunk-ready',chunk_base64=?,chunk_digest=?,updated_at=? WHERE transfer_id=? AND phase='source-pending'", result.chunkBase64, result.chunkDigest, this.now(), row.transfer_id);
    }
    if (result.action === "write") {
      if (row.phase !== "destination-pending" || hostId !== row.destination_host_id || result.role !== "destination" || result.offset !== row.offset || result.nextOffset !== row.offset + row.length || result.status !== "transferring") return false;
      return this.changed("UPDATE peer_relay_chunks SET phase='idle',offset=?,length=0,chunk_base64=NULL,chunk_digest=NULL,destination_chain_digest=?,updated_at=? WHERE transfer_id=? AND phase='destination-pending'", result.nextOffset, result.chainDigest, this.now(), row.transfer_id);
    }
    if (row.phase !== "commit-pending" || hostId !== row.destination_host_id || result.role !== "destination" || result.status !== "received" || result.nextOffset !== row.offset || result.sizeBytes !== row.offset || !result.receipt || result.receipt.transferId !== row.transfer_id || result.receipt.artifactId !== row.artifact_id || result.receipt.destinationHostId !== row.destination_host_id || result.receipt.sizeBytes !== row.offset) return false;
    const ticket = JSON.parse(row.ticket_json) as PeerTransferTicket; if (result.receipt.contentDigest !== ticket.contentDigest || result.receipt.chainDigest !== row.destination_chain_digest) return false;
    return this.changed("UPDATE peer_relay_chunks SET phase='committed',receipt_json=?,updated_at=? WHERE transfer_id=? AND phase='commit-pending'", JSON.stringify(result.receipt), this.now(), row.transfer_id);
  }
  revoke(transferId: string): boolean { return this.changed("UPDATE peer_relay_chunks SET phase='failed',updated_at=? WHERE transfer_id=? AND phase NOT IN ('committed','failed')", this.now(), transferId); }
  failed(transferId: string): boolean { return this.row(transferId)?.phase === "failed"; }
  discard(transferId: string): void { this.revoke(transferId); }
  private row(transferId: string): RelayRow | undefined { return this.db.prepare("SELECT * FROM peer_relay_chunks WHERE transfer_id=?").get(transferId) as RelayRow | undefined; }
  private bound(transferId: string, source: string, destination: string, artifact: string): RelayRow | null { const row = this.row(transferId); return row && row.source_host_id === source && row.destination_host_id === destination && row.artifact_id === artifact ? row : null; }
  private changed(sql: string, ...args: Array<string | number | null | Uint8Array>): boolean { return Number(this.db.prepare(sql).run(...args).changes) === 1; }
  private async wait(transferId: string, signal: AbortSignal, predicate: (row: RelayRow) => boolean): Promise<RelayRow> { for (;;) { if (signal.aborted) throw new DOMException("Aborted", "AbortError"); const row = this.row(transferId); if (!row || row.phase === "failed" || Date.parse(this.now()) >= Date.parse(row.expires_at)) throw new Error("ERR_TRANSFER_RELAY"); if (predicate(row)) return row; await new Promise<void>((resolve, reject) => { const timer = setTimeout(done, this.pollMs); function done() { signal.removeEventListener("abort", abort); resolve(); } function abort() { clearTimeout(timer); signal.removeEventListener("abort", abort); reject(new DOMException("Aborted", "AbortError")); } signal.addEventListener("abort", abort, { once: true }); }); } }
  private now(): string { const value = this.clock(); if (typeof value !== "string" || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) throw new Error("ERR_TRANSFER_CLOCK"); return value; }
}
