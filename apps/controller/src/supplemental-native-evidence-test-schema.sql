-- Test-only, explicitly opt-in SQLite fixture. Never registered with controller migrations.
CREATE TABLE audit_events (
  seq INTEGER PRIMARY KEY CHECK(seq > 0),
  event_json TEXT NOT NULL CHECK(json_valid(event_json)),
  body_json TEXT NOT NULL CHECK(json_valid(body_json)),
  outcome TEXT NOT NULL CHECK(outcome IN ('observed','allowed','denied','started','succeeded','failed','cancelled')),
  previous_hash TEXT CHECK(previous_hash IS NULL OR length(previous_hash)=64),
  hash TEXT NOT NULL UNIQUE CHECK(length(hash)=64),
  created_at TEXT NOT NULL
) STRICT;

-- Lifecycle sentinel tables used only to prove this store does not rewrite history/results.
CREATE TABLE jobs (job_id TEXT PRIMARY KEY, payload_json TEXT NOT NULL CHECK(json_valid(payload_json))) STRICT;
CREATE TABLE job_history (history_id INTEGER PRIMARY KEY, job_id TEXT NOT NULL, event_json TEXT NOT NULL CHECK(json_valid(event_json))) STRICT;
CREATE TABLE agent_commands (job_id TEXT PRIMARY KEY, result_json TEXT CHECK(result_json IS NULL OR json_valid(result_json))) STRICT;

CREATE TABLE evidence_commit_guard (guard_id INTEGER PRIMARY KEY) STRICT;
INSERT INTO evidence_commit_guard(guard_id) VALUES(1);

CREATE TABLE supplemental_native_evidence (
  commit_guard_id INTEGER NOT NULL DEFAULT 1 REFERENCES evidence_commit_guard(guard_id) DEFERRABLE INITIALLY DEFERRED,
  tuple_digest TEXT PRIMARY KEY CHECK(length(tuple_digest)=64 AND tuple_digest NOT GLOB '*[^0-9a-f]*'),
  tuple_json TEXT NOT NULL CHECK(json_valid(tuple_json) AND length(tuple_json)<=4096),
  payload_bytes BLOB NOT NULL CHECK(length(payload_bytes)>0 AND length(payload_bytes)<=786432),
  payload_digest TEXT NOT NULL CHECK(length(payload_digest)=64 AND payload_digest NOT GLOB '*[^0-9a-f]*'),
  response_bytes BLOB NOT NULL CHECK(length(response_bytes)>0 AND length(response_bytes)<=524288),
  response_digest TEXT NOT NULL CHECK(length(response_digest)=64 AND response_digest NOT GLOB '*[^0-9a-f]*'),
  response_byte_length INTEGER NOT NULL CHECK(response_byte_length>0 AND response_byte_length<=524288 AND response_byte_length=length(response_bytes)),
  owner_id TEXT NOT NULL CHECK(length(owner_id) BETWEEN 1 AND 128),
  session_binding_digest TEXT NOT NULL CHECK(length(session_binding_digest)=64 AND session_binding_digest NOT GLOB '*[^0-9a-f]*'),
  credential_version INTEGER NOT NULL CHECK(credential_version>0),
  host_certificate_binding_digest TEXT NOT NULL CHECK(length(host_certificate_binding_digest)=64 AND host_certificate_binding_digest NOT GLOB '*[^0-9a-f]*'),
  consent_action TEXT NOT NULL CHECK(consent_action='append-supplemental-native-evidence'),
  consent_disposition TEXT NOT NULL CHECK(consent_disposition='evidence-only'),
  consented_at TEXT NOT NULL,
  consent_json TEXT NOT NULL CHECK(json_valid(consent_json) AND length(consent_json)<=2048),
  consent_binding_digest TEXT NOT NULL CHECK(length(consent_binding_digest)=64 AND consent_binding_digest NOT GLOB '*[^0-9a-f]*'),
  receipt_core_json TEXT NOT NULL CHECK(json_valid(receipt_core_json) AND length(receipt_core_json)<=2048),
  committed_at TEXT NOT NULL
) STRICT;

-- REPLACE can delete a conflicting row without DELETE triggers when recursive_triggers
-- is OFF. Reject any second INSERT for an existing tuple before conflict handling.
CREATE TRIGGER supplemental_native_evidence_no_replace
BEFORE INSERT ON supplemental_native_evidence
WHEN EXISTS(SELECT 1 FROM supplemental_native_evidence WHERE tuple_digest=NEW.tuple_digest)
BEGIN SELECT RAISE(ABORT,'supplemental evidence tuple already exists'); END;

CREATE TRIGGER supplemental_native_evidence_no_update
BEFORE UPDATE ON supplemental_native_evidence
BEGIN SELECT RAISE(ABORT,'supplemental evidence is append-only'); END;
CREATE TRIGGER supplemental_native_evidence_no_delete
BEFORE DELETE ON supplemental_native_evidence
BEGIN SELECT RAISE(ABORT,'supplemental evidence is append-only'); END;
