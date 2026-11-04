# Certificate serial identity and compatibility

Certificate identity uses **positive uppercase numeric hexadecimal**, with no
leading zeroes (for example Node's `01` is `1`, `0ABC` is `ABC`). Zero, signs,
non-hexadecimal characters, lowercase wire/metadata serials and serials longer
than 40 hexadecimal characters are rejected. This matches Go's positive
`SerialNumber.Text(16)` after uppercasing. Fingerprints remain exact SHA-256
identities; numeric serial equivalence does not replace fingerprint, CA
signature, host, address, validity, or active/revoked binding checks.

New issuance metadata, repository writes, parsed certificates, production
controller signers and agent envelope construction emit this numeric form.
Existing uppercase byte-padded certificate rows and enrollment metadata remain
readable. Repository lookup uses the unique exact fingerprint index and then
checks numeric serial equality; it does not scan or rewrite certificate history.

**Do not normalize received signed envelopes.** Their original `certSerial`
string is part of the signed field bytes. Verification uses that original string,
while certificate identity comparisons accept equivalent legacy byte padding.
Both control and stream replay lanes retain their fingerprint keys, sequence
high-water marks, nonce/request checks and ordering. Old padded replay serials
compare numerically without resetting any high-water mark.

Migration 17 is needed solely because migration 8's replay serial CHECK excluded
one-digit numeric serials. It transactionally replaces only that replay table
with a one-character minimum, preserving all rows byte-for-byte, indexes and all
prior migration ledger entries. It does not canonicalize historical rows.

Updated controller and agent binaries interoperate with existing certificates.
An **old** controller still has its original exact-lookup defect and an **old**
Go agent still rejects a byte-padded controller signed response. Upgrading this
code does not patch already-running old binaries; upgrade both sides to obtain
bidirectional compatibility. No CA, certificate signature, fingerprint or replay
validation is bypassed to accommodate those old binaries.
