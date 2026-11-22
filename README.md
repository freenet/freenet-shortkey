# freenet-shortkey

A generic Freenet contract that resolves a 128-bit short id to a full Ed25519 public key,
optionally carrying owner-signed, versioned application data. It contains no application
logic (no River membership, no Atlas policy); any app can use it.

## Protocol

**Short id.** `short_id = BLAKE3("freenet-shortkey/v1" || vk)[..16]`, where `vk` is the 32-byte
Ed25519 verifying key. The input has a fixed length, so plain concatenation is unambiguous.

**Resolver address.** The contract PARAMETERS are the 16 raw bytes of the short id. The
contract key is `BLAKE3(BLAKE3(wasm) || params)`, so anyone can compute a resolver's address
from a handle and the frozen WASM, with no lookup.

**State** (canonical binary, all integers big-endian):

```
minimal: [0x01][vk:32][0x00]
signed:  [0x01][vk:32][0x01][revision:u64][format:u16][len:u32][data:len][signature:64]
```

Trailing bytes, unknown versions, unknown flags and `len > 16384` are rejected.

**Validation.** `vk` must be a valid, non-small-order Ed25519 point, and
`BLAKE3(domain || vk)[..16]` must equal the parameters. The minimal mapping needs no
signature, so anyone can reconstruct it from the key. If data is present, the signature must
verify (`verify_strict`) under `vk` over
`"freenet-shortkey/v1/data" || short_id || revision || format || len || data`.
The short id is inside the signed message, so a signature cannot be replayed under another
resolver. `revision` orders updates; `format` is the application's schema number and is
independent of it.

**Merge.** Higher `revision` wins. At equal revision with different content, the
lexicographically smaller signature wins (the signature covers the content, so this is a total
order). A state with no data never erases data. Merge is commutative, associative and
idempotent (fork test: `fork_merge_order_independent`).

**Summary / delta.** Summary is `[0x01][0]` (no data) or `[0x01][1][revision:u64][BLAKE3(signature):32]`.
A delta is a full state encoding carrying the sender's data, and is empty when the peer's
summary shows data at least as new. At equal revision with a different digest both sides send;
merge picks the same winner on both.

**Size limit.** `data` is at most 16 KiB (`MAX_DATA_LEN`), so the whole state is under 16.5 KiB.

## Handle text encoding: base58

Bitcoin-alphabet base58 of the 16 raw bytes, 21 or 22 characters. Chosen because River and
Freenet already show keys in base58, it avoids the ambiguous characters `0 O I l`, it has no
punctuation (safe in URLs, selectable by double-click), and it is shorter than hex (32) and
close to base64 (22) without `+ / =`. The decoder is strict: it rejects bad characters, any
length other than 16 bytes, and non-canonical spellings, so each id has one text form. A full
key (32 bytes, 43-44 characters) and a short id are told apart by decoded length
(`parse_locator`).

Test vectors (pinned in `crates/common/tests/protocol.rs`):

| vk | short id (hex) | handle |
|---|---|---|
| `00` x 32 | `65602aff592963c36beeaa812aa12b83` | `DX4ZCXQ4NZgiw1Cuh8YjuC` |
| `01` x 32 | `8c35f5bdd1081c19e80c6e1e3af9817d` | `JKCi2BXwJLh46QKm3Sf46p` |
| `ff` x 32 | `562bd5927a6025d29a6f5cdd4eaefc17` | `BeAcviiYQKaBSC15JkK1TL` |

## Collision analysis

The id is 128 bits of a hash. Finding two keys with the same id (a birthday collision) costs
about 2^64 key generations and hashes, which is a large but not infeasible attack for a
well-funded adversary; a targeted second-preimage against a chosen victim key costs about
2^128. The attack that matters is the first: an attacker who grinds two keys with one id can
present one to different audiences. Mitigations: the resolver address is first-come per id
and contents are verified against the full key, so a collision does not let anyone overwrite
an existing owner's key (the state's `vk` must hash to the id, and the colliding key hashes to
the same id, so a collision pair is the residual risk). Applications that need more than
64-bit collision resistance should use the full key for trust decisions and treat the handle
as a locator. Clients must always verify that the resolved key hashes back to the handle.

## WASM stability

The resolver address depends on the WASM code hash. Changing the WASM changes every
resolver address, so a rebuild is NEVER incidental. The build is pinned by
`rust-toolchain.toml` (1.94.1), `Cargo.lock` (`--locked`), the release profile in
`Cargo.toml`, the pinned `freenet-stdlib` and the path-remap flags in `scripts/build-wasm.sh`.
A new WASM is a new GENERATION (`v2`, a new derive domain if the derivation changes, a new
published artifact under `wasm/`), with the old generation kept resolvable. Never overwrite
`wasm/freenet_shortkey_v1.wasm`.

Generation 1 code hash (BLAKE3 of `wasm/freenet_shortkey_v1.wasm`): see the section below.

## Layout and commands

- `crates/common`: types, derivation, encoding, verification, merge (uses `std`; not `no_std`).
- `crates/contract`: the WASM contract.
- `crates/cli`: `freenet-shortkey` binary. `derive`, `parse`, `contract-key`, `make-state`,
  `sign-state`, `verify`, `merge` are real and offline. `publish`, `resolve` and
  `update-data` are STUBS that print the `fdev` command; no WebSocket client is wired up.

```
cargo test --locked                 # all tests
./scripts/build-wasm.sh             # reproducible WASM build, prints the code hash
```
