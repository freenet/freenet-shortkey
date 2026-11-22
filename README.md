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

**Validation.** `vk` must be the canonical 32-byte encoding of an Ed25519 point in the
prime-order subgroup (not the identity). Non-canonical encodings (y >= p), small-order points
and mixed-order points `A + T` are all rejected, so each real key has exactly one accepted
form and therefore exactly one handle. `BLAKE3(domain || vk)[..16]` must equal the parameters. The minimal mapping needs no
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

**Update variants.** `update_state` merges `State`, `Delta` and both halves of `StateAndDelta`
(an empty delta is skipped). `RelatedState`, `RelatedDelta` and `RelatedStateAndDelta` carry
another contract's data, and `UpdateData` is `#[non_exhaustive]`, so those and any future
variant are skipped rather than failing the batch. An empty summary is read as "the peer
holds nothing".

**Size limit.** `data` is at most 16 KiB (`MAX_DATA_LEN`), so the largest state is 16,496
bytes (1 + 32 + 1 + 8 + 2 + 4 + 16,384 + 64).

**Revisions are write-once and monotonic.** There is no rotation, tombstone, revocation or
successor pointer: the highest revision wins and nothing can lower it. An owner may choose
`revision = u64::MAX`, which is final (only a same-revision state with a smaller signature can
replace it), and that choice is irreversible. This only affects the key's owner; it is kept
because locking is the owner's decision. Use small increments. An owner can also grind
signatures to win the equal-revision tie-break against their own states; that is harmless to
anyone else. The owner key must only ever sign structured messages (never arbitrary
attacker-chosen bytes), because it signs messages beginning `freenet-shortkey/v1/data`.

**Golden vectors.** `crates/common/src/tests.rs` pins, for the key `SigningKey([1; 32])`,
the exact signed message, the minimal and signed state encodings (including the Ed25519
signature, which is deterministic) and the summary encodings as hex. Other clients (River UI,
JS) must reproduce these bytes.

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

The id is 128 bits of a hash. Two risks differ by cost:

- Targeted second preimage (an attacker wants a key that maps to a victim's handle): about
  2^128 work. Infeasible.
- Birthday collision (an attacker grinds two keys that share a handle): about 2^64 work.
  Large, but within reach of a well-funded adversary. The attacker holds both keys, so this
  lets them show different people different owners for one handle, but it cannot take over
  a handle that someone else already derived from their own key.

**Consensus effect of a collision.** Both colliding keys produce states that pass
`validate_state`, but `merge` returns `KeyMismatch` between them, so `update_state` fails.
Different peers can therefore hold different keys for one address and never converge
(summaries do not carry `vk`, so repair keeps shipping states the receiver rejects). This only
affects the attacker's own pair of keys. The merge laws above hold per key.

2^64 is the handle-uniqueness ceiling, and 128-bit handles accept it. Checking that the
resolved key hashes back to the handle does NOT detect a deliberate collision. Applications
that need more than 64-bit collision resistance should use the full key for trust decisions
and treat the handle as a locator.

## WASM stability

The resolver address depends on the WASM code hash. Changing the WASM changes every
resolver address, so a rebuild is NEVER incidental. The build is pinned by
`rust-toolchain.toml` (1.94.1), `Cargo.lock` (`--locked`), the release profile in
`Cargo.toml`, the pinned `freenet-stdlib` and the path-remap flags in `scripts/build-wasm.sh`.
A new WASM is a new GENERATION (`v2`, a new derive domain if the derivation changes, a new
published artifact under `wasm/`), with the old generation kept resolvable. Never overwrite
`wasm/freenet_shortkey_v1.wasm`.

Generation 1 (`wasm/freenet_shortkey_v1.wasm`, rustc 1.94.1, freenet-stdlib 0.12.1):

- BLAKE3 of the WASM file (hex): `7fd0f944cb9d9cb04673288846c4434525d5d103deebcde257e290c1900d04c5`
- Freenet code hash as the CLI prints it (base58): `9bwbWefShTXmVrizwn4XQ3NdT1Zjm7rm1uWLUAwqewuW`
- Example: handle `DX4ZCXQ4NZgiw1Cuh8YjuC` resolves at contract id `6ThwP2dPt1LNYY7p1hpmdpm6uNKrrVed6qjmYbFmU6Db`.

These three values are pinned by the test `committed_wasm_hash_and_contract_id_are_pinned`
(`crates/contract/tests/contract.rs`), which computes them from the committed file, so the
documents cannot drift from the artifact.

Reproducibility: `scripts/build-wasm.sh` remaps the configured `CARGO_HOME`, `RUSTUP_HOME`
and the workspace path, so the bytes do not depend on where Rust is installed or where the
repository is checked out. Verified by rebuilding a copy of the tree at a different path with
a different `CARGO_HOME` and comparing (identical bytes); CI repeats this under a different
`CARGO_HOME` (`wasm-frozen-other-cargo-home`). Formatting shifts panic line numbers baked into
the WASM, so run `cargo fmt` before building; CI checks both.

## Testing

```
cargo test --locked                 # 12 + 17 unit/protocol tests (common), 10 contract tests
```

Native tests call the contract as a Rust library, so the committed WASM was also run as WASM
(2026-11-22) on a real local node: `freenet local --ws-api-port 17531` (freenet 0.2.162, private
data dir, `--disable-auto-update`) driven with `fdev 0.3.295 -p 17531 execute ...`, using
`wasm/freenet_shortkey_v1.wasm` (BLAKE3 `7fd0f944...04c5`) and states made by the CLI for the key
`SigningKey([1; 32])` (handle `SuTtS5xX1UrqpMXjwEzCC2`, contract id
`6eoC9xFsag1ZoFEM2SAV2rY5RzXKLhqrdt6zK4i2m6TU`, which equals `contract-key` output):

| step | result |
|---|---|
| `put --parameters params.bin contract --state min.bin` | published at the predicted id |
| `get` | 34 bytes, identical to `min.bin` |
| `update --as-state r1.bin` (revision 1, signed) | accepted; `get` returns `r1.bin` byte for byte |
| `update r2.bin` (revision 2, as a delta) | accepted; `get` returns `r2.bin` |
| stale `update --as-state r1.bin` | accepted, state stays `r2.bin` (no regression) |
| `update` with another key's state | rejected: `key does not hash to the short id` |
| `update` with a flipped data byte | rejected: `data signature does not verify` |
| `update` with delta `junk` | rejected: `malformed encoding: unknown version`; state still `r2.bin` |
| `put` key 1's state under key 2's parameters | rejected: `key does not hash to the short id` |
| `put` key 2's minimal state under key 2's parameters | published |

This exercises validate, update (state and delta), summarize and get-delta (the node calls
them during update) and the error paths under `panic=abort`. The `StateAndDelta`, `Related*`
and empty-summary paths are only reachable from the library tests, because the node flattens
`StateAndDelta` before the WASM sees it and `fdev` cannot send the others.

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
