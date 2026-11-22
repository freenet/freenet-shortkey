# FREENET.md

A generic Freenet contract that resolves a 128-bit short id to a full Ed25519 public key,
with optional owner-signed versioned data. Full protocol: [README.md](README.md).

- **Parameters:** the 16-byte short id, `BLAKE3("freenet-shortkey/v1" || vk)[..16]`.
- **State:** `[1][vk:32][0]` (minimal) or `[1][vk:32][1][revision:u64][format:u16][len:u32][data][sig:64]`.
  The key binding is checked without a signature; data needs the owner's signature.
- **Merge:** higher revision wins, then the smaller signature; minimal state never erases data.
- **Handle text:** base58 of the 16 bytes (21 or 22 characters).
- **Frozen WASM:** `wasm/freenet_shortkey_v1.wasm`. Changing it changes every resolver address,
  so a change is a new generation, never a rebuild. CI fails if a rebuild differs.

Generation 1 code hash (base58): `8Yd1baYj1jh7ZowdAzGbYbZRSfaQAAxeHpx4HpyP42Vh` (BLAKE3 hex `701b87d00748639f6e826cf887bed69fd2979cb39e7374bc79d4d4b717d56f3c`).
