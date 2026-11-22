#!/usr/bin/env bash
# Reproducible WASM build. The code hash depends on rustc (pinned in rust-toolchain.toml),
# Cargo.lock (--locked) and these flags. Do not change any of them without a new generation.
set -euo pipefail
cd "$(dirname "$0")/.."
RUSTFLAGS="--remap-path-prefix=$PWD=/src --remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME/.rustup=/rustup" \
  cargo build --locked --release --target wasm32-unknown-unknown -p freenet-shortkey-contract
mkdir -p wasm
cp target/wasm32-unknown-unknown/release/freenet_shortkey_contract.wasm wasm/freenet_shortkey_v1.wasm
echo "blake3: $(b3sum wasm/freenet_shortkey_v1.wasm | cut -d' ' -f1)"
