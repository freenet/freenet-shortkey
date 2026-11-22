#!/usr/bin/env bash
# Reproducible WASM build. The code hash depends on rustc (pinned in rust-toolchain.toml),
# Cargo.lock (--locked) and these flags. Do not change any of them without a new generation.
#
# The WASM embeds the source paths of dependencies (/cargo/registry/src/...). Remapping the
# CONFIGURED cargo and rustup homes (not just $HOME/.cargo) makes the bytes independent of
# where they are installed, e.g. the official `rust` Docker image uses /usr/local/cargo.
set -euo pipefail
cd "$(dirname "$0")/.."
CARGO_DIR="$(readlink -f "${CARGO_HOME:-$HOME/.cargo}")"
RUSTUP_DIR="$(readlink -f "${RUSTUP_HOME:-$HOME/.rustup}")"
RUSTFLAGS="--remap-path-prefix=$PWD=/src --remap-path-prefix=$CARGO_DIR=/cargo --remap-path-prefix=$RUSTUP_DIR=/rustup" \
  cargo build --locked --release --target wasm32-unknown-unknown -p freenet-shortkey-contract
mkdir -p wasm
cp target/wasm32-unknown-unknown/release/freenet_shortkey_contract.wasm wasm/freenet_shortkey_v1.wasm
# Hash with the workspace's own CLI so no external b3sum is needed; fail loudly if empty.
hash="$(cargo run --locked --quiet -p freenet-shortkey-cli -- hash wasm/freenet_shortkey_v1.wasm)"
if [ "${#hash}" -ne 64 ]; then
  echo "failed to compute the BLAKE3 hash (got '$hash')" >&2
  exit 1
fi
echo "blake3: $hash"
