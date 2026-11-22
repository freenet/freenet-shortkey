//! Offline client for the short-key resolver.
//!
//! Network operations (publish, resolve, update-data) are STUBS: they print the exact
//! `fdev` invocation to run against a node instead of opening a WebSocket. Everything
//! else (derive, contract-key, make-state, verify, merge) is real and offline.

use ed25519_dalek::SigningKey;
use freenet_shortkey_common::*;
use freenet_stdlib::prelude::*;
use std::process::exit;

const USAGE: &str = "usage:
  freenet-shortkey derive <vk-base58>                       short handle for a full key
  freenet-shortkey parse <base58>                           classify a handle or full key
  freenet-shortkey contract-key <wasm> <handle>             resolver contract key
  freenet-shortkey make-state <vk-base58> <out>             write the minimal state
  freenet-shortkey sign-state <sk-hex> <rev> <fmt> <data-file> <out>   write a signed state
  freenet-shortkey verify <handle> <state-file>             check binding and signature
  freenet-shortkey merge <handle> <state-a> <state-b> <out> merge two states
  freenet-shortkey publish|resolve|update-data ...          print the fdev command (stub)";

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("error: {msg}");
    exit(1)
}

fn vk_arg(s: &str) -> [u8; KEY_LEN] {
    match parse_locator(s) {
        Ok(Locator::Full(k)) => k,
        Ok(_) => die("expected a 32-byte public key, got a short handle"),
        Err(e) => die(e),
    }
}

fn read_state(path: &str) -> ResolverState {
    let b = std::fs::read(path).unwrap_or_else(|e| die(format!("{path}: {e}")));
    ResolverState::decode(&b).unwrap_or_else(|e| die(e))
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let s = |i: usize| a.get(i).map(String::as_str).unwrap_or_else(|| die(USAGE));
    match s(0) {
        "derive" => println!("{}", ShortId::derive(&vk_arg(s(1)))),
        "parse" => match parse_locator(s(1)).unwrap_or_else(|e| die(e)) {
            Locator::Short(id) => println!("short handle {id}"),
            Locator::Full(k) => println!("full key {} (handle {})", s(1), ShortId::derive(&k)),
        },
        "contract-key" => {
            let wasm = std::fs::read(s(1)).unwrap_or_else(|e| die(e));
            let id = ShortId::from_base58(s(2)).unwrap_or_else(|e| die(e));
            let code = ContractCode::from(wasm);
            let key = ContractKey::from_params_and_code(Parameters::from(id.0.to_vec()), &code);
            println!("code hash:    {}", code.hash());
            println!("contract id:  {}", key.id());
        }
        "make-state" => {
            let st = ResolverState::minimal(vk_arg(s(1)));
            std::fs::write(s(2), st.encode()).unwrap_or_else(|e| die(e));
            println!("handle {}", st.short_id());
        }
        "sign-state" => {
            let sk: [u8; 32] = decode_hex(s(1)).try_into().unwrap_or_else(|_| die("sk must be 32 bytes hex"));
            let key = SigningKey::from_bytes(&sk);
            let rev: u64 = s(2).parse().unwrap_or_else(|_| die("bad revision"));
            let fmt: u16 = s(3).parse().unwrap_or_else(|_| die("bad format"));
            let data = std::fs::read(s(4)).unwrap_or_else(|e| die(e));
            let signed = SignedData::sign(&key, rev, fmt, data).unwrap_or_else(|e| die(e));
            let st = ResolverState { vk: *key.verifying_key().as_bytes(), signed: Some(signed) };
            std::fs::write(s(5), st.encode()).unwrap_or_else(|e| die(e));
            println!("handle {} revision {rev}", st.short_id());
        }
        "verify" => {
            let id = ShortId::from_base58(s(1)).unwrap_or_else(|e| die(e));
            read_state(s(2)).verify(&id).unwrap_or_else(|e| die(e));
            println!("ok");
        }
        "merge" => {
            let id = ShortId::from_base58(s(1)).unwrap_or_else(|e| die(e));
            let (mut x, y) = (read_state(s(2)), read_state(s(3)));
            x.verify(&id).unwrap_or_else(|e| die(e));
            y.verify(&id).unwrap_or_else(|e| die(e));
            x.merge(&y).unwrap_or_else(|e| die(e));
            std::fs::write(s(4), x.encode()).unwrap_or_else(|e| die(e));
            println!("ok");
        }
        "publish" | "resolve" | "update-data" => {
            println!("network call is a stub. Compute the key with `contract-key`, then use fdev:");
            println!("  publish/update-data: fdev execute put --code <wasm> --parameters <16-byte params file> contract --state <state-file>");
            println!("  resolve:             fdev execute get <contract-id>");
        }
        _ => die(USAGE),
    }
}

fn decode_hex(h: &str) -> Vec<u8> {
    if h.len() % 2 != 0 {
        die("odd-length hex");
    }
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap_or_else(|_| die("bad hex")))
        .collect()
}
