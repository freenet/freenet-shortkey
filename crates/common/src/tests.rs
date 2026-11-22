//! Unit tests that need private items (`SignedData::verify`) or exact byte vectors.

use super::*;
use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---- golden vectors: other clients (River UI, JS) must reproduce these bytes ----------------

const VK1_HEX: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
const MESSAGE_HEX: &str =
    "667265656e65742d73686f72746b65792f76312f64617461d1c7b64c1c2975499c7d7e670a44b303000000000000000701020000000568656c6c6f";
const SIGNED_STATE_HEX: &str =
    "018a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c01000000000000000701020000000568656c6c6f06c8882da21b217f86411af088be78fb28514d12b860e5e832ad4e455fbc4d270f315f6a2734df066c496cccd798b4283bfc71473613e6dee540228b7bc9eb0e";
const MINIMAL_STATE_HEX: &str =
    "018a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c00";
const SUMMARY_HEX: &str =
    "01010000000000000007f4401226bbb6bf9684a4195ebd0c68e6d57ff12d536ff88c87236b4f5f8815e1";
const SUMMARY_NONE_HEX: &str = "0100";

#[test]
fn golden_vectors() {
    let k = key(1);
    let vk = *k.verifying_key().as_bytes();
    let id = ShortId::derive(&vk);
    let signed = SignedData::sign(&k, 7, 0x0102, b"hello".to_vec()).unwrap();
    let st = ResolverState {
        vk,
        signed: Some(signed.clone()),
    };
    let msg = SignedData::message(&id, 7, 0x0102, b"hello");
    assert_eq!(hex(&vk), VK1_HEX);
    assert_eq!(hex(&msg), MESSAGE_HEX);
    assert_eq!(hex(&st.encode()), SIGNED_STATE_HEX);
    assert_eq!(hex(&ResolverState::minimal(vk).encode()), MINIMAL_STATE_HEX);
    assert_eq!(hex(&st.summary().encode()), SUMMARY_HEX);
    assert_eq!(hex(&Summary { head: None }.encode()), SUMMARY_NONE_HEX);
    // the pinned bytes decode back and verify
    let decoded = ResolverState::decode(&hex_to_bytes(SIGNED_STATE_HEX)).unwrap();
    assert_eq!(decoded, st);
    decoded.verify(&id).unwrap();
}

fn hex_to_bytes(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

// ---- signature checks that must reach the signature --------------------------------------------

#[test]
fn signature_is_bound_to_short_id() {
    // A valid key and a valid signature for id1 must fail on the SIGNATURE (not on the key
    // binding) when presented for id2, so the id really is inside the signed message.
    let k = key(1);
    let vk = k.verifying_key();
    let id1 = ShortId::derive(vk.as_bytes());
    let id2 = ShortId::derive(key(2).verifying_key().as_bytes());
    let s = SignedData::sign(&k, 1, 1, b"x".to_vec()).unwrap();
    assert_eq!(s.verify(&vk, &id1), Ok(()));
    assert_eq!(s.verify(&vk, &id2), Err(Error::BadSignature));
}

#[test]
fn signature_covers_every_field() {
    let k = key(1);
    let vk = k.verifying_key();
    let id = ShortId::derive(vk.as_bytes());
    let s = SignedData::sign(&k, 5, 9, b"data".to_vec()).unwrap();
    for t in [
        SignedData {
            revision: 6,
            ..s.clone()
        },
        SignedData {
            format: 10,
            ..s.clone()
        },
        SignedData {
            data: b"datb".to_vec(),
            ..s.clone()
        },
    ] {
        assert_eq!(t.verify(&vk, &id), Err(Error::BadSignature));
    }
}

/// `verify_strict` must stay: with a small-order key and the identity signature, plain
/// `verify` accepts any message, strict does not. Fails if `verify` replaces `verify_strict`.
#[test]
fn verify_strict_is_used() {
    use ed25519_dalek::Verifier;
    let mut identity = [0u8; 32];
    identity[0] = 1; // y = 1: the identity point, small order
    let weak = VerifyingKey::from_bytes(&identity).unwrap();
    let mut sig = [0u8; SIG_LEN];
    sig[0] = 1; // R = identity, S = 0
    let s = SignedData {
        revision: 1,
        format: 1,
        data: b"anything".to_vec(),
        signature: sig,
    };
    let id = ShortId::derive(&identity);
    let msg = SignedData::message(&id, 1, 1, b"anything");
    // non-vacuous: the non-strict check really accepts this forgery
    assert!(weak.verify(&msg, &Signature::from_bytes(&sig)).is_ok());
    assert_eq!(s.verify(&weak, &id), Err(Error::BadSignature));
}

// ---- key validity ----------------------------------------------------------------------------

#[test]
fn honest_keys_are_valid() {
    for seed in [0u8, 1, 2, 77, 255] {
        let vk = *key(seed).verifying_key().as_bytes();
        assert!(validate_key(&vk).is_ok());
    }
}

fn state_for(vk: [u8; KEY_LEN]) -> (ResolverState, ShortId) {
    let st = ResolverState::minimal(vk);
    let id = st.short_id();
    (st, id)
}

/// Non-canonical encodings (y >= p) exist only for y < 19. Every such y that is a curve point
/// has a torsion component (only y = 1, the identity, is torsion-free), so no honest key has a
/// non-canonical alias; this checks that dalek would accept those aliases and we do not.
#[test]
fn non_canonical_encodings_rejected() {
    let mut accepted_by_dalek = 0;
    for y in 0u8..19 {
        for sign in [0u8, 0x80] {
            // little-endian y + p, where p = 2^255 - 19 = ed ff .. ff 7f
            let mut alias = [0xffu8; 32];
            alias[31] = 0x7f | sign;
            alias[0] = 0xed + y; // 0xed + 18 = 0xff: no carry
            if VerifyingKey::from_bytes(&alias).is_ok() {
                accepted_by_dalek += 1;
                assert_eq!(
                    validate_key(&alias),
                    Err(Error::BadKey),
                    "y={y} sign={sign}"
                );
                let (st, id) = state_for(alias);
                assert_eq!(st.verify(&id), Err(Error::BadKey));
            }
        }
    }
    assert!(
        accepted_by_dalek > 0,
        "dalek accepts no alias: test is vacuous"
    );
}

#[test]
fn sign_bit_on_zero_x_rejected() {
    // y = 1 with the sign bit set encodes the identity non-canonically (x = 0)
    let mut b = [0u8; 32];
    b[0] = 1;
    b[31] = 0x80;
    assert_eq!(validate_key(&b), Err(Error::BadKey));
}

#[test]
fn small_order_keys_rejected() {
    for t in EIGHT_TORSION {
        assert_eq!(validate_key(&t.compress().to_bytes()), Err(Error::BadKey));
    }
}

#[test]
fn mixed_order_keys_rejected() {
    // A + T for an honest key A and a nonzero small-order T: passes `is_weak`, fails ours.
    let a: EdwardsPoint = ED25519_BASEPOINT_POINT * Scalar::from(123456789u64);
    let honest = a.compress().to_bytes();
    assert!(validate_key(&honest).is_ok());
    for t in &EIGHT_TORSION[1..] {
        let mixed = (a + t).compress().to_bytes();
        assert!(!VerifyingKey::from_bytes(&mixed).unwrap().is_weak());
        assert_eq!(validate_key(&mixed), Err(Error::BadKey));
        let (st, id) = state_for(mixed);
        assert_eq!(st.verify(&id), Err(Error::BadKey));
    }
}

#[test]
fn off_curve_key_rejected() {
    let mut found = false;
    for y in 2u8..100 {
        let mut b = [0u8; 32];
        b[0] = y;
        if CompressedEdwardsY(b).decompress().is_none() {
            assert_eq!(validate_key(&b), Err(Error::BadKey));
            found = true;
        }
    }
    assert!(found);
}

// ---- boundaries -------------------------------------------------------------------------------

#[test]
fn max_data_len_boundary() {
    let k = key(3);
    let vk = *k.verifying_key().as_bytes();
    let id = ShortId::derive(&vk);
    let at_max = ResolverState {
        vk,
        signed: Some(SignedData::sign(&k, 1, 1, vec![7u8; MAX_DATA_LEN]).unwrap()),
    };
    let enc = at_max.encode();
    assert_eq!(enc.len(), 16496);
    assert_eq!(ResolverState::decode(&enc).unwrap(), at_max);
    at_max.verify(&id).unwrap();
    assert!(SignedData::sign(&k, 1, 1, vec![7u8; MAX_DATA_LEN + 1]).is_err());
    // hand-built encoding claiming MAX+1 bytes is rejected from the length field alone
    let mut over = vec![WIRE_VERSION];
    over.extend_from_slice(&vk);
    over.push(1);
    over.extend_from_slice(&1u64.to_be_bytes());
    over.extend_from_slice(&1u16.to_be_bytes());
    over.extend_from_slice(&((MAX_DATA_LEN + 1) as u32).to_be_bytes());
    over.extend_from_slice(&vec![0u8; MAX_DATA_LEN + 1 + SIG_LEN]);
    assert_eq!(
        ResolverState::decode(&over),
        Err(Error::DataTooLarge(MAX_DATA_LEN + 1))
    );
}

#[test]
fn u64_max_revision_is_final_but_still_merges() {
    let k = key(4);
    let vk = *k.verifying_key().as_bytes();
    let st = |rev: u64, d: &[u8]| ResolverState {
        vk,
        signed: Some(SignedData::sign(&k, rev, 1, d.to_vec()).unwrap()),
    };
    let top = st(u64::MAX, b"top");
    for lower in [st(0, b"a"), st(u64::MAX - 1, b"b")] {
        let mut x = top.clone();
        x.merge(&lower).unwrap();
        assert_eq!(x, top);
        let mut y = lower.clone();
        y.merge(&top).unwrap();
        assert_eq!(y, top);
    }
    // only an equal-revision state with a smaller signature can replace it
    let other = st(u64::MAX, b"other");
    let mut a = top.clone();
    a.merge(&other).unwrap();
    let mut b = other.clone();
    b.merge(&top).unwrap();
    assert_eq!(a, b);
}
