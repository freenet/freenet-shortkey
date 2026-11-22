use ed25519_dalek::SigningKey;
use freenet_shortkey_common::*;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn vk(k: &SigningKey) -> [u8; 32] {
    *k.verifying_key().as_bytes()
}
fn with_data(k: &SigningKey, rev: u64, data: &[u8]) -> ResolverState {
    ResolverState {
        vk: vk(k),
        signed: Some(SignedData::sign(k, rev, 1, data.to_vec()).unwrap()),
    }
}
fn merged(a: &ResolverState, b: &ResolverState) -> ResolverState {
    let mut x = a.clone();
    x.merge(b).unwrap();
    x
}

// Test vectors are produced by this implementation and pinned: any change to the derivation,
// domain string or encoding must fail here and be treated as a new generation.
#[test]
fn derivation_vectors() {
    let cases: [([u8; 32], &str, &str); 3] = [
        (
            [0u8; 32],
            "65602aff592963c36beeaa812aa12b83",
            "DX4ZCXQ4NZgiw1Cuh8YjuC",
        ),
        (
            [1u8; 32],
            "8c35f5bdd1081c19e80c6e1e3af9817d",
            "JKCi2BXwJLh46QKm3Sf46p",
        ),
        (
            [0xffu8; 32],
            "562bd5927a6025d29a6f5cdd4eaefc17",
            "BeAcviiYQKaBSC15JkK1TL",
        ),
    ];
    for (k, hex, b58) in cases {
        let id = ShortId::derive(&k);
        let got_hex: String = id.0.iter().map(|b| format!("{b:02x}")).collect();
        println!("VECTOR {:02x}.. {} {}", k[0], got_hex, id.to_base58());
        assert_eq!(got_hex, hex);
        assert_eq!(id.to_base58(), b58);
    }
}

#[test]
fn base58_roundtrip_and_strictness() {
    let mut rng = StdRng::seed_from_u64(1);
    for _ in 0..500 {
        let id = ShortId(rng.gen());
        let s = id.to_base58();
        assert!(s.len() == 21 || s.len() == 22, "{s}");
        assert_eq!(ShortId::from_base58(&s).unwrap(), id);
    }
    // leading-zero bytes survive
    let z = ShortId([0; 16]);
    assert_eq!(z.to_base58(), "1111111111111111");
    assert_eq!(ShortId::from_base58("1111111111111111").unwrap(), z);
    // wrong length, bad alphabet (0, O, I, l), empty
    assert!(ShortId::from_base58("").is_err());
    assert!(ShortId::from_base58("111").is_err());
    assert!(ShortId::from_base58("0OIl0OIl0OIl0OIl0OIl0O").is_err());
    let full = bs58::encode([7u8; 32]).into_string();
    assert!(ShortId::from_base58(&full).is_err());
}

#[test]
fn locator_told_apart_by_length() {
    let k = vk(&key(3));
    let id = ShortId::derive(&k);
    assert_eq!(parse_locator(&id.to_base58()).unwrap(), Locator::Short(id));
    assert_eq!(
        parse_locator(&bs58::encode(k).into_string()).unwrap(),
        Locator::Full(k)
    );
    assert!(parse_locator(&bs58::encode([1u8; 24]).into_string()).is_err());
    assert!(parse_locator("not base58 !!").is_err());
}

#[test]
fn minimal_mapping_verifies_without_signature() {
    let k = key(1);
    let s = ResolverState::minimal(vk(&k));
    s.verify(&s.short_id()).unwrap();
    let back = ResolverState::decode(&s.encode()).unwrap();
    assert_eq!(back, s);
}

#[test]
fn invalid_binding_rejected() {
    let a = ResolverState::minimal(vk(&key(1)));
    let other = ShortId::derive(&vk(&key(2)));
    assert_eq!(a.verify(&other), Err(Error::BindingMismatch));
    // flipping any bit of the id must fail
    let mut id = a.short_id();
    id.0[15] ^= 1;
    assert_eq!(a.verify(&id), Err(Error::BindingMismatch));
}

#[test]
fn weak_and_invalid_keys_rejected() {
    // identity point (y=1) is a small-order key
    let mut ident = [0u8; 32];
    ident[0] = 1;
    let s = ResolverState::minimal(ident);
    assert_eq!(s.verify(&s.short_id()), Err(Error::BadKey));
}

#[test]
fn unsigned_data_change_rejected() {
    let k = key(1);
    let good = with_data(&k, 5, b"hello");
    let id = good.short_id();
    good.verify(&id).unwrap();
    // tamper data, revision, format, signature
    let mut t = good.clone();
    t.signed.as_mut().unwrap().data = b"hellp".to_vec();
    assert_eq!(t.verify(&id), Err(Error::BadSignature));
    let mut t = good.clone();
    t.signed.as_mut().unwrap().revision = 6;
    assert_eq!(t.verify(&id), Err(Error::BadSignature));
    let mut t = good.clone();
    t.signed.as_mut().unwrap().format = 2;
    assert_eq!(t.verify(&id), Err(Error::BadSignature));
    // signed by someone else, claiming this key
    let mut t = good.clone();
    t.signed = with_data(&key(9), 5, b"hello").signed;
    assert_eq!(t.verify(&id), Err(Error::BadSignature));
}

#[test]
fn size_limits() {
    let k = key(1);
    let ok = with_data(&k, 1, &vec![7u8; MAX_DATA_LEN]);
    ok.verify(&ok.short_id()).unwrap();
    assert_eq!(ResolverState::decode(&ok.encode()).unwrap(), ok);
    assert_eq!(
        SignedData::sign(&k, 1, 1, vec![0; MAX_DATA_LEN + 1]),
        Err(Error::DataTooLarge(MAX_DATA_LEN + 1))
    );
    // a hostile encoding claiming a huge length is refused before any allocation
    let mut bytes = ResolverState::minimal(vk(&k)).encode();
    *bytes.last_mut().unwrap() = 1;
    bytes.extend_from_slice(&1u64.to_be_bytes());
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        ResolverState::decode(&bytes),
        Err(Error::DataTooLarge(_))
    ));
}

#[test]
fn decode_rejects_garbage() {
    let s = with_data(&key(1), 1, b"x").encode();
    assert!(ResolverState::decode(&[]).is_err());
    for n in 0..s.len() {
        assert!(ResolverState::decode(&s[..n]).is_err(), "truncated at {n}");
    }
    let mut t = s.clone();
    t.push(0);
    assert!(ResolverState::decode(&t).is_err());
    let mut t = s.clone();
    t[0] = 2;
    assert!(ResolverState::decode(&t).is_err());
    let mut t = s;
    t[33] = 2;
    assert!(ResolverState::decode(&t).is_err());
}

#[test]
fn higher_revision_wins_either_order() {
    let k = key(1);
    let old = with_data(&k, 1, b"old");
    let new = with_data(&k, 2, b"new");
    assert_eq!(merged(&old, &new), new);
    assert_eq!(merged(&new, &old), new); // stale state does not roll back
}

#[test]
fn duplicate_updates_idempotent() {
    let k = key(1);
    let s = with_data(&k, 3, b"d");
    assert_eq!(merged(&s, &s), s);
    let m = ResolverState::minimal(vk(&k));
    assert_eq!(merged(&m, &m), m);
}

#[test]
fn equal_revision_conflict_is_deterministic() {
    let k = key(1);
    let a = with_data(&k, 4, b"alpha");
    let b = with_data(&k, 4, b"beta");
    assert_ne!(a, b);
    let ab = merged(&a, &b);
    let ba = merged(&b, &a);
    assert_eq!(ab, ba);
    // winner has the lexicographically smaller signature
    let (sa, sb) = (a.signed.as_ref().unwrap(), b.signed.as_ref().unwrap());
    let want = if sa.signature < sb.signature { &a } else { &b };
    assert_eq!(&ab, want);
}

#[test]
fn minimal_reconstruction_never_erases_data() {
    let k = key(1);
    let full = with_data(&k, 9, b"keep me");
    let min = ResolverState::minimal(vk(&k));
    assert_eq!(merged(&full, &min), full);
    assert_eq!(merged(&min, &full), full);
}

#[test]
fn merge_rejects_different_keys() {
    let mut a = ResolverState::minimal(vk(&key(1)));
    assert_eq!(
        a.merge(&ResolverState::minimal(vk(&key(2)))),
        Err(Error::KeyMismatch)
    );
}

/// Fork test: generate a pool of valid states, then merge random subsets in random orders
/// and groupings; every result must equal the merge of the whole pool (commutative,
/// associative, idempotent, convergent).
#[test]
fn fork_merge_order_independent() {
    let k = key(5);
    let mut pool = vec![ResolverState::minimal(vk(&k))];
    for rev in 0..4u64 {
        for variant in 0..3u8 {
            pool.push(with_data(&k, rev, &[variant, rev as u8]));
        }
    }
    let id = pool[0].short_id();
    pool.iter().for_each(|s| s.verify(&id).unwrap());

    let mut truth = pool[0].clone();
    for s in &pool {
        truth.merge(s).unwrap();
    }
    assert_eq!(truth.signed.as_ref().unwrap().revision, 3);

    let mut rng = StdRng::seed_from_u64(42);
    for _ in 0..300 {
        // two forks fold random permutations (with duplicates), then reconcile
        let mut fork = |n: usize| {
            let mut acc = ResolverState::minimal(vk(&k));
            for _ in 0..n {
                acc.merge(&pool[rng.gen_range(0..pool.len())]).unwrap();
            }
            acc
        };
        let (a, b) = (fork(8), fork(8));
        let mut left = a.clone();
        left.merge(&b).unwrap();
        let mut right = b.clone();
        right.merge(&a).unwrap();
        assert_eq!(left, right);
        // finishing with every pool member converges to the truth from any start
        for s in &pool {
            left.merge(s).unwrap();
        }
        assert_eq!(left, truth);
    }
}

#[test]
fn summary_and_delta() {
    let k = key(1);
    let min = ResolverState::minimal(vk(&k));
    let r1 = with_data(&k, 1, b"one");
    let r2 = with_data(&k, 2, b"two");

    // summary roundtrip
    for s in [&min, &r1, &r2] {
        let sm = s.summary();
        assert_eq!(Summary::decode(&sm.encode()).unwrap(), sm);
    }
    assert!(Summary::decode(&[1, 1, 0]).is_err());
    assert!(Summary::decode(&[1, 0, 0]).is_err());

    // nothing to send when we have no data, or the peer is at least as new
    assert!(min.delta_for(&r2.summary()).is_none());
    assert!(r1.delta_for(&r2.summary()).is_none());
    assert!(r1.delta_for(&r1.summary()).is_none());
    // send when the peer has nothing or is behind
    assert_eq!(r1.delta_for(&min.summary()).unwrap(), r1);
    assert_eq!(r2.delta_for(&r1.summary()).unwrap(), r2);

    // equal revision, different signature: both sides send, both converge
    let a = with_data(&k, 3, b"a");
    let b = with_data(&k, 3, b"b");
    let da = a.delta_for(&b.summary()).unwrap();
    let db = b.delta_for(&a.summary()).unwrap();
    assert_eq!(merged(&a, &db), merged(&b, &da));

    // applying the delta to the peer reproduces the sender's data
    let d = r2.delta_for(&min.summary()).unwrap();
    assert_eq!(merged(&min, &d), r2);
}

#[test]
fn signature_is_bound_to_short_id() {
    // a signature is not transferable across short ids even for the same data
    let k = key(1);
    let s1 = SignedData::sign(&k, 1, 1, b"x".to_vec()).unwrap();
    let id2 = ShortId::derive(&vk(&key(2)));
    let st = ResolverState {
        vk: vk(&k),
        signed: Some(s1),
    };
    // rejected at the key binding; the signature check itself is covered in src/tests.rs
    assert_eq!(st.verify(&id2), Err(Error::BindingMismatch));
}
