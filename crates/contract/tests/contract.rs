use ed25519_dalek::SigningKey;
use freenet_shortkey_common::*;
use freenet_shortkey_contract::ShortKeyContract;
use freenet_stdlib::prelude::*;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn minimal(k: &SigningKey) -> ResolverState {
    ResolverState::minimal(*k.verifying_key().as_bytes())
}
fn full(k: &SigningKey, rev: u64, data: &[u8]) -> ResolverState {
    let mut s = minimal(k);
    s.signed = Some(SignedData::sign(k, rev, 1, data.to_vec()).unwrap());
    s
}
fn params(s: &ResolverState) -> Parameters<'static> {
    Parameters::from(s.short_id().0.to_vec())
}
fn validate(p: Parameters<'static>, s: &ResolverState) -> bool {
    matches!(
        ShortKeyContract::validate_state(p, State::from(s.encode()), RelatedContracts::default()),
        Ok(ValidateResult::Valid)
    )
}
fn update(
    p: Parameters<'static>,
    cur: &ResolverState,
    ups: Vec<UpdateData<'static>>,
) -> Result<ResolverState, ContractError> {
    let m = ShortKeyContract::update_state(p, State::from(cur.encode()), ups)?;
    let bytes = m.new_state.unwrap();
    Ok(ResolverState::decode(bytes.as_ref()).unwrap())
}
fn st(s: &ResolverState) -> UpdateData<'static> {
    UpdateData::State(State::from(s.encode()))
}

#[test]
fn validate_binding_and_signature() {
    let k = key(1);
    let m = minimal(&k);
    assert!(validate(params(&m), &m));
    assert!(validate(params(&m), &full(&k, 1, b"x")));
    // wrong params, short params, empty state, tampered data
    assert!(!validate(params(&minimal(&key(2))), &m));
    assert!(!validate(Parameters::from(vec![0u8; 15]), &m));
    assert!(ShortKeyContract::validate_state(
        params(&m),
        State::from(vec![]),
        RelatedContracts::default()
    )
    .is_err());
    let mut t = full(&k, 1, b"x");
    t.signed.as_mut().unwrap().data = b"y".to_vec();
    assert!(!validate(params(&m), &t));
}

#[test]
fn update_merges_and_never_erases() {
    let k = key(1);
    let p = params(&minimal(&k));
    let r1 = full(&k, 1, b"one");
    let r2 = full(&k, 2, b"two");
    assert_eq!(update(p.clone(), &minimal(&k), vec![st(&r2)]).unwrap(), r2);
    // reversed order, stale state, minimal reconstruction, duplicates
    assert_eq!(update(p.clone(), &r2, vec![st(&r1)]).unwrap(), r2);
    assert_eq!(update(p.clone(), &r2, vec![st(&minimal(&k))]).unwrap(), r2);
    assert_eq!(update(p.clone(), &r2, vec![st(&r2), st(&r2)]).unwrap(), r2);
    assert_eq!(
        update(p.clone(), &minimal(&k), vec![st(&r2), st(&r1)]).unwrap(),
        r2
    );
    // empty delta is skipped
    let empty = UpdateData::Delta(StateDelta::from(vec![]));
    assert_eq!(update(p, &r1, vec![empty]).unwrap(), r1);
}

#[test]
fn update_rejects_bad_input() {
    let k = key(1);
    let p = params(&minimal(&k));
    let other = full(&key(2), 5, b"evil");
    assert!(update(p.clone(), &minimal(&k), vec![st(&other)]).is_err());
    let mut forged = full(&k, 9, b"a");
    forged.signed.as_mut().unwrap().data = b"b".to_vec();
    assert!(update(p.clone(), &minimal(&k), vec![st(&forged)]).is_err());
    let junk = UpdateData::Delta(StateDelta::from(vec![9, 9, 9]));
    assert!(update(p, &minimal(&k), vec![junk]).is_err());
}

#[test]
fn equal_revision_conflict_converges() {
    let k = key(1);
    let p = params(&minimal(&k));
    let a = full(&k, 4, b"a");
    let b = full(&k, 4, b"b");
    let ab = update(p.clone(), &a, vec![st(&b)]).unwrap();
    let ba = update(p, &b, vec![st(&a)]).unwrap();
    assert_eq!(ab, ba);
}

#[test]
fn summary_delta_roundtrip() {
    let k = key(1);
    let p = params(&minimal(&k));
    let m = minimal(&k);
    let r = full(&k, 3, b"data");
    let sum_m = ShortKeyContract::summarize_state(p.clone(), State::from(m.encode())).unwrap();
    let delta =
        ShortKeyContract::get_state_delta(p.clone(), State::from(r.encode()), sum_m).unwrap();
    assert!(!delta.as_ref().is_empty());
    let got = update(p.clone(), &m, vec![UpdateData::Delta(delta)]).unwrap();
    assert_eq!(got, r);
    // peer already current: empty delta
    let sum_r = ShortKeyContract::summarize_state(p.clone(), State::from(r.encode())).unwrap();
    let d = ShortKeyContract::get_state_delta(p, State::from(r.encode()), sum_r).unwrap();
    assert!(d.as_ref().is_empty());
}

#[test]
fn state_and_delta_merges_both_halves() {
    let k = key(1);
    let p = params(&minimal(&k));
    let r1 = full(&k, 1, b"one");
    let r2 = full(&k, 2, b"two");
    let both = UpdateData::StateAndDelta {
        state: State::from(r1.encode()),
        delta: StateDelta::from(r2.encode()),
    };
    assert_eq!(update(p.clone(), &minimal(&k), vec![both]).unwrap(), r2);
    // empty delta half is skipped, the state half still merges
    let state_only = UpdateData::StateAndDelta {
        state: State::from(r1.encode()),
        delta: StateDelta::from(vec![]),
    };
    assert_eq!(
        update(p.clone(), &minimal(&k), vec![state_only]).unwrap(),
        r1
    );
    // an invalid half still fails the update
    let bad = UpdateData::StateAndDelta {
        state: State::from(r1.encode()),
        delta: StateDelta::from(vec![9, 9]),
    };
    assert!(update(p, &minimal(&k), vec![bad]).is_err());
}

#[test]
fn related_variants_are_skipped_not_fatal() {
    let k = key(1);
    let p = params(&minimal(&k));
    let r1 = full(&k, 1, b"one");
    let related = ContractInstanceId::new([5u8; 32]);
    let ups = vec![
        UpdateData::RelatedState {
            related_to: related,
            state: State::from(vec![1, 2, 3]),
        },
        UpdateData::RelatedDelta {
            related_to: related,
            delta: StateDelta::from(vec![1, 2, 3]),
        },
        UpdateData::RelatedStateAndDelta {
            related_to: related,
            state: State::from(vec![1]),
            delta: StateDelta::from(vec![2]),
        },
        st(&r1),
    ];
    assert_eq!(update(p, &minimal(&k), ups).unwrap(), r1);
}

#[test]
fn empty_summary_means_peer_holds_nothing() {
    let k = key(1);
    let p = params(&minimal(&k));
    let r = full(&k, 3, b"data");
    let d = ShortKeyContract::get_state_delta(
        p.clone(),
        State::from(r.encode()),
        StateSummary::from(vec![]),
    )
    .unwrap();
    assert_eq!(ResolverState::decode(d.as_ref()).unwrap(), r);
    // a minimal state has nothing to send, summary or not
    let d = ShortKeyContract::get_state_delta(
        p,
        State::from(minimal(&k).encode()),
        StateSummary::from(vec![]),
    )
    .unwrap();
    assert!(d.as_ref().is_empty());
}

#[test]
fn mixed_order_key_state_is_rejected() {
    use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
    let a = ED25519_BASEPOINT_POINT * curve25519_dalek::scalar::Scalar::from(42u64);
    let mixed = (a + EIGHT_TORSION[4]).compress().to_bytes();
    let m = ResolverState::minimal(mixed);
    assert!(!validate(params(&m), &m));
}

/// Pins the committed generation-1 artifact and the resolver address derived from it, so the
/// README, FREENET.md and the file cannot drift apart. Recorded values come from
/// `freenet-shortkey contract-key wasm/freenet_shortkey_v1.wasm DX4ZCXQ4NZgiw1Cuh8YjuC`.
#[test]
fn committed_wasm_hash_and_contract_id_are_pinned() {
    const WASM: &[u8] = include_bytes!("../../../wasm/freenet_shortkey_v1.wasm");
    assert_eq!(
        blake3::hash(WASM).to_hex().as_str(),
        "7fd0f944cb9d9cb04673288846c4434525d5d103deebcde257e290c1900d04c5"
    );
    let code = ContractCode::from(WASM.to_vec());
    assert_eq!(
        code.hash().to_string(),
        "9bwbWefShTXmVrizwn4XQ3NdT1Zjm7rm1uWLUAwqewuW"
    );
    let id = ShortId::from_base58("DX4ZCXQ4NZgiw1Cuh8YjuC").unwrap();
    let key = ContractKey::from_params_and_code(Parameters::from(id.0.to_vec()), &code);
    assert_eq!(
        key.id().to_string(),
        "6ThwP2dPt1LNYY7p1hpmdpm6uNKrrVed6qjmYbFmU6Db"
    );
}
