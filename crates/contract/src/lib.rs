//! Freenet short-key resolver contract.
//!
//! Parameters: the 16-byte short id. State: see `freenet_shortkey_common::ResolverState`.
//! This WASM is frozen per generation: changing it changes every resolver address.

use freenet_shortkey_common::{ResolverState, ShortId, Summary};
use freenet_stdlib::prelude::*;

pub struct ShortKeyContract;

fn err<E: std::fmt::Display>(e: E) -> ContractError {
    ContractError::InvalidUpdateWithInfo {
        reason: e.to_string(),
    }
}

/// Parse and fully verify a state (or delta, which has the state encoding) against `id`.
fn parse_verified(bytes: &[u8], id: &ShortId) -> Result<ResolverState, ContractError> {
    let s = ResolverState::decode(bytes).map_err(|e| ContractError::Deser(e.to_string()))?;
    s.verify(id).map_err(err)?;
    Ok(s)
}

#[contract]
impl ContractInterface for ShortKeyContract {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        let id = ShortId::from_params(parameters.as_ref()).map_err(err)?;
        parse_verified(state.as_ref(), &id)?;
        Ok(ValidateResult::Valid)
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let id = ShortId::from_params(parameters.as_ref()).map_err(err)?;
        let mut current = parse_verified(state.as_ref(), &id)?;
        for update in &data {
            // Every variant that can carry this contract's own state or delta is merged.
            // `RelatedState*` / `RelatedDelta` carry ANOTHER contract's data (this contract
            // declares no related contracts), and `UpdateData` is `#[non_exhaustive]`, so
            // anything else is skipped rather than failing the whole batch. This WASM can
            // never be changed after publication, so it must tolerate future variants.
            let (state, delta) = match update {
                UpdateData::State(s) => (Some(s.as_ref()), None),
                UpdateData::Delta(d) => (None, Some(d.as_ref())),
                UpdateData::StateAndDelta { state, delta } => {
                    (Some(state.as_ref()), Some(delta.as_ref()))
                }
                _ => continue,
            };
            if let Some(bytes) = state {
                let incoming = parse_verified(bytes, &id)?;
                current.merge(&incoming).map_err(err)?;
            }
            // An empty delta means "nothing to send" (see `get_state_delta`).
            if let Some(bytes) = delta.filter(|d| !d.is_empty()) {
                let incoming = parse_verified(bytes, &id)?;
                current.merge(&incoming).map_err(err)?;
            }
        }
        Ok(UpdateModification::valid(current.encode().into()))
    }

    fn summarize_state(
        parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        let id = ShortId::from_params(parameters.as_ref()).map_err(err)?;
        let s = parse_verified(state.as_ref(), &id)?;
        Ok(StateSummary::from(s.summary().encode()))
    }

    fn get_state_delta(
        parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let id = ShortId::from_params(parameters.as_ref()).map_err(err)?;
        let s = parse_verified(state.as_ref(), &id)?;
        // An empty summary is what a node ships when it could not summarize: treat it as
        // "holds nothing".
        let peer = if summary.as_ref().is_empty() {
            Summary { head: None }
        } else {
            Summary::decode(summary.as_ref()).map_err(|e| ContractError::Deser(e.to_string()))?
        };
        Ok(StateDelta::from(
            s.delta_for(&peer).map(|d| d.encode()).unwrap_or_default(),
        ))
    }
}
