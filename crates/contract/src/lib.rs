//! Freenet short-key resolver contract.
//!
//! Parameters: the 16-byte short id. State: see `freenet_shortkey_common::ResolverState`.
//! This WASM is frozen per generation: changing it changes every resolver address.

use freenet_shortkey_common::{ResolverState, ShortId, Summary};
use freenet_stdlib::prelude::*;

pub struct ShortKeyContract;

fn err<E: std::fmt::Display>(e: E) -> ContractError {
    ContractError::InvalidUpdateWithInfo { reason: e.to_string() }
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
        for update in data {
            let bytes = match &update {
                UpdateData::State(s) => s.as_ref(),
                UpdateData::Delta(d) => {
                    if d.as_ref().is_empty() {
                        continue;
                    }
                    d.as_ref()
                }
                _ => return Err(ContractError::InvalidUpdate),
            };
            let incoming = parse_verified(bytes, &id)?;
            current.merge(&incoming).map_err(err)?;
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
        let peer = Summary::decode(summary.as_ref()).map_err(|e| ContractError::Deser(e.to_string()))?;
        Ok(StateDelta::from(s.delta_for(&peer).map(|d| d.encode()).unwrap_or_default()))
    }
}
