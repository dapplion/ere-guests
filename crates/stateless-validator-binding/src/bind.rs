//! The binding prologue: `verify_execution_transition` without the execution, mirroring the
//! EIP-8025 [`guest-program.md`] prologue and the Gloas `verify_execution_payload_envelope` it
//! calls. The execution stays with the client's stateless validator, which the guest calls on the
//! returned [`StatelessInput`].
//!
//! [`guest-program.md`]: https://github.com/ethereum/consensus-specs/blob/master/specs/_features/eip8025/guest-program.md

#![allow(missing_docs)]

use alloc::vec::Vec;

use libssz_merkle::{HashTreeRoot, Sha256Hasher};
use stateless_validator_common::guest::{
    StatelessInput,
    input::{
        ProtocolFork,
        new_payload_request::{
            Bytes48, ExecutionRequestsGloas, NewPayloadRequest, NewPayloadRequestGloas,
            VersionedHash,
        },
    },
};

use crate::{
    error::Error,
    input::BindingInput,
    network::Network,
    types::{ExecutionPayloadEnvelope, PublicInput},
};

/// The protocol fork the prologue binds payloads for. Payload envelopes exist from Gloas on.
pub const BINDING_PROTOCOL_FORK: ProtocolFork = ProtocolFork::Amsterdam;

const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;

/// The guest commits `hash_tree_root(public_input)` and validates `stateless_input`.
#[derive(Debug, Clone)]
pub struct Bound {
    pub public_input: PublicInput,
    pub stateless_input: StatelessInput,
}

/// The chain identifier, the slot duration and the payload limits come from `N`, never from
/// `input`: EIP-8025 requires the guest to own them, so one guest binary serves one network.
pub fn bind<N: Network>(input: BindingInput, hasher: &impl Sha256Hasher) -> Result<Bound, Error> {
    let BindingInput {
        state,
        envelope,
        execution_witness,
    } = input;
    let ExecutionPayloadEnvelope {
        payload,
        execution_requests,
        builder_index,
        beacon_block_root,
        parent_beacon_block_root,
    } = envelope;

    // Gloas enforces these limits only in payload envelope gossip, where exceeding one is a
    // gossip rejection. Here it fails the proof.
    verify_execution_requests_limits::<N>(&execution_requests)?;
    if payload.withdrawals.len() > N::MAX_WITHDRAWALS_PER_PAYLOAD {
        return Err(Error::TooManyWithdrawals);
    }

    state.verify(hasher)?;
    let bid = &state.latest_execution_payload_bid;

    let mut header = state.latest_block_header.clone();
    header.state_root = state.state_root;
    if beacon_block_root != header.hash_tree_root(hasher) {
        return Err(Error::BeaconBlockRoot);
    }
    if parent_beacon_block_root != state.latest_block_header.parent_root {
        return Err(Error::ParentBeaconBlockRoot);
    }

    if builder_index != bid.builder_index {
        return Err(Error::BuilderIndex);
    }
    if payload.prev_randao != bid.prev_randao {
        return Err(Error::PrevRandao);
    }
    if payload.gas_limit != bid.gas_limit {
        return Err(Error::GasLimit);
    }
    if payload.block_hash != bid.block_hash {
        return Err(Error::BlockHash);
    }
    if execution_requests.hash_tree_root(hasher) != bid.execution_requests_root {
        return Err(Error::ExecutionRequestsRoot);
    }

    if payload.slot_number != state.slot {
        return Err(Error::SlotNumber);
    }
    if payload.parent_hash != state.latest_block_hash {
        return Err(Error::ParentHash);
    }
    if payload.timestamp
        != state
            .genesis_time
            .saturating_add(state.slot.saturating_mul(N::SECONDS_PER_SLOT))
    {
        return Err(Error::Timestamp);
    }
    if payload.withdrawals.hash_tree_root(hasher) != state.payload_expected_withdrawals_root {
        return Err(Error::WithdrawalsRoot);
    }

    Ok(Bound {
        public_input: PublicInput {
            beacon_block_root,
            successful_validation: true,
            chain_id: N::DEPOSIT_CHAIN_ID,
            schema_id: BINDING_PROTOCOL_FORK.schema_id(),
        },
        stateless_input: StatelessInput {
            new_payload_request: NewPayloadRequest::Gloas(NewPayloadRequestGloas {
                execution_payload: payload,
                versioned_hashes: bid
                    .blob_kzg_commitments
                    .iter()
                    .map(|commitment| kzg_commitment_to_versioned_hash(hasher, commitment))
                    .collect::<Vec<_>>()
                    .into(),
                parent_beacon_block_root,
                execution_requests,
            }),
            witness: execution_witness,
            chain_id: N::DEPOSIT_CHAIN_ID,
        },
    })
}

fn verify_execution_requests_limits<N: Network>(
    execution_requests: &ExecutionRequestsGloas,
) -> Result<(), Error> {
    if execution_requests.withdrawals.len() > N::MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD {
        return Err(Error::TooManyWithdrawalRequests);
    }
    if execution_requests.consolidations.len() > N::MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD {
        return Err(Error::TooManyConsolidationRequests);
    }
    if execution_requests.builder_deposits.len() > N::MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD {
        return Err(Error::TooManyBuilderDepositRequests);
    }
    if execution_requests.builder_exits.len() > N::MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD {
        return Err(Error::TooManyBuilderExitRequests);
    }
    Ok(())
}

fn kzg_commitment_to_versioned_hash(
    hasher: &impl Sha256Hasher,
    commitment: &Bytes48,
) -> VersionedHash {
    let mut versioned_hash = hasher.hash(commitment);
    versioned_hash[0] = VERSIONED_HASH_VERSION_KZG;
    versioned_hash
}

#[cfg(test)]
mod tests {
    use const_hex::decode_to_array;
    use libssz_merkle::Sha2Hasher;
    use stateless_validator_common::guest::input::ExecutionWitness;

    use super::*;
    use crate::{
        network::Mainnet,
        test_support::{binding_input, execution_requests, payload},
        witness::GINDEX_LATEST_EXECUTION_PAYLOAD_BID,
    };

    /// `0x01 || sha256(commitment)[1..]` of the sample blob commitments.
    const VERSIONED_HASHES: [&str; 2] = [
        "010950a9b30853ab22cc7cb66486bd89496f36e066318196b0d5583cbf79fe80",
        "015f8226fae010d7c32127a16cc60c05d963f873462c673df923be0b6f9dd48e",
    ];

    #[test]
    fn binds_a_payload_envelope_to_its_beacon_block() {
        let input = binding_input();
        let beacon_block_root = input.envelope.beacon_block_root;
        let bound = bind::<Mainnet>(input, &Sha2Hasher).unwrap();

        assert_eq!(
            bound.public_input,
            PublicInput {
                beacon_block_root,
                successful_validation: true,
                chain_id: 1,
                schema_id: 0x1501,
            }
        );
        assert_eq!(
            bound.stateless_input,
            StatelessInput {
                new_payload_request: NewPayloadRequest::Gloas(NewPayloadRequestGloas {
                    execution_payload: payload(),
                    versioned_hashes: VERSIONED_HASHES
                        .iter()
                        .map(|hash| decode_to_array(hash).unwrap())
                        .collect::<Vec<VersionedHash>>()
                        .into(),
                    parent_beacon_block_root: [2; 32],
                    execution_requests: execution_requests(),
                }),
                witness: ExecutionWitness::default(),
                chain_id: 1,
            }
        );
    }

    #[test]
    fn rejects_a_tampered_envelope_or_state() {
        let mut input = binding_input();
        input.envelope.beacon_block_root[0] ^= 1;
        assert_eq!(
            bind::<Mainnet>(input, &Sha2Hasher).unwrap_err(),
            Error::BeaconBlockRoot
        );

        let mut input = binding_input();
        input.state.latest_execution_payload_bid.gas_limit += 1;
        assert_eq!(
            bind::<Mainnet>(input, &Sha2Hasher).unwrap_err(),
            Error::StateFieldBranch(GINDEX_LATEST_EXECUTION_PAYLOAD_BID)
        );
    }
}
