//! Given a payload, builds the beacon state and the envelope that committed to it, as a prover
//! does from a real state. Also the source of conformance vectors for other guests.

use libssz_merkle::{HashTreeRoot, Sha256Hasher};
use stateless_validator_common::guest::input::{
    ExecutionWitness,
    new_payload_request::{ExecutionPayloadV4, ExecutionRequestsGloas},
};

use crate::{
    input::BindingInput,
    network::Network,
    types::{BeaconBlockHeader, BlobKZGCommitments, ExecutionPayloadBid, ExecutionPayloadEnvelope},
    witness::{StateFields, synthesize_witness},
};

const BUILDER_INDEX: u64 = 7;
const PARENT_BLOCK_ROOT: [u8; 32] = [2; 32];
const BODY_ROOT: [u8; 32] = [3; 32];
const PROPOSER_INDEX: u64 = 11;

/// Returns `None` when the payload's timestamp is earlier than its slot's time on `N`, which no
/// beacon state can produce.
pub fn consistent_binding_input<N: Network>(
    hasher: &impl Sha256Hasher,
    payload: ExecutionPayloadV4,
    execution_requests: ExecutionRequestsGloas,
    blob_kzg_commitments: BlobKZGCommitments,
    execution_witness: ExecutionWitness,
) -> Option<BindingInput> {
    let latest_block_header = BeaconBlockHeader {
        slot: payload.slot_number,
        proposer_index: PROPOSER_INDEX,
        parent_root: PARENT_BLOCK_ROOT,
        state_root: [0; 32],
        body_root: BODY_ROOT,
    };
    let state = synthesize_witness(
        hasher,
        StateFields {
            genesis_time: payload
                .timestamp
                .checked_sub(payload.slot_number.checked_mul(N::SECONDS_PER_SLOT)?)?,
            slot: payload.slot_number,
            latest_block_header,
            latest_block_hash: payload.parent_hash,
            latest_execution_payload_bid: ExecutionPayloadBid {
                parent_block_hash: payload.parent_hash,
                parent_block_root: PARENT_BLOCK_ROOT,
                block_hash: payload.block_hash,
                prev_randao: payload.prev_randao,
                fee_recipient: payload.fee_recipient,
                gas_limit: payload.gas_limit,
                builder_index: BUILDER_INDEX,
                slot: payload.slot_number,
                value: 0,
                execution_payment: 0,
                blob_kzg_commitments,
                execution_requests_root: execution_requests.hash_tree_root(hasher),
            },
            payload_expected_withdrawals_root: payload.withdrawals.hash_tree_root(hasher),
        },
        [0; 32],
    );
    let mut header = state.latest_block_header.clone();
    header.state_root = state.state_root;

    Some(BindingInput {
        envelope: ExecutionPayloadEnvelope {
            payload,
            execution_requests,
            builder_index: BUILDER_INDEX,
            beacon_block_root: header.hash_tree_root(hasher),
            parent_beacon_block_root: PARENT_BLOCK_ROOT,
        },
        state,
        execution_witness,
    })
}
