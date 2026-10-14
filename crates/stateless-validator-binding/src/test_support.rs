//! Deterministic payloads for the unit tests.

use alloc::{vec, vec::Vec};

use libssz_merkle::Sha2Hasher;
use stateless_validator_common::guest::input::{
    ExecutionWitness,
    new_payload_request::{
        Bytes48, ExecutionPayloadV4, ExecutionRequestsGloas, Withdrawal, WithdrawalRequest,
    },
};

use crate::{fixture::consistent_binding_input, input::BindingInput, network::Mainnet};

pub(crate) const SLOT: u64 = 1_000;
pub(crate) const GENESIS_TIME: u64 = 1_700_000_000;

/// A payload whose fields are distinct constants, so a test that moves one can only fail for the
/// reason it is testing.
pub(crate) fn payload() -> ExecutionPayloadV4 {
    ExecutionPayloadV4 {
        parent_hash: [0x11; 32],
        fee_recipient: [0x22; 20],
        state_root: [0x33; 32],
        receipts_root: [0x44; 32],
        logs_bloom: [0x55; 256],
        prev_randao: [0x66; 32],
        block_number: 4_242,
        gas_limit: 30_000_000,
        gas_used: 21_000,
        timestamp: GENESIS_TIME + SLOT * 12,
        extra_data: vec![0xee; 4].try_into().unwrap(),
        base_fee_per_gas: [0x77; 32],
        block_hash: [0x88; 32],
        transactions: vec![vec![0x02, 0xf8].into()].into(),
        withdrawals: vec![Withdrawal {
            index: 9,
            validator_index: 10,
            address: [0x99; 20],
            amount: 32_000_000_000,
        }]
        .into(),
        blob_gas_used: 0,
        excess_blob_gas: 0,
        block_access_list: vec![0xaa].into(),
        slot_number: SLOT,
    }
}

/// Execution requests with one withdrawal request, so their root is not the empty one.
pub(crate) fn execution_requests() -> ExecutionRequestsGloas {
    ExecutionRequestsGloas {
        withdrawals: vec![WithdrawalRequest {
            source_address: [0xbb; 20],
            validator_pubkey: [0xcc; 48],
            amount: 1,
        }]
        .into(),
        ..ExecutionRequestsGloas::default()
    }
}

/// Two blob commitments, so the derived versioned hashes are not an empty list.
pub(crate) fn blob_kzg_commitments() -> Vec<Bytes48> {
    vec![[0xd1; 48], [0xd2; 48]]
}

pub(crate) fn binding_input() -> BindingInput {
    consistent_binding_input::<Mainnet>(
        &Sha2Hasher,
        payload(),
        execution_requests(),
        blob_kzg_commitments().into(),
        ExecutionWitness::default(),
    )
    .expect("the sample payload's timestamp is reachable on mainnet")
}
