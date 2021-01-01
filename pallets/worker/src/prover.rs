#![cfg_attr(not(feature = "std"), no_std)]

use crate::*;
use rlp::Rlp;

pub trait Prover {
    fn extract_nibbles(a: Vec<u8>) -> Vec<u8>;
    fn concat_nibbles(a: Vec<u8>) -> Vec<u8>;

    fn assert_ethclient_hash(
        block_number: u64,
        expected_block_hash: H256,
    ) -> bool;

    fn verify_log_entry(
        log_index: u64,
        log_entry_data: Vec<u8>,
        receipt_index: u64,
        receipt_data: Vec<u8>,
        header_data: Vec<u8>,
        proof: Vec<Vec<u8>>,
    ) -> bool;

    fn verify_trie_proof(
        expected_root: H256,
        key: Vec<u8>,
        proof: Vec<Vec<u8>>,
        expected_value: Vec<u8>
    ) -> bool;

    fn _verify_trie_proof(
        expected_root: H256,
        key: Vec<u8>,
        proof: Vec<Vec<u8>>,
        key_index: usize,
        proof_index: usize,
        expected_value: Vec<u8>,
    ) -> bool;
}

impl<T: Config> Prover for Module<T> {
    fn extract_nibbles(a: Vec<u8>) -> Vec<u8> {
        a.iter().flat_map(|b| vec![b >> 4, b & 0x0F]).collect()
    }

    fn concat_nibbles(a: Vec<u8>) -> Vec<u8> {
        a.iter()
            .enumerate()
            .filter(|(i, _)| i % 2 == 0)
            .zip(a.iter().enumerate().filter(|(i, _)| i % 2 == 1))
            .map(|((_, x), (_, y))| (x << 4) | y)
            .collect()
    }

    fn assert_ethclient_hash(block_number: u64, expected_block_hash: H256) -> bool {
        match Self::block_hash_safe(block_number) {
            Some(hash) => hash == expected_block_hash,
            None => false,
        }
    }

    fn verify_log_entry(
        log_index: u64,
        log_entry_data: Vec<u8>,
        receipt_index: u64,
        receipt_data: Vec<u8>,
        header_data: Vec<u8>,
        proof: Vec<Vec<u8>>,
    ) -> bool {
        let log_entry: ethereum::Log = rlp::decode(log_entry_data.as_slice()).unwrap();
        let receipt: ethereum::Receipt = rlp::decode(receipt_data.as_slice()).unwrap();
        let header: ethereum::Header = rlp::decode(header_data.as_slice()).unwrap();

        // Verify log_entry included in receipt
        if receipt.logs[log_index as usize] == log_entry {
            return false;
        }

        // Verify receipt included into header
        let verification_result = Self::verify_trie_proof(
            header.receipts_root,
            rlp::encode(&receipt_index),
            proof,
            receipt_data,
        );

        if !verification_result {
            return false;
        }

        Self::assert_ethclient_hash(header.number.as_u64(), header.hash())
    }

    fn verify_trie_proof(
        expected_root: H256,
        key: Vec<u8>,
        proof: Vec<Vec<u8>>,
        expected_value: Vec<u8>
    ) -> bool {
        let mut actual_key = vec![];
        for el in key {
            if actual_key.len() + 1 == proof.len() {
                actual_key.push(el);
            } else {
                actual_key.push(el / 16);
                actual_key.push(el % 16);
            }
        }

        Self::_verify_trie_proof(expected_root, actual_key, proof, 0, 0, expected_value)
    }

    fn _verify_trie_proof(
        expected_root: H256,
        key: Vec<u8>,
        proof: Vec<Vec<u8>>,
        key_index: usize,
        proof_index: usize,
        expected_value: Vec<u8>,
    ) -> bool {
        let node = &proof[proof_index];
        let dec = Rlp::new(&node.as_slice());

        if key_index == 0 {
            // trie root is always a hash
            if sp_io::hashing::keccak_256(node) != expected_root.0 {
                return false;
            }
            // assert_eq!(keccak256(node), (expected_root.0).0);
        } else if node.len() < 32 {
            // if rlp < 32 bytes, then it is not hashed
            if dec.as_raw() != expected_root.0 {
                return false;
            }
            // assert_eq!(dec.as_raw(), (expected_root.0).0);
        } else {
            if sp_io::hashing::keccak_256(node) != expected_root.0 {
                return false;
            }
        }

        if dec.iter().count() == 17 {
            // branch node
            if key_index == key.len() {
                if dec
                    .at(dec.iter().count() - 1)
                    .unwrap()
                    .as_val::<Vec<u8>>()
                    .unwrap()
                    == expected_value
                {
                    // value stored in the branch
                    return true;
                }
            } else if key_index < key.len() {
                let new_expected_root = dec
                    .at(key[key_index] as usize)
                    .unwrap()
                    .as_val::<Vec<u8>>()
                    .unwrap();

                let mut trunc_expected_root: [u8; 32] = [0; 32];
                for i in 0..new_expected_root.len() {
                    if i == 32 { break; }
                    trunc_expected_root[i] = new_expected_root[i];
                }

                if new_expected_root.len() != 0 {
                    return Self::_verify_trie_proof(
                        trunc_expected_root.into(),
                        key,
                        proof,
                        key_index + 1,
                        proof_index + 1,
                        expected_value,
                    );
                }
            } else {
                panic!("This should not be reached if the proof has the correct format");
            }
        } else if dec.iter().count() == 2 {
            // leaf or extension node
            // get prefix and optional nibble from the first byte
            let nibbles = Self::extract_nibbles(dec.at(0).unwrap().as_val::<Vec<u8>>().unwrap());
            let (prefix, nibble) = (nibbles[0], nibbles[1]);

            if prefix == 2 {
                // even leaf node
                let key_end = &nibbles[2..];
                if Self::concat_nibbles(key_end.to_vec()) == &key[key_index..]
                    && expected_value == dec.at(1).unwrap().as_val::<Vec<u8>>().unwrap()
                {
                    return true;
                }
            } else if prefix == 3 {
                // odd leaf node
                let key_end = &nibbles[2..];
                if nibble == key[key_index]
                    && Self::concat_nibbles(key_end.to_vec()) == &key[key_index + 1..]
                    && expected_value == dec.at(1).unwrap().as_val::<Vec<u8>>().unwrap()
                {
                    return true;
                }
            } else if prefix == 0 {
                // even extension node
                let shared_nibbles = &nibbles[2..];
                let extension_length = shared_nibbles.len();
                if Self::concat_nibbles(shared_nibbles.to_vec())
                    == &key[key_index..key_index + extension_length]
                {

                    let new_expected_root = dec.at(1).unwrap().as_val::<Vec<u8>>().unwrap();
                    let mut trunc_expected_root: [u8; 32] = [0; 32];
                    for i in 0..new_expected_root.len() {
                        if i == 32 { break; }
                        trunc_expected_root[i] = new_expected_root[i];
                    }

                    return Self::_verify_trie_proof(
                        trunc_expected_root.into(),
                        key,
                        proof,
                        key_index + extension_length,
                        proof_index + 1,
                        expected_value,
                    );
                }
            } else if prefix == 1 {
                // odd extension node
                let shared_nibbles = &nibbles[2..];
                let extension_length = 1 + shared_nibbles.len();
                if nibble == key[key_index]
                    && Self::concat_nibbles(shared_nibbles.to_vec())
                        == &key[key_index + 1..key_index + extension_length]
                {
                    let new_expected_root = dec.at(1).unwrap().as_val::<Vec<u8>>().unwrap();
                    let mut trunc_expected_root: [u8; 32] = [0; 32];
                    for i in 0..new_expected_root.len() {
                        if i == 32 { break; }
                        trunc_expected_root[i] = new_expected_root[i];
                    }
                    return Self::_verify_trie_proof(
                        trunc_expected_root.into(),
                        key,
                        proof,
                        key_index + extension_length,
                        proof_index + 1,
                        expected_value,
                    );
                }
            } else {
                panic!("This should not be reached if the proof has the correct format");
            }
        } else {
            panic!("This should not be reached if the proof has the correct format");
        }

        expected_value.len() == 0
    }
}