use crate::*;
use ethereum_types::{Address, Bloom, H160, H256, H64, U256};
use rlp::{
    Decodable as RlpDecodable, DecoderError as RlpDecoderError,
    Encodable as RlpEncodable, Rlp, RlpStream,
};
use rlp_derive::{
    RlpDecodable as RlpDecodableDerive, RlpEncodable as RlpEncodableDerive,
};

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::string::String;

use sp_runtime::RuntimeDebug;
use tiny_keccak::{Hasher, Keccak};

// TODO(shekohex) clean up the following code
// add a trait for doing this work.

fn hex_to_h256(v: String) -> H256 {
    let s = &mut v[2..].as_bytes().to_vec();
    if s.len() % 2 != 0 {
        s.push(b'0');
    }
    let b = hex::decode(&s).unwrap();
    H256::from_slice(&b)
}

fn hex_to_h64(v: String) -> H64 {
    let s = &mut v[2..].as_bytes().to_vec();
    if s.len() % 2 != 0 {
        s.push(b'0');
    }
    let b = hex::decode(&s).unwrap();
    H64::from_slice(&b)
}

fn hex_to_u256(v: String) -> U256 {
    let s = &mut v[2..].as_bytes().to_vec();
    if s.len() % 2 != 0 {
        s.push(b'0');
    }
    let b = hex::decode(&s).unwrap();
    U256::from_big_endian(&b)
}

fn hex_to_u256_le(v: String) -> U256 {
    let s = &mut v[2..].as_bytes().to_vec();
    if s.len() % 2 != 0 {
        s.push(b'0');
    }
    let b = hex::decode(&s).unwrap();
    U256::from_little_endian(&b)
}

fn hex_to_bloom(v: String) -> Bloom {
    let s = &mut v[2..].as_bytes().to_vec();
    if s.len() % 2 != 0 {
        s.push(b'0');
    }
    let b = hex::decode(&s).unwrap();
    Bloom::from_slice(&b)
}

fn hex_to_address(v: String) -> Address {
    let s = &mut v[2..].as_bytes().to_vec();
    if s.len() % 2 != 0 {
        s.push(b'0');
    }
    let b = hex::decode(&s).unwrap();
    Address::from_slice(&b)
}

#[derive(Debug, Clone, Encode, Decode, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlockHeader {
    pub parent_hash: H256,
    pub uncles_hash: H256,
    pub author: Address,
    pub state_root: H256,
    pub transactions_root: H256,
    pub receipts_root: H256,
    pub log_bloom: Bloom,
    pub difficulty: U256,
    pub number: U256,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub mix_hash: H256,
    pub nonce: H64,
    pub hash: H256,
}

#[derive(Debug, Clone)]
pub struct BlockHeaderSeal {
    pub parent_hash: H256,
    pub uncles_hash: H256,
    pub author: Address,
    pub state_root: H256,
    pub transactions_root: H256,
    pub receipts_root: H256,
    pub log_bloom: Bloom,
    pub difficulty: U256,
    pub number: U256,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InfuraBlockHeader {
    pub difficulty: String,
    pub extra_data: String,
    pub gas_limit: String,
    pub gas_used: String,
    pub hash: String,
    pub logs_bloom: String,
    pub miner: String,
    pub mix_hash: String,
    pub nonce: String,
    pub number: String,
    pub parent_hash: String,
    pub receipts_root: String,
    pub sha3_uncles: String,
    pub size: String,
    pub state_root: String,
    pub timestamp: String,
    pub total_difficulty: String,
    pub transactions_root: String,
}

impl From<BlockHeader> for BlockHeaderSeal {
    fn from(b: BlockHeader) -> Self {
        Self {
            parent_hash: b.parent_hash,
            uncles_hash: b.uncles_hash,
            author: b.author,
            state_root: b.state_root,
            transactions_root: b.transactions_root,
            receipts_root: b.receipts_root,
            log_bloom: b.log_bloom,
            difficulty: b.difficulty,
            number: b.number,
            gas_limit: b.gas_limit,
            gas_used: b.gas_used,
            timestamp: b.timestamp,
            extra_data: b.extra_data,
        }
    }
}

impl From<InfuraBlockHeader> for BlockHeader {
    fn from(b: InfuraBlockHeader) -> Self {
        debug::native::info!("{:?}", b);
        Self {
            parent_hash: hex_to_h256(b.parent_hash),
            uncles_hash: hex_to_h256(b.sha3_uncles),
            number: hex_to_u256(b.number),
            author: hex_to_address(b.miner),
            state_root: hex_to_h256(b.state_root),
            transactions_root: hex_to_h256(b.transactions_root),
            receipts_root: hex_to_h256(b.receipts_root),
            log_bloom: hex_to_bloom(b.logs_bloom),
            difficulty: hex_to_u256_le(b.difficulty),
            gas_limit: hex_to_u256(b.gas_limit).as_u64(),
            gas_used: hex_to_u256(b.gas_used).as_u64(),
            timestamp: hex_to_u256(b.timestamp).as_u64(),
            extra_data: b.extra_data.as_bytes().to_vec(),
            mix_hash: hex_to_h256(b.mix_hash),
            nonce: hex_to_h64(b.nonce),
            hash: hex_to_h256(b.hash),
        }
    }
}

impl BlockHeader {
    #[cfg(test)]
    pub fn mock_with(number: u64) -> Self {
        Self {
            parent_hash: H256::random(),
            uncles_hash: H256::random(),
            author: Address::random(),
            state_root: H256::random(),
            transactions_root: H256::random(),
            receipts_root: H256::random(),
            log_bloom: Bloom::random(),
            difficulty: U256::MAX,
            number: U256::from(number),
            gas_limit: 1000,
            gas_used: 100,
            timestamp: 1610749011,
            extra_data: b"Mocked data for tests".to_vec(),
            mix_hash: H256::random(),
            nonce: H64::random(),
            hash: H256::random(),
        }
    }

    pub fn extra_data(&self) -> H256 {
        let mut data = [0u8; 32];
        data.copy_from_slice(&self.extra_data);
        H256(data)
    }

    fn stream_rlp(&self, stream: &mut RlpStream) {
        stream.begin_list(16);

        stream.append(&self.parent_hash);
        stream.append(&self.uncles_hash);
        stream.append(&self.author);
        stream.append(&self.state_root);
        stream.append(&self.transactions_root);
        stream.append(&self.receipts_root);
        stream.append(&self.log_bloom);
        stream.append(&self.difficulty);
        stream.append(&self.number);
        stream.append(&self.gas_limit);
        stream.append(&self.gas_used);
        stream.append(&self.timestamp);
        stream.append(&self.extra_data);
        stream.append(&self.mix_hash);
        stream.append(&self.nonce);
        stream.append(&self.hash);
    }
}

impl RlpEncodable for BlockHeader {
    fn rlp_append(&self, stream: &mut RlpStream) { self.stream_rlp(stream); }
}

impl RlpDecodable for BlockHeader {
    fn decode(serialized: &Rlp) -> Result<Self, RlpDecoderError> {
        let block_header = BlockHeader {
            parent_hash: serialized.val_at(0)?,
            uncles_hash: serialized.val_at(1)?,
            author: serialized.val_at(2)?,
            state_root: serialized.val_at(3)?,
            transactions_root: serialized.val_at(4)?,
            receipts_root: serialized.val_at(5)?,
            log_bloom: serialized.val_at(6)?,
            difficulty: serialized.val_at(7)?,
            number: serialized.val_at(8)?,
            gas_limit: serialized.val_at(9)?,
            gas_used: serialized.val_at(10)?,
            timestamp: serialized.val_at(11)?,
            extra_data: serialized.val_at(12)?,
            mix_hash: serialized.val_at(13)?,
            nonce: serialized.val_at(14)?,
            hash: serialized.val_at(15)?,
        };

        Ok(block_header)
    }
}

impl RlpEncodable for BlockHeaderSeal {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.begin_list(13);

        stream.append(&self.parent_hash);
        stream.append(&self.uncles_hash);
        stream.append(&self.author);
        stream.append(&self.state_root);
        stream.append(&self.transactions_root);
        stream.append(&self.receipts_root);
        stream.append(&self.log_bloom);
        stream.append(&self.difficulty);
        stream.append(&self.number);
        stream.append(&self.gas_limit);
        stream.append(&self.gas_used);
        stream.append(&self.timestamp);
        stream.append(&self.extra_data);
    }
}

// Log

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub address: H160,
    pub topics: Vec<H256>,
    pub data: Vec<u8>,
}

impl rlp::Decodable for LogEntry {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let result = LogEntry {
            address: rlp.val_at(0usize)?,
            topics: rlp.list_at(1usize)?,
            data: rlp.val_at(2usize)?,
        };
        Ok(result)
    }
}

impl rlp::Encodable for LogEntry {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        stream.begin_list(3usize);
        stream.append(&self.address);
        stream.append_list::<H256, _>(&self.topics);
        stream.append(&self.data);
    }
}

// Receipt Header

#[derive(
    Debug, Clone, PartialEq, Eq, RlpEncodableDerive, RlpDecodableDerive,
)]
pub struct Receipt {
    pub status: bool,
    pub gas_used: U256,
    pub log_bloom: Bloom,
    pub logs: Vec<LogEntry>,
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut buffer = [0u8; 32];
    buffer.copy_from_slice(&sha2_256(data));
    buffer
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    keccak.update(data);
    let mut output = [0u8; 32];
    keccak.finalize(&mut output);
    output
}

// https://github.com/paritytech/substrate/commit/510e68b8d06a3d407eda0d4c1c330bd484140b65
pub fn keccak_512(data: &[u8]) -> [u8; 64] {
    let mut keccak = Keccak::v512();
    keccak.update(data);
    let mut output = [0u8; 64];
    keccak.finalize(&mut output);
    output
}

/// Blocks per epoch
pub const EPOCH_LENGTH: u64 = 30000;

#[derive(RuntimeDebug, Default, Clone, Encode, Decode, PartialEq)]
pub struct DoubleNodeWithMerkleProof {
    pub dag_nodes: [H512; 2],
    pub proof: Vec<H128>,
}

impl DoubleNodeWithMerkleProof {
    pub fn new() -> Self {
        Self {
            dag_nodes: [H512::from([0; 64]); 2],
            proof: vec![],
        }
    }

    pub fn from_values(dag_nodes: [H512; 2], proof: Vec<H128>) -> Self {
        Self { dag_nodes, proof }
    }

    fn truncate_to_h128(arr: H256) -> H128 {
        let mut data = [0u8; 16];
        data.copy_from_slice(&(arr.0)[16..]);
        H128(data)
    }

    fn hash_h128(l: H128, r: H128) -> H128 {
        let mut data = [0u8; 64];
        data[16..32].copy_from_slice(&(l.0));
        data[48..64].copy_from_slice(&(r.0));
        Self::truncate_to_h128(sha2_256(&data).into())
    }

    pub fn apply_merkle_proof(&self, index: u64) -> Result<H128, &'static str> {
        let mut data = [0u8; 128];
        data[..64].copy_from_slice(&(self.dag_nodes[0].0));
        data[64..].copy_from_slice(&(self.dag_nodes[1].0));

        let mut leaf = Self::truncate_to_h128(sha2_256(&data).into());

        for i in 0..self.proof.len() {
            let index_shifted =
                index.checked_shr(i as u32).ok_or("Failed to shift index")?;
            if index_shifted % 2 == 0 {
                leaf = Self::hash_h128(leaf, self.proof[i]);
            } else {
                leaf = Self::hash_h128(self.proof[i], leaf);
            }
        }
        Ok(leaf)
    }
}

#[derive(Debug, serde::Serialize)]
pub struct ProofsPayload {
    pub rlp: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct BlockWithProofsRaw {
    pub number: u64,
    pub proof_length: u64,
    pub merkle_root: String,
    pub elements: Vec<String>,
    pub merkle_proofs: Vec<String>,
}

#[derive(Debug)]
pub struct BlockWithProofs {
    pub proof_length: u64,
    pub merkle_root: H128,
    pub elements: Vec<H256>,
    pub merkle_proofs: Vec<H128>,
}

impl From<BlockWithProofsRaw> for BlockWithProofs {
    fn from(raw: BlockWithProofsRaw) -> Self {
        Self {
            proof_length: raw.proof_length,
            merkle_root: H128::from_slice(
                &hex::decode(&raw.merkle_root).unwrap(),
            ),
            merkle_proofs: raw
                .merkle_proofs
                .into_iter()
                .map(|v| hex::decode(&v))
                .flatten()
                .map(|v| H128::from_slice(&v))
                .collect(),
            elements: raw
                .elements
                .into_iter()
                .map(|v| hex::decode(&v))
                .flatten()
                .map(|v| H256::from_slice(&v))
                .collect(),
        }
    }
}

impl BlockWithProofs {
    fn combine_dag_h256_to_h512(elements: Vec<H256>) -> Vec<H512> {
        elements
            .iter()
            .zip(elements.iter().skip(1))
            .enumerate()
            .filter(|(i, _)| i % 2 == 0)
            .map(|(_, (a, b))| {
                let mut buffer = [0u8; 64];
                buffer[..32].copy_from_slice(&(a.0));
                buffer[32..].copy_from_slice(&(b.0));
                H512(buffer.into())
            })
            .collect()
    }

    pub fn to_double_node_with_merkle_proof_vec(
        &self,
    ) -> Vec<types::DoubleNodeWithMerkleProof> {
        let h512s = Self::combine_dag_h256_to_h512(self.elements.clone());
        h512s
            .iter()
            .zip(h512s.iter().skip(1))
            .enumerate()
            .filter(|(i, _)| i % 2 == 0)
            .map(|(i, (a, b))| DoubleNodeWithMerkleProof {
                dag_nodes: [*a, *b],
                proof: self.merkle_proofs[i / 2 * self.proof_length as usize
                    ..(i / 2 + 1) * self.proof_length as usize]
                    .to_vec(),
            })
            .collect()
    }
}
