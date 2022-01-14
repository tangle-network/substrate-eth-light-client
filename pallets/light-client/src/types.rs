use crate::*;
use ethereum_types::{Address, Bloom, H160, H256, H64, U256};
use rlp::{Rlp, RlpStream};
use rlp_derive::{
    RlpDecodable as RlpDecodableDerive, RlpEncodable as RlpEncodableDerive,
};
use codec::{Encode, Decode};
use scale_info::TypeInfo;
use sp_std::vec::Vec;

extern crate alloc;
use alloc::string::String;

use sp_runtime::RuntimeDebug;

/// Minimal information about a header.
#[derive(Clone, Encode, Decode, TypeInfo)]
pub struct HeaderInfo {
    pub total_difficulty: U256,
    pub parent_hash: H256,
    pub number: U256,
}

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
        s.insert(0, b'0'); // big endian .. add to the first.
    }
    let b = hex::decode(&s).unwrap();
    U256::from_big_endian(b.as_slice())
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

#[derive(Debug, Clone, Encode, Decode, PartialEq, Eq, PartialOrd, Ord, TypeInfo)]
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
}

#[derive(Debug, Clone, serde::Deserialize, TypeInfo)]
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

impl Into<BlockHeader> for InfuraBlockHeader {
    fn into(self) -> BlockHeader {
        let extra_data = hex::decode(&self.extra_data[2..])
            .expect("bad extra data hex value");
        BlockHeader {
            parent_hash: hex_to_h256(self.parent_hash),
            uncles_hash: hex_to_h256(self.sha3_uncles),
            number: hex_to_u256(self.number),
            author: hex_to_address(self.miner),
            state_root: hex_to_h256(self.state_root),
            transactions_root: hex_to_h256(self.transactions_root),
            receipts_root: hex_to_h256(self.receipts_root),
            log_bloom: hex_to_bloom(self.logs_bloom),
            difficulty: hex_to_u256(self.difficulty),
            gas_limit: hex_to_u256(self.gas_limit).as_u64(),
            gas_used: hex_to_u256(self.gas_used).as_u64(),
            timestamp: hex_to_u256(self.timestamp).as_u64(),
            extra_data,
            mix_hash: hex_to_h256(self.mix_hash),
            nonce: hex_to_h64(self.nonce),
        }
    }
}

impl BlockHeader {
    pub fn hash(&self) -> H256 {
        let mut stream = RlpStream::new();
        self.stream_rlp(&mut stream, false);
        let data = stream.out();
        crate::keccak_256(&data).into()
    }

    pub fn seal_hash(&self) -> H256 {
        let mut stream = RlpStream::new();
        self.stream_rlp(&mut stream, true);
        let data = stream.out();
        crate::keccak_256(&data).into()
    }

    fn stream_rlp(&self, stream: &mut RlpStream, partial: bool) {
        stream.begin_list(13 + if !partial { 2 } else { 0 });
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

        if !partial {
            stream.append(&self.mix_hash);
            stream.append(&self.nonce);
        }
    }
}

impl rlp::Encodable for BlockHeader {
    fn rlp_append(&self, s: &mut RlpStream) { self.stream_rlp(s, false); }
}

impl rlp::Decodable for BlockHeader {
    fn decode(rlp: &Rlp) -> Result<Self, rlp::DecoderError> {
        Ok(Self {
            parent_hash: rlp.val_at(0)?,
            uncles_hash: rlp.val_at(1)?,
            author: rlp.val_at(2)?,
            state_root: rlp.val_at(3)?,
            transactions_root: rlp.val_at(4)?,
            receipts_root: rlp.val_at(5)?,
            log_bloom: rlp.val_at(6)?,
            difficulty: rlp.val_at(7)?,
            number: rlp.val_at(8)?,
            gas_limit: rlp.val_at(9)?,
            gas_used: rlp.val_at(10)?,
            timestamp: rlp.val_at(11)?,
            extra_data: rlp.val_at(12)?,
            mix_hash: rlp.val_at(13)?,
            nonce: rlp.val_at(14)?,
        })
    }
} // Log

#[derive(Default, Debug, Clone, PartialEq, Eq, TypeInfo)]
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
    Debug, Clone, PartialEq, Eq, RlpEncodableDerive, RlpDecodableDerive, TypeInfo
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

#[derive(RuntimeDebug, Default, Clone, Encode, Decode, PartialEq, TypeInfo)]
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

#[derive(Debug, serde::Serialize, TypeInfo)]
pub struct ProofsPayload {
    pub rlp: String,
}

#[derive(Debug, serde::Deserialize, TypeInfo)]
pub struct BlockWithProofsRaw {
    pub number: u64,
    pub proof_length: u64,
    pub merkle_root: String,
    pub elements: Vec<String>,
    pub merkle_proofs: Vec<String>,
}

#[derive(Debug, TypeInfo)]
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
                .map(|v| v.parse::<H128>().unwrap())
                .collect(),
            elements: raw
                .elements
                .into_iter()
                .map(|v| v.parse::<H256>().unwrap())
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
                H512(buffer)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infura_header() {
        let json = serde_json::json!({
            "difficulty": "0xedbaf37f0c430",
            "extraData": "0x65746865726d696e652d7573322d312d67657468",
            "gasLimit": "0xbe8c72",
            "gasUsed": "0xbe7ab8",
            "hash": "0xd3a0b6eda8368e73530dc8bd2091a785457994205d6daf5d911984aefa666f60",
            "logsBloom": "0x50a65b12e0d4c92d21a42eb480255a29dfc125103a3802347205319910032b885525334574c0a1d95849d35ed04805798aa3828a0f52855789d782c24478401a0a03e682837ac388d912500ef4040364d801404c8becaae11140d27ad25671115c5a89d5b764a49638a8c71099b09978866239641d3c0fc918267277492324cb9a409eb7abd94aae1c48872467401413881c99d15db5575b0002f8c7c0950c38af53278ecad22932644b98ccdfd23eae22856297b0301071f1c6d30dd81001012c607847198456aaa80f07f3e4c2dc0d6528cbc34526c81027bef663c47567903c392211d5b0602b9aa6561f1101b3bf0c20d792b0362652a48d9be6227bb654",
            "miner": "0xea674fdde714fd979de3edf0f56aa9716b898ec8",
            "mixHash": "0x1f6fbb053a40da369e84407233bb174d293a9fee38782fe9300208b1b7600b4e",
            "nonce": "0xc2ea5685a61d9478",
            "number": "0xb25416",
            "parentHash": "0xbeb860381c8f28470fcdf0032c1030adce78aeed382a8731a11b032410da6923",
            "receiptsRoot": "0x2eff104e916ce3355e760620970c4c3685189b19d99233fdedf86fb14dd49792",
            "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            "size": "0xac83",
            "stateRoot": "0xaf1d85b69363d59e5a2c8a1c67028e9f4c2c5dd1a513f0de4eb35e431dd1cf40",
            "timestamp": "0x60070e01",
            "totalDifficulty": "0x44c77312392e01c990e",
            "transactionsRoot": "0xdf0f809fdbfa4780e58f27669b8cd07ee5ad0836d75a5511002c8b2043ce91b7",
        });

        let infura_header = serde_json::from_value::<InfuraBlockHeader>(json);
        let b: BlockHeader = infura_header.unwrap().into();
        eprintln!("{:#?}", b);
        assert_eq!(b.number.as_u64(), 11_686_934);
        assert_eq!(b.difficulty.as_u64(), 4_182_195_278_234_672);
    }
}
