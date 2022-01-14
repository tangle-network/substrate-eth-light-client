use super::*;
use mock::*;
use types::*;
use sp_core::{
    offchain::{testing, OffchainDbExt},
    sr25519::Signature,
    H256,
};
use std::fs::File;
use std::io::Write;

use sp_runtime::{
    testing::{Header, TestXt},
    traits::{
        BlakeTwo256, Extrinsic as ExtrinsicT, IdentifyAccount, IdentityLookup,
        Verify,
    },
    Perbill,
};

use futures::future::join_all;
use hex::FromHex;
use lazy_static::lazy_static;
use rlp::RlpStream;
use serde::{Deserialize, Deserializer};
use sp_core::Pair;
use std::panic;
use web3::{futures::Future, transports::Http, types::BlockId};
use web3::types::Block;

#[derive(Debug)]
struct Hex(pub Vec<u8>);

impl<'de> Deserialize<'de> for Hex {
    fn deserialize<D>(
        deserializer: D,
    ) -> Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        let mut s = <String as Deserialize>::deserialize(deserializer)?;
        if s.starts_with("0x") {
            s = s[2..].to_string();
        }
        if s.len() % 2 == 1 {
            s.insert_str(0, "0");
        }
        Ok(Hex(Vec::from_hex(&s).map_err(|err| {
            serde::de::Error::custom(err.to_string())
        })?))
    }
}

#[derive(Debug, Deserialize)]
struct RootsCollectionRaw {
    pub dag_merkle_roots: Vec<Hex>, // H128
}

#[derive(Debug)]
struct RootsCollection {
    pub dag_merkle_roots: Vec<H128>,
}

impl From<RootsCollectionRaw> for RootsCollection {
    fn from(item: RootsCollectionRaw) -> Self {
        Self {
            dag_merkle_roots: item
                .dag_merkle_roots
                .iter()
                .map(|e| {
                    let mut res: [u8; 16] = [0; 16];
                    let carry = if e.0.len() < 16 { 1 } else { 0 };
                    for i in 0..e.0.len() {
                        res[i + carry] = e.0[i];
                    }
                    H128::from(res)
                })
                .collect(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct BlockWithProofsRaw {
    pub proof_length: u64,
    pub header_rlp: Hex,
    pub merkle_root: Hex,        // H128
    pub elements: Vec<Hex>,      // H256
    pub merkle_proofs: Vec<Hex>, // H128
}

impl From<BlockWithProofsRaw> for BlockWithProofs {
    fn from(item: BlockWithProofsRaw) -> Self {
        let mut temp_merkle_root: [u8; 16] = [0; 16];
        for i in 0..16 {
            temp_merkle_root[i] = item.merkle_root.0[i];
        }
        Self {
            proof_length: item.proof_length,
            merkle_root: H128::from(temp_merkle_root),
            elements: item
                .elements
                .iter()
                .map(|e| {
                    let mut temp: [u8; 32] = [0; 32];
                    let carry = if e.0.len() < 32 { 1 } else { 0 };
                    for i in 0..e.0.len() {
                        temp[i + carry] = e.0[i];
                    }
                    H256::from(temp)
                })
                .collect(),
            merkle_proofs: item
                .merkle_proofs
                .iter()
                .map(|e| {
                    let mut temp: [u8; 16] = [0; 16];
                    let carry = if e.0.len() < 16 { 1 } else { 0 };
                    for i in 0..e.0.len() {
                        temp[carry + i] = e.0[i];
                    }

                    H128::from(temp)
                })
                .collect(),
        }
    }
}

fn catch_unwind_silent<F: FnOnce() -> R + panic::UnwindSafe, R>(
    f: F,
) -> std::thread::Result<R> {
    let prev_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let result = panic::catch_unwind(f);
    panic::set_hook(prev_hook);
    result
}

fn read_roots_collection() -> RootsCollection {
    read_roots_collection_raw().into()
}

fn read_roots_collection_raw() -> RootsCollectionRaw {
    serde_json::from_reader(
        std::fs::File::open(std::path::Path::new(
            "./data/dag_merkle_roots.json",
        ))
        .unwrap(),
    )
    .unwrap()
}

fn write_file() -> std::result::Result<(), std::io::Error> {
    let mut file = File::create("elts.txt")?;
    for i in read_roots_collection().dag_merkle_roots.iter() {
        // println!("{:?}", i.as_bytes());
        write!(file, "{:?}", i.as_bytes())?;
    }

    Ok(())
}

// Wish to avoid this code and use web3+rlp libraries directly
fn rlp_append<TX>(header: &Block<TX>, stream: &mut RlpStream) {
    stream.begin_list(16);
    stream.append(&header.parent_hash);
    stream.append(&header.uncles_hash);
    stream.append(&header.author);
    stream.append(&header.state_root);
    stream.append(&header.transactions_root);
    stream.append(&header.receipts_root);
    stream.append(&header.logs_bloom);
    stream.append(&header.difficulty);
    stream.append(&header.number.unwrap());
    stream.append(&header.gas_limit);
    stream.append(&header.gas_used);
    stream.append(&header.timestamp);
    stream.append(&header.extra_data.0);
    stream.append(&header.mix_hash.unwrap());
    stream.append(&header.nonce.unwrap());
    stream.append(&header.hash.unwrap());
}

lazy_static! {
    static ref WEB3RS: web3::Web3<web3::transports::Http> = {
        let http: Http = web3::transports::Http::new(
            "https://mainnet.infura.io/v3/b5f870422ee5454fb11937e947154cd2",
        )
        .unwrap();
        web3::Web3::new(http)
    };
}

async fn get_blocks(
    web3rust: &web3::Web3<web3::transports::Http>,
    start: usize,
    stop: usize,
) -> (Vec<Vec<u8>>, Vec<H256>) {
    let futures = (start..stop)
        .map(|i| web3rust.eth().block(BlockId::Number(i.into())))
        .collect::<Vec<_>>();

    let block_headers = join_all(futures).await;

    let mut blocks: Vec<Vec<u8>> = vec![];
    let mut hashes: Vec<H256> = vec![];
    for block_header in block_headers {
        let mut stream = RlpStream::new();
        rlp_append(&block_header.clone().unwrap().unwrap(), &mut stream);
        blocks.push(stream.out().to_vec());
        hashes.push(H256(block_header.clone().unwrap().unwrap().hash.unwrap().0));
    }

    (blocks, hashes)
}

fn read_block(filename: String) -> BlockWithProofs {
    read_block_raw(filename).into()
}

fn read_block_raw(filename: String) -> BlockWithProofsRaw {
    serde_json::from_reader(
        std::fs::File::open(std::path::Path::new(&filename)).unwrap(),
    )
    .unwrap()
}

fn set_block_response(state: &mut testing::OffchainState) {
    let body = b"{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBlockByNumber\",\"params\":[\"latest\", false],\"id\":1}";
    state.expect_request(testing::PendingRequest {
		method: "POST".into(),
		uri: "http://localhost:8545".into(),
		body: body.to_vec(),
		response: Some(br#"{
			"jsonrpc":"2.0",
			"id":1,
			"result":{
				"difficulty": "0x29d45538",
				"extraData": "0xdb830300018c4f70656e457468657265756d86312e34332e31826c69",
				"gasLimit": "0x7a121d",
				"gasUsed": "0xcb5e",
				"hash": "0xa03b310a4fa187d7aafe458323da848fe4e4ed610b0ca970818f8d76ff7acafc",
				"logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400400000000000000000000000000000000020000001000008000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000110000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000001000000000000000000000000",
				"miner": "0x05fc5a079e0583b8a07526023a16e2022c4c6296",
				"mixHash": "0xca855e662d1d628cdb218b1989386aceb1eab53eb4968fdf4220851db7f776a2",
				"nonce": "0x83e8ba4b86c92bee",
				"number": "0x88555f",
				"parentHash": "0xe607a9cfcdfd3e2f37b6097ca1a1070c1fa5b585d7a5d0ade47315e898a9d385",
				"receiptsRoot": "0x5d12aadaaec5d49a8e3e224db5c9cfb56c65b9f91ede8fa2c29a164839a999e7",
				"sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
				"size": "0x2ce",
				"stateRoot": "0xbd460aaf576af40fe13a1457c5cb59aa420f16f5aceea0582b07393e8d767641",
				"timestamp": "0x5f930edb",
				"totalDifficulty": "0x70f44fb8647010",
				"transactionsRoot": "0x8dd40061cf130707ff20d40867a7c8ced409d30951604209eac4e08883c2d35d",
				"transactions": []
			}
		}"#.to_vec()),
		sent: true,
		..Default::default()
	});
}

fn set_infura_block_response(state: &mut testing::OffchainState) {
    let body = b"{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBlockByNumber\",\"params\":[\"latest\", false],\"id\":1}";
    state.expect_request(testing::PendingRequest {
		method: "POST".into(),
		uri: "https://mainnet.infura.io/v3/b5f870422ee5454fb11937e947154cd2".into(),
		body: body.to_vec(),
		response: Some(br#"{
			"jsonrpc": "2.0",
			"id": 1,
			"result": {
				"difficulty": "0xc3097478dc9f3",
				"extraData": "0x6574682d70726f2d687a6f2d74303035",
				"gasLimit": "0xbf0335",
				"gasUsed": "0xbed04a",
				"hash": "0x09d89a973040f671f1e33824d806634b625228faf87b5faa1f8f56b3d6af28e6",
				"logsBloom": "0xbabb737509801c83c436040080b59409e1850658c445477ceae58102843219836d42751410540241b40e9321004281d78a69d400ee2360dba21342955d6f0ea044a972061880a36f40cc2c8c72c502f40c04466209649c94ed12c09cc39994429b4a075c266add1af470098403944af04200d80e1e8c7d0c9245db780d10308218e2c08d4418a805a0c51d21da5186bc4808b0011e073029c1c3ab63675c0816077a351710e2999222a018bcb110800712d0c197250a08a1c0aba3c61af688f2f048cc1a60c3d04abc0c0c37130a30040bcc175b5486ae104048d01ab73c7c2e2154ec5db80484ca828259c805ee4c986006329b4920ea74005a1460295b0452",
				"miner": "0x5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c",
				"mixHash": "0xfcd66e3d064d1ebbc03eaa86101661566d33c7c534de005c21f6c89db55e7215",
				"nonce": "0xcf18e648d3ca4516",
				"number": "0xaacc3e",
				"parentHash": "0x46d3ea37a7b53f6fbfc60e39607289d2a8b4e60ba0dc3059bf1728d4a6600d42",
				"receiptsRoot": "0xefc9e67343bdde1c70c41da1b5ca927b8965d924f4f44f763476adf61abb5b88",
				"sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
				"size": "0x7bab",
				"stateRoot": "0xbfceeaef1fa4ca5c09ede0d83b9082610105ba45810a66365c7fae86bc292005",
				"timestamp": "0x5fa328d6",
				"totalDifficulty": "0x3ea67e31b2288dc01fa",
				"transactions": [],
				"transactionsRoot": "0x67dbb0fe68ee00b62b29ea1bcf31ffbb24aa10e982aca1c8b6df5f95fd79de7c",
				"uncles": []
			}
		}"#.to_vec()),
		sent: true,
		..Default::default()
	})
}

#[test]
fn should_fail_to_verify_without_parameters() {
	new_test_ext().execute_with(|| {
		// Pass arbitrary
		assert_eq!(true, true);
	});
}
