use crate::*;
use codec::{Encode, Decode};
use frame_support::{
	impl_outer_origin, parameter_types,
	weights::Weight, assert_ok,
};
use sp_core::{
	H256,
	offchain::{OffchainExt, testing},
	sr25519::Signature,
};

use sp_runtime::{
	Perbill,
	testing::{Header, TestXt},
	traits::{
		BlakeTwo256, IdentityLookup, Extrinsic as ExtrinsicT,
		IdentifyAccount, Verify,
	},
};

use rlp::RlpStream;
use futures::future::join_all;
use web3::futures::Future;
use web3::types::Block;
use lazy_static::lazy_static;
use serde::{Deserialize, Deserializer};
use std::panic;
use sp_core::Pair;
use hex::FromHex;

impl_outer_origin! {
	pub enum Origin for Test where system = frame_system {}
}

// For testing the module, we construct most of a mock runtime. This means
// first constructing a configuration type (`Test`) which `impl`s each of the
// configuration traits of modules we want to use.
#[derive(Clone, Eq, PartialEq, Encode, Decode)]
pub struct Test;
parameter_types! {
	pub const BlockHashCount: u64 = 250;
	pub const MaximumBlockWeight: Weight = 1024;
	pub const MaximumBlockLength: u32 = 2 * 1024;
	pub const AvailableBlockRatio: Perbill = Perbill::one();
}
impl frame_system::Trait for Test {
	type BaseCallFilter = ();
	type Origin = Origin;
	type Call = ();
	type Index = u64;
	type BlockNumber = u64;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = sp_core::sr25519::Public;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Header = Header;
	type Event = ();
	type BlockHashCount = BlockHashCount;
	type MaximumBlockWeight = MaximumBlockWeight;
	type DbWeight = ();
	type BlockExecutionWeight = ();
	type ExtrinsicBaseWeight = ();
	type MaximumExtrinsicWeight = MaximumBlockWeight;
	type MaximumBlockLength = MaximumBlockLength;
	type AvailableBlockRatio = AvailableBlockRatio;
	type Version = ();
	type PalletInfo = ();
	type AccountData = ();
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
}

type Extrinsic = TestXt<Call<Test>, ()>;
type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

impl frame_system::offchain::SigningTypes for Test {
	type Public = <Signature as Verify>::Signer;
	type Signature = Signature;
}

impl<LocalCall> frame_system::offchain::SendTransactionTypes<LocalCall> for Test where
	Call<Test>: From<LocalCall>,
{
	type OverarchingCall = Call<Test>;
	type Extrinsic = Extrinsic;
}

impl<LocalCall> frame_system::offchain::CreateSignedTransaction<LocalCall> for Test where
	Call<Test>: From<LocalCall>,
{
	fn create_transaction<C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>>(
		call: Call<Test>,
		_public: <Signature as Verify>::Signer,
		_account: AccountId,
		nonce: u64,
	) -> Option<(Call<Test>, <Extrinsic as ExtrinsicT>::SignaturePayload)> {
		Some((call, (nonce, ())))
	}
}

parameter_types! {
	pub const GracePeriod: u64 = 5;
	pub const UnsignedInterval: u64 = 128;
	pub const UnsignedPriority: u64 = 1 << 20;
}

impl Trait for Test {
	type Event = ();
	type AuthorityId = crypto::TestAuthId;
	type Call = Call<Test>;
	type GracePeriod = GracePeriod;
	type UnsignedInterval = UnsignedInterval;
	type UnsignedPriority = UnsignedPriority;
}

type Example = Module<Test>;

#[derive(Debug)]
struct Hex(pub Vec<u8>);

impl<'de> Deserialize<'de> for Hex {
	fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
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
					for i in 0..16 {
						res[i] = e.0[i];
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

#[derive(Debug)]
struct BlockWithProofs {
	pub proof_length: u64,
	pub header_rlp: Hex,
	pub merkle_root: H128,
	pub elements: Vec<H256>,
	pub merkle_proofs: Vec<H128>,
}

impl From<BlockWithProofsRaw> for BlockWithProofs {
	fn from(item: BlockWithProofsRaw) -> Self {
		let mut temp_merkle_root: [u8; 16] = [0; 16];
		for i in 0..16 {
			temp_merkle_root[i] = item.merkle_root.0[i];
		}
		Self {
			proof_length: item.proof_length,
			header_rlp: item.header_rlp,
			merkle_root: H128::from(temp_merkle_root),
			elements: item.elements.iter().map(|e| {
				let mut temp: [u8; 32] = [0; 32];
				for i in 0..e.0.len() {
					temp[i] = e.0[i];
				}
				H256::from(temp)
			}).collect(),
			merkle_proofs: item
				.merkle_proofs
				.iter()
				.map(|e| {
					let mut temp: [u8; 16] = [0; 16];
					for i in 0..e.0.len() {
						temp[i] = e.0[i];
					}
					H128::from(temp)
				})
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

	pub fn to_double_node_with_merkle_proof_vec(&self) -> Vec<(Vec<H512>, Vec<H128>)> {
		let h512s = Self::combine_dag_h256_to_h512(self.elements.clone());
		h512s
			.iter()
			.zip(h512s.iter().skip(1))
			.enumerate()
			.filter(|(i, _)| i % 2 == 0)
			.map(|(i, (a, b))| {
				let dag_nodes = vec![*a, *b];
				let proof = self.merkle_proofs
					[i / 2 * self.proof_length as usize..(i / 2 + 1) * self.proof_length as usize]
					.to_vec();
				(dag_nodes, proof)
			})
			.collect()
	}
}

fn catch_unwind_silent<F: FnOnce() -> R + panic::UnwindSafe, R>(f: F) -> std::thread::Result<R> {
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
		std::fs::File::open(std::path::Path::new("./src/data/dag_merkle_roots.json")).unwrap(),
	)
	.unwrap()
}

// Wish to avoid this code and use web3+rlp libraries directly
fn rlp_append<TX>(header: &Block<TX>, stream: &mut RlpStream) {
	stream.begin_list(15);
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
}

lazy_static! {
	static ref WEB3RS: web3::Web3<web3::transports::Http> = {
		let (eloop, transport) = web3::transports::Http::new(
			"https://mainnet.infura.io/v3/b5f870422ee5454fb11937e947154cd2",
		)
		.unwrap();
		eloop.into_remote();
		web3::Web3::new(transport)
	};
}

fn get_blocks(
	web3rust: &web3::Web3<web3::transports::Http>,
	start: usize,
	stop: usize,
) -> (Vec<Vec<u8>>, Vec<H256>) {
	let futures = (start..stop)
		.map(|i| web3rust.eth().block((i as u64).into()))
		.collect::<Vec<_>>();

	let block_headers = join_all(futures).wait().unwrap();

	let mut blocks: Vec<Vec<u8>> = vec![];
	let mut hashes: Vec<H256> = vec![];
	for block_header in block_headers {
		let eth_header = ethereum::Header {
			parent_hash: sp_core::H256(block_header.clone().unwrap().parent_hash.0),
			ommers_hash: sp_core::H256(block_header.clone().unwrap().uncles_hash.0),
			beneficiary: sp_core::H160(block_header.clone().unwrap().author.0),
			state_root: sp_core::H256(block_header.clone().unwrap().state_root.0),
			transactions_root: sp_core::H256(block_header.clone().unwrap().transactions_root.0),
			receipts_root: sp_core::H256(block_header.clone().unwrap().receipts_root.0),
			logs_bloom: block_header.clone().unwrap().logs_bloom.0.into(),
			difficulty: sp_core::U256(block_header.clone().unwrap().difficulty.0),
			number: sp_core::U256::from(block_header.clone().unwrap().number.unwrap().as_u64()),
			gas_limit: sp_core::U256(block_header.clone().unwrap().gas_limit.0),
			gas_used: sp_core::U256(block_header.clone().unwrap().gas_used.0),
			timestamp: block_header.clone().unwrap().timestamp.as_u64(),
			extra_data: block_header.clone().unwrap().extra_data.0,
			mix_hash: sp_core::H256(block_header.clone().unwrap().mix_hash.unwrap().0),
			nonce: ethereum_types::H64(block_header.clone().unwrap().nonce.unwrap().0),
		};
		println!("{:?}", eth_header.hash());
		println!("{:?}", H256(block_header.clone().unwrap().hash.unwrap().0.into()));
		println!("{:?}", block_header);
		let mut stream = RlpStream::new();
		rlp_append(&block_header.clone().unwrap(), &mut stream);
		blocks.push(stream.out());
		let mut stream = RlpStream::new();
		rlp_append(&block_header.clone().unwrap(), &mut stream);
		let header: ethereum::Header = rlp::decode(&stream.out()).unwrap();
		// println!("{:?}", header.hash());
		println!("\n");
		hashes.push(H256(block_header.clone().unwrap().hash.unwrap().0.into()));
	}

	(blocks, hashes)
}

fn read_block(filename: String) -> BlockWithProofs {
	read_block_raw(filename).into()
}

fn read_block_raw(filename: String) -> BlockWithProofsRaw {
	serde_json::from_reader(std::fs::File::open(std::path::Path::new(&filename)).unwrap()).unwrap()
}


#[test]
fn should_make_http_call_and_parse_result() {
	let (offchain, state) = testing::TestOffchainExt::new();
	let mut t = sp_io::TestExternalities::default();
	t.register_extension(OffchainExt::new(offchain));

	set_block_response(&mut state.write());

	t.execute_with(|| {
		// when
		let number = Example::fetch_block().unwrap();
		// then
		assert_eq!(number, 8934751);
	});
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

#[test]
fn should_init() {
	let mut t = sp_io::TestExternalities::default();
	t.execute_with(|| {
		let (blocks, _) = get_blocks(&WEB3RS, 400_000, 400_001);
		let pair = sp_core::sr25519::Pair::from_seed(b"12345678901234567890123456789012");
		let dmr = read_roots_collection();
		assert_ok!(Example::init(
			Origin::signed(pair.public()),
			0,
			read_roots_collection().dag_merkle_roots,
			blocks[0].clone(),
			U256::from(30),
			U256::from(10),
			U256::from(10),
			None,
		));

		assert_eq!(dmr.dag_merkle_roots[0], Example::dag_merkle_root(0));
		assert_eq!(dmr.dag_merkle_roots[10], Example::dag_merkle_root(10));
		assert_eq!(dmr.dag_merkle_roots[511], Example::dag_merkle_root(511));

		let result = catch_unwind_silent(|| Example::dag_merkle_root(512));
		assert!(result.is_err());
	});
}

#[test]
fn should_add_blocks_2_3_and_verify() {
	let mut t = sp_io::TestExternalities::default();
	t.execute_with(|| {
		let pair = sp_core::sr25519::Pair::from_seed(b"12345678901234567890123456789012");
		// Check on 3 block from here: https://github.com/KyberNetwork/bridge_eos_smart_contracts/blob/master/scripts/jungle/jungle_relay_3.js
		let (blocks, hashes) = get_blocks(&WEB3RS, 2, 4);

		// $ ../ethrelay/ethashproof/cmd/relayer/relayer 3
		let blocks_with_proofs: Vec<BlockWithProofs> = ["./src/data/2.json", "./src/data/3.json"]
			.iter()
			.map(|filename| read_block((&filename).to_string()))
			.collect();

		for i in 0..blocks.len() {
			let b = &blocks[i];
			let header: ethereum::Header = rlp::decode(b.as_slice()).unwrap();
			println!("{:?}, {:?}", header.hash(), hashes[i]);
		}

		assert_ok!(Example::init(
			Origin::signed(pair.public()),
			0,
			read_roots_collection().dag_merkle_roots,
			blocks[0].clone(),
			U256::from(30),
			U256::from(10),
			U256::from(10),
			None,
		));

		for (block, proof) in blocks
			.into_iter()
			.zip(blocks_with_proofs.into_iter())
			.skip(1)
		{
			assert_ok!(Example::add_block_header(
				Origin::signed(pair.public()),
				block,
				proof.to_double_node_with_merkle_proof_vec(),
			));
		}

		assert_eq!((hashes[1].0), (Example::block_hash(3).unwrap().0));
	})
}