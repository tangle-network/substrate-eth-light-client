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
	type AuthorityId = crypto::AuthId;
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
				let carry = if e.0.len() < 32 { 1 } else { 0 };
				for i in 0..e.0.len() {
					temp[i + carry] = e.0[i];
				}
				H256::from(temp)
			}).collect(),
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
		let mut stream = RlpStream::new();
		rlp_append(&block_header.clone().unwrap(), &mut stream);
		blocks.push(stream.out());
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
		let number = Example::fetch_block_header().unwrap().number;
		// then
		assert_eq!(number, 8934751);
	});
}

#[test]
fn should_make_infura_call_and_parse_result() {
	let (offchain, state) = testing::TestOffchainExt::new();
	let mut t = sp_io::TestExternalities::default();
	t.register_extension(OffchainExt::new(offchain));

	set_infura_block_response(&mut state.write());

	t.execute_with(|| {
		// when
		let number = Example::fetch_block_header().unwrap().number;
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
				"transactions": [
					"0x11af72b7045f39e7a555c5bb4ef08709c52c62c70070ee9de727a3d0c6f2ccee",
					"0x45886fec4045ffd5cdd62f28d9205c5e9880d68341e324a30a7581bef29ffbac",
					"0x31da6887c8cab1cd7e8ffba99f5efebb5a8d28a7a729f6972ec3059b659f8790",
					"0xfafc3f9a763f4113e8cfb4847946824df8a7eeb8fbc9558574c705f6c80d77c2",
					"0xb4423f7fa235b10986d466fe80deec3c1538740768cf337eef046a60efc12731",
					"0xcacb6c408284ef94325aa11547edb9a9ebbf0073ab64e70c4b3a9bdd29b3f9f8",
					"0x51964bc3e0bc4601597a48bcc4cd7bb68710cd2cab72622aadfda6c2ab992309",
					"0x0eef047a4d56eaf5fdd58ef6753dc240c49c199720155f708488e1c85b6497dd",
					"0xddc0ed6d16977cdfdc6cdf8e1d3d28104532194fb074774037b6d980179fc197",
					"0xb2f9f66c6d796094f74d8029ab65a159db8238ae837f62ce53513c21e2ef5c7d",
					"0x1020781f8f8997b36cbb3e453f4b245fedc599baaa3b450a33974627b150baea",
					"0x5012210254fa8c099feb566f79cd2a9766d1ff3221419df753eab9744a8deee6",
					"0x92a816d5c441c09260e1017c59d375dccdbf3dddf11da9290f46834dc1ffabe8",
					"0x29c497cec05ca52bbcbc289dbedb58cdf37b09cef040d0a33a9a27b0c0d243db",
					"0xa181cb28a350609ebd0728cdf7403f353ad10e404536b98efef700b6c3a0a908",
					"0x777a4bfaa07a26a5c4415d5924b986361cbf3881a130c9e609ff777e95301093",
					"0x2c807e01f7606d9eac9c841284357b68806d5bb87e788ca8ad6955e5004543ee",
					"0xa1fada6bf2f524f4ab28abe28e9493d4c54be0742bbf0a60a3539f43e2ffa2e6",
					"0xfa54502045f5c52ad2f0db837859a3bbe1cd8e36c05b27d2358081a7cd242b49",
					"0x728d671d4541a9d37596822969c29c3ed9929b68c68069a9751dfa999c3ca5ff",
					"0xb2844b0934f9fc85420e9f28278afb049d8e4744988e8c348522a65e7b5c15e7",
					"0x1ec0b54e495b47d3744ff8058747afd6cca4bf3094c49e8f37292e6f5c51484c",
					"0x31aae3ce3abef21e5e07d0581a8dc3fe6709b1684ac1526a6e562d1a5d78d5c8",
					"0x5f231c8c7769af2978a19cbf1f0c5dfef9bb79ede582eadd329f01cdf51bb796",
					"0x763587307cd8b2857bfcba2172540cfca3fc9e21e587dcecc2e4fd7cd84470cc",
					"0xa9b32ac1b27147b095e26682a166f97b022e5753cb8b54258a2dbc515a5fe167",
					"0xd9d741067cffa84b71a56064beffe44f6bb1ffe54d2801d65fdcaf4e296f8a1a",
					"0x5af4b6fd5fe7643029ec9c7bccd6ec57c79e284a2316281f532454ad0d8267a0",
					"0x277639eb2c876123a847b83256110b7b2a87522e9c190db44248a0a5511379ce",
					"0x24ee160643307263849ba19b5118b325d3b9e15c55ede35dfdff6a899d49092e",
					"0x6e4942026bf7d908d2634c6436a529462717b05b37ac4c4f8c50dc6e2921a7d3",
					"0x87849358b330309fa6b65606a8a41007c76df98cc0f51b4e50b255fb6ea1df15",
					"0xab757a441e0996e2fd0fc1852037e97d234d94bee05d8c5f2be9ce3ae41abacf",
					"0x04694708a2415dd1a120ef5ec0cb1a097fa4a31b7e9b42a5f89ba834d03226d9",
					"0x91b646f39e8fc01301dab3bfbd8c5a984330f50a174d353721e9fe67003db619",
					"0xd04cfbb6dd38ce4ddf8ff25261caf61b7b558a383904c10b2e73ebe993c1e27e",
					"0x3cc4c5a9f4bd9652442c91da4580678e87946b4759b1efc54439a95d4eb476e3",
					"0x71b045d2872060ca2c2b06ed864fb9026a4282b502fb79ec0c12a121443e0df0",
					"0xebd338c7257c0d681c006282238833d0ec5fc7c920af761e76f5e787a5c5251f",
					"0x7ac5d2d84cf05a62b1081460c4e74a14df365f8ab414c8322d606ef13bdda170",
					"0x3840b2df0bab5fa904dfcae2fe19aaecf9569c2ab6843c4357ffa5005f070976",
					"0xf450608058695c81132cacb1d18cb9dc5e1b01912d273308a04a2298d5f9e9e7",
					"0x5470e86ca95df6da000f4a9a5d4cf37312753c3a3e7f9f91f999c391ad0c1eb9",
					"0x97982bb51771e6bbc155d62b79014fd66f8f1592f39d69b8f4341dfeb6490e55",
					"0xfcc430c5d86fc3020127b844ed585269ab8738d14c79a202f57cfd9d3282756a",
					"0xd5ff5e80fd343a7ac057edec345aab81a159b710e15b4e7e03194f139b0023ce",
					"0xe3c2333328a26f4c57e2ba7f7abdbf43612cdb688162ccdb77ee927792d2c9b7",
					"0x922b53d04592828e012d9d2f6bb6dca4666e9fded186893c4bbdb43d2de4b2f2",
					"0xac42e10b08c275d5309bdc3a8f0d3b5b0763d960e8b830337f136eeb0acbba06",
					"0xea4e0b4a8df0ef703b1c101871ca7ac1088be834d393cdc8aa3095769052f9d8",
					"0xa05477103e37424b7675e6b2d72254221c167a61169770439382f705bac51cf9",
					"0x4eda5b8baf06fcc8ac46bca1d298effc2eb9ee4ec8350fde8f528e7e0a3dc4b1",
					"0xf2bb30b24c0c531b3d9ac89bdcbc6f0d65c81e4fba4a934eaadff80183ef0e54",
					"0x030c47f1ca5155ea7bbc3787efb3d7b9c60da9ee9300e59b2f3ab41499d18915",
					"0x4e281dcf58ec0a79262afccef1b78bc8ade560ab78b6dd585d88fd8f2fa9381b",
					"0xefbbadd563761a353aea19752b6756619024bff35373d9ca2f297bd9b8414470",
					"0x5b16b4c2507609938a9f47c567feadd978a31736f1902ad971c04bdffa08edfa",
					"0x50c594032b7c4c6ddb61edb235d9f650554c128e7e84d89ab409c6aec828d1df",
					"0x88e4e3f6d39ff88def86a3c21c46d26315fdb855c28ccc549f92c6c72787feab",
					"0x5937ae2406e9cfe1427f4ae1ab52a93d66afcfe54ac9db310ffa9f0d5422b038",
					"0xced0ab87daa5ac909aa245d25479fe1505a4504d1f8acb5d4ab2bed04a6b1a6a",
					"0x587156342419cb6b6fc9d205e7c24c86c4b9c8636fbfa7b9551e5282c304fd4d",
					"0xef14c0a2517083fa9cd0658d14d806214e25a9a225bc5c74ebfafa8bc306f7c1",
					"0xab4b4eee10e5b4c4891ab82a82b1d3c3eef502800e92cd8241e96eb276c276ff",
					"0xef93d8cfad880419158189b9ca3f9857ba46325ee48a66cf08418ccf99dfdbe1",
					"0x0de4f0a3879b7c58cc4fb4d573d3823734dd7b773bf44cc967ce2a0c26b968d9",
					"0x8b0047d72da0f5cb34da5f0d8a40e429f1f287f68fef26d09a32ff4405e83d26",
					"0x4d0b00bacd26c571431e6f70eb75dc2806870291fa91da072c0fb99c0121918f",
					"0x1908db3b5e95232b3d2a419de50ce47becb7041fe307abd280c7e90ddc42c0bb",
					"0xb61db202a9e62096344ff7c8a097405bb5a3e011917e7c67d8760e8b338d1a28",
					"0x1db41093586f1ecf387a4a3b5879832f235bcef6fe00283b8ac1869c37ad7f0b",
					"0xef4f5c7718f9ae020d1c5305d08db99b7934a2340bb915f9b12806bd343e01f7",
					"0x6263c8cff1973047f90ee59e52cab0a68a9f6c545b40e8c266808cc5ff34dad9",
					"0xf2aff8627f9b063a707c0a8c887d6be9ea8356dee6c0850e83d8d4224f94c32e",
					"0x5b767e2d6776d778aecb137499c7199d0dfac220365439cba63219d7129befd1",
					"0x15fa2f162782fd2a612f7b85bbc6e07741c4798097c6b3f3926f0d51a6bb4d86",
					"0xabf535ec9c3127efce8448a94283cf32c435df2c2259e2db77b8277fea702055",
					"0xdbb62f0c16e8bdd871ac8877e02a843740ad99c62ec19be8504da7578f7cceec",
					"0x5fee4d6bea740ef95e489c67d8dbc53b6026c663e45e93b57c10acfab50515f3",
					"0x619bdaab5e8cefd222e1651dfae3642394a1e8d291580d35fe57db12c051d3ac",
					"0x43f2a837b7c5140cfb3b952d14dc9676ef3cd20bd4bc8e7441c0d788dcd9c15c",
					"0x2c65d3846305dda39a647d249703cb0efedc38ae7def528c62f5ec2c60140aea",
					"0x11b025acab9246a3fdf13bb12ecd438d0ac9b117f475ee5741876c2e65630f62",
					"0xdcb560422d40668ffb1922f26974db09fd83d8e2518171f6a88ee339ab7f6e80",
					"0x5c37c846a94a2cc1c19caeaeabeb37675385f970f5aa3eaaaf65ebeec6830a1b",
					"0xd64771fd6f69984611ead0c501d7d43943e0bb642b9bf1835e949490b104e27b",
					"0xfe6ce49fe4019ea44e6d6968925546feddf6bd1ba6736da8aad242f36eff743c",
					"0xc45043db14025c9592abaf66050b86d584ece7c7b21ae75aa3081be80c768713",
					"0xc8ce36a29103fbf27b01a3f05efee26a7e61cb8eed592b95ad96323908745501",
					"0xf55d9f4247899244c4188aa81513494020cf12a39cd8c689e2ee45cf039b821d",
					"0x5129df582f45aa2f27fad4e18dac65aed52a2319cbec24074ce14ef8c1a50c11",
					"0x9838517e2203a4a7961e9a11260e01faf09eebabfff86ee3304c543b4ada45b3",
					"0xa37e6f21c7286ca4d7d95d4cce5bdd460a238857f0dfdce8ad72733dc2077c59",
					"0x35d7be63adbd8b21753c3cea87549baa566a7d029b93fafcd2062b4aec9f7f0e",
					"0xd13f824ed7cdbed540623c23a74eb440e7e009b3e00aeb06fe46ce7b11312329",
					"0x88480b73a5ee72a20d13d16a475bfd3a7fc18d47e7eaabf89fd331c40ffc1d23",
					"0x54fe5470661613f0f36ce91f16d8be8bc192ee7831502b64553bbc1fc83dfd1a",
					"0x96050fcd23dc10cbc853f0bf245c315b997707f8261a90f227d90a90d778ee40",
					"0xad7c603ec554f7868050a7935d3df921507ae8c115597686007162562ad30718",
					"0xee514b8a14242ad071a4ab97295a361f4cdc2581dbd37c93fafd7349ff5750fe",
					"0x7426c537dffcbda0904334b6a8673a1f5b684d6efea6c0c5fa429b2e7f382ac2",
					"0xaf27bb731913db8443494a332d1dbf7a18ffc428860e9a0407fc59943a3d74c2",
					"0x07c89d3626c58f02d30f380f22cb82219ca59b21a66c0adcb65d9a47e3bad90a",
					"0x8db855cf39a61456669eb8c4a8e290479cc267cc211b9cc57f7f858f8763d0f2",
					"0x47b08fb7ade309d1a36e79de056d797195520853e9eb0ad8235fe1f6d43b9b3b",
					"0x99730381284e8f1f24ac42668caf4154d25d9c6c5eac562d17d6ceda9e77ae45",
					"0x1591dcab00c70ae3f7f9487a07c9b8058c55b187773e033aa75e2d70a42685cf",
					"0xfb397cbee7da698d1cfac49e51cbf3da1c5a00ce73924518c6d8afcc028cc013",
					"0x698ed1315efe8274c22e037c92027843aa798cdf76e600f33b65902c2cb93a1d",
					"0xf8070bdf7b6a3b1f05661ebf95039d89c52d2374d6f1d417719447bf43cab218",
					"0x02567e6a17657e292ac69fa5b7dd4b0bfc58ed6ea06eb82260357ed9943a8ac5",
					"0x85f92b36b3883956f493535313d0d9ce6fa39940f09181e023a9606487f639f4",
					"0x6d36a147f8ebdecf8b682385dfd094b27ba88d61ac9ae15c711e5cffa331ad53",
					"0x1ff00dc586a2542a6950864781f7619d9598b1d13749b182dcc7b337c3291b8a",
					"0x357b48a437e4471d38265f9ec218f7789bc7f5b48cb332a521089d68234931fa",
					"0xb4615930abef159d26b40e610f391e0ae23d83a73b38de9b4eed760450201a8c",
					"0xc83af1e6edfad50a29c10b57765f0c83f03e102716017318954a259996c8f557",
					"0xb07af7c3a50e02aded496a8d1fc778304d84dfab3909731a3d37e3761bcbb0da",
					"0xe257781733a05fbef7b3e0d30a1e006e9ae46e7b5fe78169e41930b216d4cee7",
					"0xdbd67f3bd3a410ad843e249c74183b919b5c5247df3a84165b3e1231cb9fee57",
					"0x8f70b567966bdd16ef87086662781a6925eb68adf64de3847e3a4a4e63a5f232",
					"0xa0d2d48e03d66d383101a692550e3aa6696df93c4aabdaf9b172e9111023b6f2",
					"0x4f1873f13141a4956e61e655bff3ba35265aef90f2ade7a2a110a8853e4fb9f2",
					"0x7fc95ecfc88d9bb54ece17d37c8578c53d5d02cc4e877498707d736d36ec3ca9",
					"0x5bea01c10781dc3beaa6144ee4a3012562f1da12aa3dc17b5b37f9b5451b3036",
					"0xa27f45ca815a44d980643597c05933ee120e857e227f3791157c33f21490ff8c",
					"0x319b599f63ccdac9663266f4043b3daec468fb6796dc1f34398a9805bce3e91e",
					"0x095cb128c54ec449dc2f41dd9741b05052b57932b792ea065ff34bcca5e2ae86",
					"0x295ed59887ad193b77f73c025a1f8789a92036e64b68a1116a252d0c1ab452cb",
					"0x5df38f5ad197bceb8f3c05730c8650380ce5eef8c2cf7455b9bf66b191d6885a",
					"0x97ae20d33639724dd52f0c417ec71f067c3beddeeb943ef81c588c52bf9463ca",
					"0x81f7a6aba02813d4f5b26a60e62a1b1fe6781c96fa785dec86b6f3399e004445",
					"0x18031439317cd9a272e0012294de7292b515b31116470aa0197d7d5d91e8a3eb",
					"0x16792679167d45d5cea4db19563206f34c40a34f2d22129479ff96105cf5e513",
					"0x9beae3e19cd4398a493d50d6260ac37a131c4b7290c845d7fc3562f3537cec4e",
					"0x7d9eb863b132941e08d050b6110c7b95774191f9c62574700631a75e36c8e44e",
					"0x66875def8b34f114051c4c23b0bfa5e2b20788cec0c4890120b8d0b85280a977",
					"0x95947944768400b764c7a1cedf53afae992654235c7f374f5cb342b4f311eb5f",
					"0xe28c6adc86da666bcda84d3a16199d88f19aa2d1c531c0542c0efa479298a59e",
					"0xeb0fb5789652544465eb7755b8435cd28cde0106ecf7f1f6c61bcff10ef51234",
					"0xa0e42fc09fd0f9330b4c15685834637dc3d52c7296ab4705697356d07cb612d1",
					"0x628a196767fc1784650f7eea81145bf33ba807e69a4779562ab97ab6ee17d7f0",
					"0x40a20b5d0f8557085c1a06f6ea766d360eea976315fdf7d7aebb895b5d11243b"
				],
				"transactionsRoot": "0x67dbb0fe68ee00b62b29ea1bcf31ffbb24aa10e982aca1c8b6df5f95fd79de7c",
				"uncles": []
			}
		}"#.to_vec()),
		sent: true,
		..Default::default()
	})
}

#[test]
fn should_init() {
	let (offchain, _state) = testing::TestOffchainExt::new();
	let mut t = sp_io::TestExternalities::default();
	t.register_extension(OffchainExt::new(offchain));
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
fn add_blocks_2_and_3() {
	let (offchain, _state) = testing::TestOffchainExt::new();
	let mut t = sp_io::TestExternalities::default();
	t.register_extension(OffchainExt::new(offchain));
	t.execute_with(|| {
		let pair = sp_core::sr25519::Pair::from_seed(b"12345678901234567890123456789012");
		// Check on 3 block from here: https://github.com/KyberNetwork/bridge_eos_smart_contracts/blob/master/scripts/jungle/jungle_relay_3.js
		let (blocks, hashes) = get_blocks(&WEB3RS, 2, 4);

		// $ ../ethrelay/ethashproof/cmd/relayer/relayer 3
		let blocks_with_proofs: Vec<BlockWithProofs> = ["./src/data/2.json", "./src/data/3.json"]
			.iter()
			.map(|filename| read_block((&filename).to_string()))
			.collect();

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
			));
		}

		assert_eq!((hashes[1].0), (Example::block_hash(3).unwrap().0));
	})
}

#[test]
fn add_400000_block_only() {
	let (offchain, _state) = testing::TestOffchainExt::new();
	let mut t = sp_io::TestExternalities::default();
	t.register_extension(OffchainExt::new(offchain));
	t.execute_with(|| {
		let pair = sp_core::sr25519::Pair::from_seed(b"12345678901234567890123456789012");

		// Check on 400000 block from this answer: https://ethereum.stackexchange.com/a/67333/3032
		let (blocks, hashes) = get_blocks(&WEB3RS, 400_000, 400_001);

		// $ ../ethrelay/ethashproof/cmd/relayer/relayer 400000
		// digest: 0x3fbea7af642a4e20cd93a945a1f5e23bd72fc5261153e09102cf718980aeff38
		// ethash result: 0x00000000000ca599ebe9913fa00da78a4d1dd2fa154c4fd2aad10ccbca52a2a1
		// Proof length: 24
		// [400000.json]

		let block_with_proof = read_block("./src/data/400000.json".to_string());
		assert_ok!(Example::init(
			Origin::signed(pair.public()),
			400_000 / 30000,
			vec![block_with_proof.merkle_root],
			blocks[0].clone(),
			U256::from(30),
			U256::from(10),
			U256::from(10),
			None,
		));
		assert_eq!((hashes[0].0), Example::block_hash(400_000).unwrap().0);
	});
}

#[test]
fn add_two_blocks_from_8996776() {
	let (offchain, _state) = testing::TestOffchainExt::new();
	let mut t = sp_io::TestExternalities::default();
	t.register_extension(OffchainExt::new(offchain));
	t.execute_with(|| {
		let pair = sp_core::sr25519::Pair::from_seed(b"12345678901234567890123456789012");
		// Check on 8996777 block from this test: https://github.com/sorpaas/rust-ethash/blob/ac6e42bcb7f40ad2a3b89f7400a61f7baf3f0926/src/lib.rs#L318-L326
		let (blocks, hashes) = get_blocks(&WEB3RS, 8_996_776, 8_996_778);

		// $ ../ethrelay/ethashproof/cmd/relayer/relayer 8996777
		let blocks_with_proofs: Vec<BlockWithProofs> =
			["./src/data/8996776.json", "./src/data/8996777.json"]
				.iter()
				.map(|filename| read_block((&filename).to_string()))
				.collect();

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
			));
		}

		assert_eq!(
			(hashes[0].0),
			Example::block_hash(8_996_776).unwrap().0
		);
		assert_eq!(
			(hashes[1].0),
			Example::block_hash(8_996_777).unwrap().0
		);
	});
}

#[test]
fn add_2_blocks_from_400000() {
	let (offchain, _state) = testing::TestOffchainExt::new();
	let mut t = sp_io::TestExternalities::default();
	t.register_extension(OffchainExt::new(offchain));
	t.execute_with(|| {
		let pair = sp_core::sr25519::Pair::from_seed(b"12345678901234567890123456789012");

		// Check on 400000 block from this answer: https://ethereum.stackexchange.com/a/67333/3032
		let (blocks, hashes) = get_blocks(&WEB3RS, 400_000, 400_002);

		// $ ../ethrelay/ethashproof/cmd/relayer/relayer 400001
		// digest: 0x3fbea7af642a4e20cd93a945a1f5e23bd72fc5261153e09102cf718980aeff38
		// ethash result: 0x00000000000ca599ebe9913fa00da78a4d1dd2fa154c4fd2aad10ccbca52a2a1
		// Proof length: 24
		// [400001.json]

		let blocks_with_proofs: Vec<BlockWithProofs> =
			["./src/data/400000.json", "./src/data/400001.json"]
				.iter()
				.map(|filename| read_block((&filename).to_string()))
				.collect();

		assert_ok!(Example::init(
			Origin::signed(pair.public()),
			400_000 / 30000,
			vec![blocks_with_proofs.first().unwrap().merkle_root],
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
			));
		}

		assert_eq!((hashes[0].0), Example::block_hash(400_000).unwrap().0);
		assert_eq!((hashes[1].0), Example::block_hash(400_001).unwrap().0);
	});
}
