use crate::*;
use codec::{Encode, Decode};
use frame_support::{
	impl_outer_origin, parameter_types,
	weights::Weight,
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
