use crate::*;
use codec::{Decode, Encode};
use frame_support::{
    assert_ok, impl_outer_origin, parameter_types, weights::Weight,
};
use sp_core::{
    offchain::{testing, OffchainExt},
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
use web3::futures::Future;
use web3::types::Block;

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
    pub BlockWeights: frame_system::limits::BlockWeights =
        frame_system::limits::BlockWeights::simple_max(1024);
    pub const MinimumPeriod: u64 = 1;
}

impl frame_system::Config for Test {
    type AccountData = ();
    type AccountId = sp_core::sr25519::Public;
    type BaseCallFilter = ();
    type BlockHashCount = BlockHashCount;
    type BlockLength = ();
    type BlockNumber = u64;
    type BlockWeights = ();
    type Call = ();
    type DbWeight = ();
    type Event = ();
    type Hash = H256;
    type Hashing = ::sp_runtime::traits::BlakeTwo256;
    type Header = Header;
    type Index = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type OnKilledAccount = ();
    type OnNewAccount = ();
    type Origin = Origin;
    type PalletInfo = ();
    type SystemWeightInfo = ();
    type Version = ();
}

type Extrinsic = TestXt<Call<Test>, ()>;
type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

impl frame_system::offchain::SigningTypes for Test {
    type Public = <Signature as Verify>::Signer;
    type Signature = Signature;
}

impl<LocalCall> frame_system::offchain::SendTransactionTypes<LocalCall> for Test
where
    Call<Test>: From<LocalCall>,
{
    type Extrinsic = Extrinsic;
    type OverarchingCall = Call<Test>;
}

impl<LocalCall> frame_system::offchain::CreateSignedTransaction<LocalCall>
    for Test
where
    Call<Test>: From<LocalCall>,
{
    fn create_transaction<
        C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>,
    >(
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

impl Config for Test {
    type AuthorityId = crypto::AuthId;
    type Call = Call<Test>;
    type Event = ();
}

type Example = Module<Test>;

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
    serde_json::from_reader(
        std::fs::File::open(std::path::Path::new(&filename)).unwrap(),
    )
    .unwrap()
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
        assert_eq!(number, 11193406);
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
fn should_init() {
    let (offchain, _state) = testing::TestOffchainExt::new();
    let mut t = sp_io::TestExternalities::default();
    t.register_extension(OffchainExt::new(offchain));
    t.execute_with(|| {
        let (blocks, _) = get_blocks(&WEB3RS, 400_000, 400_001);
        let pair = sp_core::sr25519::Pair::from_seed(
            b"12345678901234567890123456789012",
        );
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
        let pair = sp_core::sr25519::Pair::from_seed(
            b"12345678901234567890123456789012",
        );
        // Check on 3 block from here: https://github.com/KyberNetwork/bridge_eos_smart_contracts/blob/master/scripts/jungle/jungle_relay_3.js
        let (blocks, hashes) = get_blocks(&WEB3RS, 2, 4);

        // $ ../ethrelay/ethashproof/cmd/relayer/relayer 3
        let blocks_with_proofs: Vec<BlockWithProofs> =
            ["./data/2.json", "./data/3.json"]
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

        let l_dag = DAG::new(2.into());

        for (block, _proof) in blocks
            .into_iter()
            .zip(blocks_with_proofs.into_iter())
            .skip(1)
        {
            assert_ok!(Example::add_block_header(
                Origin::signed(pair.public()),
                block,
                _proof.to_double_node_with_merkle_proof_vec(),
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
        let pair = sp_core::sr25519::Pair::from_seed(
            b"12345678901234567890123456789012",
        );

        // Check on 400000 block from this answer: https://ethereum.stackexchange.com/a/67333/3032
        let (blocks, hashes) = get_blocks(&WEB3RS, 400_000, 400_001);

        // $ ../ethrelay/ethashproof/cmd/relayer/relayer 400000
        // digest: 0x3fbea7af642a4e20cd93a945a1f5e23bd72fc5261153e09102cf718980aeff38
        // ethash result:
        // 0x00000000000ca599ebe9913fa00da78a4d1dd2fa154c4fd2aad10ccbca52a2a1
        // Proof length: 24
        // [400000.json]

        let block_with_proof = read_block("./data/400000.json".to_string());
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
        let pair = sp_core::sr25519::Pair::from_seed(
            b"12345678901234567890123456789012",
        );
        // Check on 8996777 block from this test: https://github.com/sorpaas/rust-ethash/blob/ac6e42bcb7f40ad2a3b89f7400a61f7baf3f0926/src/lib.rs#L318-L326
        let (blocks, hashes) = get_blocks(&WEB3RS, 8_996_776, 8_996_778);

        // $ ../ethrelay/ethashproof/cmd/relayer/relayer 8996777
        let blocks_with_proofs: Vec<BlockWithProofs> =
            ["./data/8996776.json", "./data/8996777.json"]
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

        let l_dag = DAG::new(8_996_776.into());

        for (block, _proof) in blocks
            .into_iter()
            .zip(blocks_with_proofs.into_iter())
            .skip(1)
        {
            assert_ok!(Example::add_block_header(
                Origin::signed(pair.public()),
                block,
                _proof.to_double_node_with_merkle_proof_vec(),
            ));
        }

        assert_eq!((hashes[0].0), Example::block_hash(8_996_776).unwrap().0);
        assert_eq!((hashes[1].0), Example::block_hash(8_996_777).unwrap().0);
    });
}

#[test]
fn add_2_blocks_from_400000() {
    let (offchain, _state) = testing::TestOffchainExt::new();
    let mut t = sp_io::TestExternalities::default();
    t.register_extension(OffchainExt::new(offchain));
    t.execute_with(|| {
        let pair = sp_core::sr25519::Pair::from_seed(
            b"12345678901234567890123456789012",
        );

        // Check on 400000 block from this answer: https://ethereum.stackexchange.com/a/67333/3032
        let (blocks, hashes) = get_blocks(&WEB3RS, 400_000, 400_002);

        // $ ../ethrelay/ethashproof/cmd/relayer/relayer 400001
        // digest: 0x3fbea7af642a4e20cd93a945a1f5e23bd72fc5261153e09102cf718980aeff38
        // ethash result:
        // 0x00000000000ca599ebe9913fa00da78a4d1dd2fa154c4fd2aad10ccbca52a2a1
        // Proof length: 24
        // [400001.json]

        let blocks_with_proofs: Vec<BlockWithProofs> =
            ["./data/400000.json", "./data/400001.json"]
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

        let l_dag = DAG::new(400_000.into());

        for (block, _proof) in blocks
            .into_iter()
            .zip(blocks_with_proofs.into_iter())
            .skip(1)
        {
            assert_ok!(Example::add_block_header(
                Origin::signed(pair.public()),
                block,
                _proof.to_double_node_with_merkle_proof_vec(),
            ));
        }

        assert_eq!((hashes[0].0), Example::block_hash(400_000).unwrap().0);
        assert_eq!((hashes[1].0), Example::block_hash(400_001).unwrap().0);
    });
}

#[test]
fn should_check_for_generate_dataset() {
    let block_number = U256::from(2);
    let stored_epoch = block_number.as_u64() / 30_000;
    assert_eq!(should_generate_dataset(block_number, stored_epoch), false);

    let block_number = U256::from(400_000);
    let stored_epoch = 0; // last_block_number 30_000

    assert_eq!(should_generate_dataset(block_number, stored_epoch), true);
}
