#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::too_many_arguments, clippy::large_enum_variant)]

use codec::{Decode, Encode};
use frame_support::{
    debug, decl_error, decl_event, decl_module, decl_storage, ensure,
};
use frame_system::{
    self as system, ensure_signed,
    offchain::{
        AppCrypto, CreateSignedTransaction, SendSignedTransaction,
        SignedPayload, Signer, SigningTypes,
    },
};
use sp_core::crypto::KeyTypeId;
use sp_runtime::offchain::storage::StorageValueRef;
use sp_runtime::{
    offchain::http,
    transaction_validity::{
        InvalidTransaction, TransactionSource, TransactionValidity,
        ValidTransaction,
    },
};
use sp_std::prelude::*;

use ethereum_types::{H128, H256, H512, H64, U256};
use sp_io::hashing::{keccak_256, sha2_256};

mod constants;

mod types;
use types::BlockHeader;

mod prover;

mod blocks_queue;
use blocks_queue::{BlockQueue, Infura};

#[cfg(test)]
mod tests;

pub const UNSIGNED_TXS_PRIORITY: u64 = 100;

/// Defines application identifier for crypto keys of this module.
///
/// Every module that deals with signatures needs to declare its unique
/// identifier for its crypto keys.
/// When offchain worker is signing transactions it's going to request keys of
/// type `KeyTypeId` from the keystore and use the ones it finds to sign the
/// transaction. The keys can be inserted manually via RPC (see
/// `author_insertKey`).
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"eth!");

/// Based on the above `KeyTypeId` we need to generate a pallet-specific crypto
/// type wrappers. We can use from supported crypto kinds (`sr25519`, `ed25519`
/// and `ecdsa`) and augment the types with this pallet-specific identifier.
pub mod crypto {
    use super::KEY_TYPE;
    use sp_core::sr25519::Signature as Sr25519Signature;
    use sp_runtime::{
        app_crypto::{app_crypto, sr25519},
        traits::Verify,
    };
    app_crypto!(sr25519, KEY_TYPE);

    pub struct AuthId;
    impl
        frame_system::offchain::AppCrypto<
            <Sr25519Signature as Verify>::Signer,
            Sr25519Signature,
        > for AuthId
    {
        type GenericPublic = sp_core::sr25519::Public;
        type GenericSignature = sp_core::sr25519::Signature;
        type RuntimeAppPublic = Public;
    }
}

#[derive(Encode, Decode, Clone, PartialEq, Eq)]
pub struct Payload<Public> {
    number: u64,
    public: Public,
}

impl<T: SigningTypes> SignedPayload<T> for Payload<T::Public> {
    fn public(&self) -> T::Public { self.public.clone() }
}

/// This pallet's configuration trait
pub trait Config: system::Config + CreateSignedTransaction<Call<Self>> {
    /// The identifier type for an offchain worker.
    type AuthorityId: AppCrypto<Self::Public, Self::Signature>;

    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as frame_system::Config>::Event>;
    /// The overarching dispatch call type.
    type Call: From<Call<Self>>;
}

/// Minimal information about a header.
#[derive(Clone, Encode, Decode)]
pub struct HeaderInfo {
    pub total_difficulty: U256,
    pub parent_hash: H256,
    pub number: U256,
}

#[derive(Encode, Decode)]
pub struct RpcUrl {
    url: Vec<u8>,
}

decl_error! {
    pub enum Error for Module<T: Config> {
        // Error returned when not sure which ocw function to executed
        UnknownOffchainMux,

        // Error returned when making signed transactions in off-chain worker
        NoLocalAcctForSigning,
        OffchainSignedTxError,

        // Error returned when making unsigned transactions in off-chain worker
        OffchainUnsignedTxError,

        // Error returned when making unsigned transactions with signed payloads in off-chain worker
        OffchainUnsignedTxSignedPayloadError,

        // Error returned when fetching github info
        HttpFetchingError,
    }
}

decl_storage! {
    trait Store for Module<T: Config> as WorkerModule {
        pub ValidateETHash get(fn validate_ethash): bool;
        /// The epoch from which the DAG merkle roots start.
        pub DAGsStartEpoch get(fn dags_start_epoch): Option<u64>;
        /// DAG merkle roots for the next several years.
        pub DAGsMerkleRoots get(fn dags_merkle_roots): Vec<H128>;
        /// Hash of the header that has the highest cumulative difficulty. The current head of the
        /// canonical chain.
        pub BestHeaderHash get(fn best_header_hash): H256;
        /// We store the hashes of the blocks for the past `hashes_gc_threshold` headers.
        /// Events that happen past this threshold cannot be verified by the client.
        /// It is desirable that this number is larger than 7 days worth of headers, which is roughly
        /// 40k Ethereum blocks. So this number should be 40k in production.
        pub HashesGCThreshold get(fn hashes_gc_threshold): Option<U256>;
        /// We store full information about the headers for the past `finalized_gc_threshold` blocks.
        /// This is required to be able to adjust the canonical chain when the fork switch happens.
        /// The commonly used number is 500 blocks, so this number should be 500 in production.
        pub FinalizedGCThreshold get(fn finalized_gc_threshold): Option<U256>;
        /// Number of confirmations that applications can use to consider the transaction safe.
        /// For most use cases 25 should be enough, for super safe cases it should be 500.
        pub NumConfirmations get(fn num_confirmations): Option<U256>;
        /// Hashes of the canonical chain mapped to their numbers. Stores up to `hashes_gc_threshold`
        /// entries.
        /// header number -> header hash
        pub CanonicalHeaderHashes get(fn canonical_header_hashes): map hasher(twox_64_concat) U256 => Option<H256>;
        /// All known header hashes. Stores up to `finalized_gc_threshold`.
        /// header number -> hashes of all headers with this number.
        pub AllHeaderHashes get(fn all_header_hashes): map hasher(twox_64_concat) U256 => Vec<H256>;
        /// Known headers. Stores up to `finalized_gc_threshold`.
        pub Headers get(fn headers): map hasher(twox_64_concat) H256 => Option<BlockHeader>;
        /// Minimal information about the headers, like cumulative difficulty. Stores up to
        /// `finalized_gc_threshold`.
        pub Infos get(fn infos): map hasher(twox_64_concat) H256 => Option<HeaderInfo>;
        /// If set, block header added by trusted signer will skip validation and added by
        /// others will be immediately rejected, used in PoA testnets
        pub TrustedSigner get(fn trusted_signer): Option<T::AccountId>;
        /// RpcUrls set by anyone (intended for offchain workers themselves)
        pub RpcUrls get(fn rpc_urls): map hasher(twox_64_concat) T::AccountId => Option<RpcUrl>;
        /// Verification index for hashimoto scheme
        pub VerificationIndex get(fn verification_index): u32;
    }
}

decl_event!(
    pub enum Event<T>
    where
        AccountId = <T as frame_system::Config>::AccountId,
    {
        NewHeader(u32, AccountId),
    }
);

decl_module! {
    pub struct Module<T: Config> for enum Call where origin: T::Origin {
        // // Errors must be initialized if they are used by the pallet.
        // type Error = Error<T>;

        // Events must be initialized if they are used by the pallet.
        fn deposit_event() = default;

        #[weight = 0]
        fn init(
            origin,
            dags_start_epoch: u64,
            dags_merkle_roots: Vec<H128>,
            first_header: BlockHeader,
            hashes_gc_threshold: U256,
            finalized_gc_threshold: U256,
            num_confirmations: U256,
            trusted_signer: Option<T::AccountId>,
        ) {
            debug::native::info!("Initializing the module ..");
            let _signer = ensure_signed(origin)?;
            ensure!(Self::dags_start_epoch().is_none(), "Already initialized");
            ensure!(Self::hashes_gc_threshold().is_none(), "Already initialized");
            ensure!(Self::finalized_gc_threshold().is_none(), "Already initialized");

            <ValidateETHash>::set(true);
            <DAGsStartEpoch>::set(Some(dags_start_epoch));
            <DAGsMerkleRoots>::set(dags_merkle_roots);
            <HashesGCThreshold>::set(Some(hashes_gc_threshold));
            <FinalizedGCThreshold>::set(Some(finalized_gc_threshold));
            <NumConfirmations>::set(Some(num_confirmations));
            <TrustedSigner<T>>::set(trusted_signer);

            let header_hash = first_header.hash();
            let header_number = first_header.number;

            <BestHeaderHash>::set(header_hash);
            <AllHeaderHashes>::insert(header_number, vec![header_hash]);
            <CanonicalHeaderHashes>::insert(header_number, header_hash);
            <Headers>::insert(header_hash, first_header.clone());
            debug::native::debug!("Added: {:#?}", first_header);
            <Infos>::insert(header_hash, HeaderInfo {
                total_difficulty: first_header.difficulty,
                parent_hash: first_header.parent_hash,
                number: first_header.number,
            });
            debug::native::info!("module init with header block #{}", first_header.number);
            debug::native::info!("module is ready ..");
        }

        /// Add the block header to the client.
        /// `block_header` -- RLP-encoded Ethereum header;
        /// `dag_nodes` -- dag nodes with their merkle proofs.
        #[weight = 0]
        pub fn add_block_header(
            origin,
            block_header: BlockHeader,
            dag_nodes: Vec<types::DoubleNodeWithMerkleProof>,
        ) {
            let _signer = ensure_signed(origin)?;
            let header = block_header;
            if let Some(trusted_signer) = Self::trusted_signer() {
                ensure!(
                    _signer == trusted_signer,
                    "Eth-client is deployed as trust mode, only trusted_signer can add a new header"
                );
            } else {
                debug::native::debug!("trying to find header #{} parent", header.number);
                if let Some(prev) = Self::headers(header.parent_hash) {
                    debug::native::debug!("found parent header: {:?}", prev);
                    debug::native::debug!("starting verification...");
                    let verified = Self::verify_header(header.clone(), prev, dag_nodes);
                    debug::native::debug!("Is header verified? {:?}", verified);
                    ensure!(verified, "The header is not valid");
                    debug::native::debug!("header #{} verified!", header.number);
                } else {
                    debug::native::warn!("{:#?}", header);
                    panic!("parent_hash not found for header #{}", header.number);
                }
            }

            let finalized_gc_threshold = match Self::finalized_gc_threshold() {
                Some(t) => t,
                None => U256::zero(),
            };

            let hashes_gc_threshold = match Self::hashes_gc_threshold() {
                Some(t) => t,
                None => U256::zero(),
            };

            if let Some(best_info) = Self::infos(Self::best_header_hash()) {
                let header_hash = header.hash();
                let header_number = header.number;
                if header_number + finalized_gc_threshold < best_info.number {
                    panic!("Header is too old to have a chance to appear on the canonical chain.");
                }

                if let Some(parent_info) = Self::infos(header.parent_hash) {
                    // Record this header in `all_hashes`.
                    let mut all_hashes = Self::all_header_hashes(header_number);
                    if !all_hashes.is_empty() {
                        ensure!(all_hashes.iter().any(|x| x == &header_hash), "Header is already known.");
                    }
                    all_hashes.push(header_hash);
                    <AllHeaderHashes>::insert(header_number, all_hashes);

                    // Record full information about this header.
                    <Headers>::insert(header_hash, header.clone());
                    debug::native::debug!("Header #{} added", header.number);
                    let info = HeaderInfo {
                        total_difficulty: parent_info.total_difficulty + header.difficulty,
                        parent_hash: header.parent_hash,
                        number: header_number,
                    };
                    <Infos>::insert(header_hash, info.clone());

                    // Check if canonical chain needs to be updated.
                    if info.total_difficulty > best_info.total_difficulty
                        || (info.total_difficulty == best_info.total_difficulty
                            && header.difficulty % 2 == U256::default())
                    {
                        // If the new header has a lower number than the previous header, we need to clean it
                        // going forward.
                        if best_info.number > info.number {
                            let mut num = info.number + U256::one();
                            loop {
                                if num == best_info.number {
                                    break;
                                }

                                <CanonicalHeaderHashes>::remove(num);
                                num += U256::one();
                            }
                        }
                        // Replacing the global best header hash.
                        <BestHeaderHash>::set(header_hash);
                        <CanonicalHeaderHashes>::insert(header_number, header_hash);

                        // Replacing past hashes until we converge into the same parent.
                        // Starting from the parent hash.
                        let mut number = header.number - 1;
                        let mut current_hash = info.parent_hash;
                        loop {
                            if let Some(prev_value) = Self::canonical_header_hashes(number) {
                                <CanonicalHeaderHashes>::insert(number, current_hash);
                                // If the current block hash is 0 (unlikely), or the previous hash matches the
                                // current hash, then the chains converged and we can stop now.
                                if number == U256::zero() || prev_value == current_hash {
                                    break;
                                }
                                // Check if there is an info to get the parent hash
                                if let Some(info) = Self::infos(current_hash) {
                                    current_hash = info.parent_hash;
                                } else {
                                    break;
                                }
                                number -= U256::one();
                            }
                        }
                        if header_number >= hashes_gc_threshold {
                            Self::gc_canonical_chain(header_number - hashes_gc_threshold);
                        }
                        if header_number >= finalized_gc_threshold {
                            Self::gc_headers(header_number - finalized_gc_threshold);
                        }
                    }
                }
            }
        }

        /// Offchain Worker entry point.
        ///
        /// By implementing `fn offchain_worker` within `decl_module!` you declare a new offchain
        /// worker.
        /// This function will be called when the node is fully synced and a new best block is
        /// succesfuly imported.
        /// Note that it's not guaranteed for offchain workers to run on EVERY block, there might
        /// be cases where some blocks are skipped, or for some the worker runs twice (re-orgs),
        /// so the code should be able to handle that.
        /// You can use `Local Storage` API to coordinate runs of the worker.
        fn offchain_worker(block_number: T::BlockNumber) {
            let parent_hash = <system::Module<T>>::block_hash(block_number - 1u32.into());
            debug::native::info!("Current block: {:?} (parent hash: {:?})", block_number, parent_hash);

            let header_queue_info = StorageValueRef::persistent(
                constants::storage_keys::BLOCKS_QUEUE,
            );
            let mut header_queue = match header_queue_info.get::<BlockQueue<Infura>>() {
                Some(queue) => queue.unwrap(),
                None => BlockQueue::with_fetcher(Infura),
            };

            let header = match header_queue.fetch_next_block() {
                Ok(block) => block,
                Err(err) => {
                    debug::native::error!("Block queue error: {:?}", err);
                    return;
                }
            };

            let signer = Signer::<T, T::AuthorityId>::any_account();

            let latest_block_number = Self::last_block_number();
            let call = if header.number > latest_block_number {
                if Self::initialized() {
                    if let Some(proofs) = generate_proofs(&header) {
                        debug::native::info!("Adding header #: {:?}!", header.number);
                        Some(Call::add_block_header(header, proofs))
                    } else {
                        // it sounds that we can't generate the proofs for that header now.
                        // push it back to the front of the queue.
                        header_queue.push_front(header);
                        None
                    }
                } else {
                    debug::native::info!("Initializing with header #: {:?}!", header.number);
                    Some(Call::init(
                        constants::DAG_START_EPOCH,
                        constants::ROOT_HASHES.clone(),
                        header,
                        U256::from(30),
                        U256::from(10),
                        U256::from(10),
                        None,
                    ))
                }
            } else {
                debug::native::info!("Skipping adding #: {:?}, already added!", header.number);
                None
            };
            header_queue_info.set(&header_queue);
            if let Some(c) = call {
                let result = signer.send_signed_transaction(|_acct| c.clone());
                // Display error if the signed tx fails.
                if let Some((acc, res)) = result {
                    if res.is_err() {
                        debug::error!("failure: offchain_signed_tx: tx sent: {:?}", acc.id);
                    }
                    // Transaction is sent successfully
                } else {
                    debug::native::info!("transaction sent but no result");
                }
            }
        }
    }
}

fn generate_proofs(
    header: &BlockHeader,
) -> Option<Vec<types::DoubleNodeWithMerkleProof>> {
    let rlp_header = rlp::encode(header);
    let rlp_hex = hex::encode(rlp_header);
    let payload = types::ProofsPayload { rlp: rlp_hex };
    let body = serde_json::to_vec(&payload);
    let request = match http::Request::post(
        "http://127.0.0.1:3000/proofs",
        body,
    )
    .send()
    {
        Ok(handle) => handle,
        Err(e) => {
            debug::native::error!("http request failed: {:?}", e);
            return None;
        },
    };
    let response = match request.wait() {
        Ok(res) => res,
        Err(e) => {
            debug::native::error!("http error: {:?}", e);
            return None;
        },
    };
    let status_code = response.code;
    if status_code != 200 {
        // server is not ready yet!
        return None;
    }
    let body: Vec<u8> = response.body().collect();
    let raw: types::BlockWithProofsRaw = serde_json::from_slice(&body).unwrap();
    let output = types::BlockWithProofs::from(raw);
    Some(output.to_double_node_with_merkle_proof_vec())
}

fn hex_to_bytes(v: &Vec<char>) -> Result<Vec<u8>, hex::FromHexError> {
    let mut vec = v.clone();

    // remove 0x prefix
    if vec.len() >= 2 && vec[0] == '0' && vec[1] == 'x' {
        vec.drain(0..2);
    }

    // add leading 0 if odd length
    if vec.len() % 2 != 0 {
        vec.insert(0, '0');
    }
    let vec_u8 = vec.iter().map(|c| *c as u8).collect::<Vec<u8>>();
    hex::decode(&vec_u8[..])
}

impl<T: Config> Module<T> {
    pub fn initialized() -> bool { Self::dags_start_epoch().is_some() }

    pub fn dag_merkle_root(epoch: u64) -> H128 {
        match Self::dags_start_epoch() {
            Some(ep) => Self::dags_merkle_roots()[(epoch - ep) as usize],
            None => H128::zero(),
        }
    }

    pub fn last_block_number() -> U256 {
        match Self::infos(Self::best_header_hash()) {
            Some(header) => header.number,
            None => U256::zero(),
        }
    }

    /// Returns the block hash from the canonical chain.
    pub fn block_hash(index: u64) -> Option<H256> {
        Self::canonical_header_hashes(U256::from(index))
    }

    /// Returns all hashes known for that height.
    pub fn known_hashes(index: u64) -> Vec<H256> {
        Self::all_header_hashes(U256::from(index))
    }

    /// Returns block hash if it is safe.
    pub fn block_hash_safe(index: u64) -> Option<H256> {
        let confirmations = match Self::num_confirmations() {
            Some(c) => c,
            None => panic!("No confirmations"),
        };

        match Self::block_hash(index) {
            Some(header_hash) => {
                let last_block_number = Self::last_block_number();
                if U256::from(index) + confirmations > last_block_number {
                    None
                } else {
                    Some(header_hash)
                }
            },
            None => None,
        }
    }

    /// Remove hashes from the canonical chain that are at least as old as the
    /// given header number.
    fn gc_canonical_chain(mut header_number: U256) {
        loop {
            if Self::canonical_header_hashes(header_number).is_some() {
                <CanonicalHeaderHashes>::remove(header_number);
                if header_number == U256::zero() {
                    break;
                } else {
                    header_number -= U256::one();
                }
            } else {
                break;
            }
        }
    }

    /// Remove information about the headers that are at least as old as the
    /// given header number.
    fn gc_headers(mut header_number: U256) {
        loop {
            let all_headers = Self::all_header_hashes(header_number);
            if all_headers.is_empty() {
                break;
            }
            for hash in all_headers {
                <Headers>::remove(hash);
                <Infos>::remove(hash);
            }
            <AllHeaderHashes>::remove(header_number);
            if header_number == U256::zero() {
                break;
            } else {
                header_number -= U256::one();
            }
        }
    }

    // 0x823a4ce867a306eca6ecb523198293e46c7e137f4bf29af83590041afa365f11
    fn truncate_to_h128(arr: H256) -> H128 {
        let mut data = [0u8; 16];
        data.copy_from_slice(&(arr.0)[16..]);
        H128(data)
    }

    fn hash_h128(l: H128, r: H128) -> H128 {
        let mut data = [0u8; 64];
        data[16..32].copy_from_slice(&(l.0));
        data[48..64].copy_from_slice(&(r.0));

        Self::truncate_to_h128(types::sha256(&data).into())
    }

    pub fn apply_merkle_proof(
        index: u64,
        dag_nodes: Vec<H512>,
        proof: Vec<H128>,
    ) -> H128 {
        let mut data = [0u8; 128];

        data[..64].copy_from_slice(&(dag_nodes[0].0));
        data[64..].copy_from_slice(&(dag_nodes[1].0));
        let mut leaf = Self::truncate_to_h128(sha2_256(&data).into());

        for i in 0..proof.len() {
            if (index >> i as u64) % 2 == 0 {
                leaf = Self::hash_h128(leaf, proof[i]);
            } else {
                leaf = Self::hash_h128(proof[i], leaf);
            }
        }
        leaf
    }

    /// Verify PoW of the header.
    fn verify_header(
        header: BlockHeader,
        prev: BlockHeader,
        dag_nodes: Vec<types::DoubleNodeWithMerkleProof>,
    ) -> bool {
        debug::native::debug!("Starting hashimoto merkle...");
        let (mix_hash, result) = Self::hashimoto_merkle(
            header.seal_hash(),
            header.nonce,
            header.number,
            &dag_nodes,
        );
        debug::native::debug!("Finished hashimoto merkle...");
        // See YellowPaper formula (50) in section 4.3.4
        // 1. Simplified difficulty check to conform adjusting difficulty bomb
        // 2. Added condition: header.parent_hash() == prev.hash()
        //

        debug::native::trace!(
            "{:?} -------------- header.difficulty",
            header.difficulty
        );
        let validate_ethash = Self::validate_ethash();
        debug::native::trace!(
            "{:?} -------------- Self::validate_ethash()",
            validate_ethash
        );

        debug::native::trace!(
            "{:?} -------------- (!Self::validate_ethash() || (header.difficulty < header.difficulty * 101 / 100 && header.difficulty > header.difficulty * 99 / 100))",
            (!validate_ethash || (header.difficulty < header.difficulty * 101 / 100 && header.difficulty > header.difficulty * 99 / 100)));
        debug::native::trace!(
            "{:?} -------------- header.gas_used <= header.gas_limit",
            header.gas_used <= header.gas_limit
        );
        debug::native::trace!(
            "{:?} -------------- header.gas_limit < prev.gas_limit * 1025 / 1024",
            header.gas_limit < prev.gas_limit * 1025 / 1024);
        debug::native::trace!(
            "{:?} -------------- header.gas_limit > prev.gas_limit * 1023 / 1024",
            header.gas_limit > prev.gas_limit * 1023 / 1024);
        debug::native::trace!(
            "{:?} -------------- header.gas_limit >= 5000",
            header.gas_limit >= 5000u64
        );
        debug::native::trace!(
            "{:?} -------------- header.timestamp > prev.timestamp",
            header.timestamp > prev.timestamp
        );
        debug::native::trace!(
            "{:?} -------------- header.number == prev.number + 1",
            header.number == prev.number + 1
        );
        debug::native::trace!(
            "{:?} -------------- header.parent_hash == prev.hash",
            header.parent_hash == prev.hash()
        );
        debug::native::trace!("Extra data len: {:?}", header.extra_data.len());
        let boundary = ethash::cross_boundary(header.difficulty);
        debug::native::trace!(
            "{:?} -------------- U256::from(result.as_bytes()) < boundary",
            U256::from_big_endian(result.as_bytes()) < boundary
        );
        debug::native::trace!(
            "{:?} -------------- U256::from_big_endian(result.as_bytes())",
            U256::from(result.as_bytes())
        );
        debug::native::trace!("{:?} -------------- boundary", boundary);

        assert_eq!(mix_hash, header.mix_hash, "mix_hash mismatch");
        U256::from(result.as_bytes()) < boundary
            && (!validate_ethash
                || (header.difficulty < header.difficulty * 101 / 100
                    && header.difficulty > header.difficulty * 99 / 100))
            && header.gas_used <= header.gas_limit
            && header.gas_limit < prev.gas_limit * 1025 / 1024
            && header.gas_limit > prev.gas_limit * 1023 / 1024
            && header.gas_limit >= 5000u64
            && header.timestamp > prev.timestamp
            && header.number == prev.number + 1
            && header.parent_hash == prev.hash()
    }

    /// Verify merkle paths to the DAG nodes.
    fn hashimoto_merkle(
        header_hash: H256,
        nonce: H64,
        header_number: U256,
        nodes: &[types::DoubleNodeWithMerkleProof],
    ) -> (H256, H256) {
        <VerificationIndex>::set(0);
        // Check that we have the expected number of nodes with proofs
        // const MIXHASHES: usize = MIX_BYTES / HASH_BYTES;
        // if nodes.len() != MIXHASHES * ACCESSES / 2 {
        //     return Err(Error::UnexpectedNumberOfNodes);
        // }

        let epoch = header_number.as_u64() / 30_000;
        // Reuse single Merkle root across all the proofs
        let merkle_root = Self::dag_merkle_root(epoch);
        ethash::hashimoto(
            header_hash.0.into(),
            nonce.0.into(),
            ethash::get_full_size(epoch as usize),
            |offset| {
                let idx = Self::verification_index() as usize;
                <VerificationIndex>::set(Self::verification_index() + 1);
                debug::native::trace!(
                    "Starting verification index: {:?}...",
                    idx
                );
                // Each two nodes are packed into single 128 bytes with Merkle
                // proof
                let node = &nodes[idx as usize / 2];
                if idx % 2 == 0 && Self::validate_ethash() {
                    // Divide by 2 to adjust offset for 64-byte words instead of
                    // 128-byte
                    if let Ok(computed_root) =
                        node.apply_merkle_proof((offset / 2) as u64)
                    {
                        assert_eq!(merkle_root, computed_root);
                    }
                };

                // Reverse each 32 bytes for ETHASH compatibility
                let mut data = node.dag_nodes[idx % 2].0;
                data[..32].reverse();
                data[32..].reverse();
                data.into()
            },
        )
    }
}

impl<T: Config> frame_support::unsigned::ValidateUnsigned for Module<T> {
    type Call = Call<T>;

    fn validate_unsigned(
        _source: TransactionSource,
        call: &Self::Call,
    ) -> TransactionValidity {
        let valid_tx = |provide| {
            ValidTransaction::with_tag_prefix("ocw-demo")
                .priority(UNSIGNED_TXS_PRIORITY)
                .and_provides([&provide])
                .longevity(3)
                .propagate(true)
                .build()
        };

        match call {
            Call::init(
                _dags_start_epoch,
                _dags_merkle_roots,
                _first_header,
                _hashes_gc_threshold,
                _finalized_gc_threshold,
                _num_confirmations,
                _trusted_signer,
            ) => valid_tx(b"init".to_vec()),
            Call::add_block_header(_header, _proof) => {
                valid_tx(b"add_block_header".to_vec())
            },
            // -- snip --
            _ => InvalidTransaction::Call.into(),
        }
    }
}
