#![cfg_attr(not(feature = "std"), no_std)]

use sp_runtime::offchain::storage::StorageValueRef;
use sp_std::prelude::*;
use codec::{Encode, Decode};
use frame_system::{
	self as system, ensure_signed,
	offchain::{
		AppCrypto, CreateSignedTransaction, SendSignedTransaction,
		SignedPayload, Signer,
	},
};
use frame_support::{
	debug, decl_module, decl_storage, decl_event, ensure, decl_error,
	traits::Get,
};
use sp_core::crypto::KeyTypeId;
use sp_runtime::{
	transaction_validity::{
		ValidTransaction, TransactionValidity, TransactionSource,
		TransactionPriority,
	},
	offchain::{http},
};
use tiny_keccak::{Keccak, Hasher};
use lite_json::json::JsonValue;
use sp_io::hashing::{sha2_256};
use ethereum_types::{Bloom, H64, H128, H160, U256, H256, H512};
use rlp::RlpStream;
use ethash::{LightDAG, EthereumPatch};
// pub mod eth;

#[cfg(test)]
mod tests;
mod types;
mod prover;

pub type DAG = LightDAG<EthereumPatch>;

/// Defines application identifier for crypto keys of this module.
///
/// Every module that deals with signatures needs to declare its unique identifier for
/// its crypto keys.
/// When offchain worker is signing transactions it's going to request keys of type
/// `KeyTypeId` from the keystore and use the ones it finds to sign the transaction.
/// The keys can be inserted manually via RPC (see `author_insertKey`).
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"eth!");

/// Based on the above `KeyTypeId` we need to generate a pallet-specific crypto type wrappers.
/// We can use from supported crypto kinds (`sr25519`, `ed25519` and `ecdsa`) and augment
/// the types with this pallet-specific identifier.
pub mod crypto {
	use super::KEY_TYPE;
	use sp_runtime::{
		app_crypto::{app_crypto, sr25519},
		traits::Verify,
	};
	use sp_core::sr25519::Signature as Sr25519Signature;
	app_crypto!(sr25519, KEY_TYPE);

	pub struct AuthId;
	impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature> for AuthId {
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}
}

/// This pallet's configuration trait
pub trait Trait: CreateSignedTransaction<Call<Self>> {
	/// The identifier type for an offchain worker.
	type AuthorityId: AppCrypto<Self::Public, Self::Signature>;

	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
	/// The overarching dispatch call type.
	type Call: From<Call<Self>>;

	// Configuration parameters

	/// A grace period after we send transaction.
	///
	/// To avoid sending too many transactions, we only attempt to send one
	/// every `GRACE_PERIOD` blocks. We use Local Storage to coordinate
	/// sending between distinct runs of this offchain worker.
	type GracePeriod: Get<Self::BlockNumber>;

	/// Number of blocks of cooldown after unsigned transaction is included.
	///
	/// This ensures that we only accept unsigned transactions once, every `UnsignedInterval` blocks.
	type UnsignedInterval: Get<Self::BlockNumber>;

	/// A configuration for base priority of unsigned transactions.
	///
	/// This is exposed so that it can be tuned for particular runtime, when
	/// multiple pallets send unsigned transactions.
	type UnsignedPriority: Get<TransactionPriority>;
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

/// Convert across boundary. `f(x) = 2 ^ 256 / x`.
pub fn cross_boundary(val: U256) -> U256 {
	if val <= U256::one() {
		U256::max_value()
	} else {
		((U256::one() << 255) / val) << 1
	}
}

decl_error! {
	pub enum Error for Module<T: Trait> {
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
	trait Store for Module<T: Trait> as WorkerModule {
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
		pub Headers get(fn headers): map hasher(twox_64_concat) H256 => Option<types::BlockHeader>;
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
	pub enum Event<T> where AccountId = <T as frame_system::Trait>::AccountId {
		NewHeader(u32, AccountId),
	}
);

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		// // Errors must be initialized if they are used by the pallet.
		// type Error = Error<T>;

		// Events must be initialized if they are used by the pallet.
		fn deposit_event() = default;

		#[weight = 0]
		fn init(
			origin,
			dags_start_epoch: u64,
			dags_merkle_roots: Vec<H128>,
			first_header: Vec<u8>,
			hashes_gc_threshold: U256,
			finalized_gc_threshold: U256,
			num_confirmations: U256,
			trusted_signer: Option<T::AccountId>,
		) {
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

			let header: types::BlockHeader = rlp::decode(first_header.as_slice()).unwrap();
			let header_hash = header.hash.unwrap();
			let header_number = U256::from(header.number);

			<BestHeaderHash>::set(header_hash.clone());
			<AllHeaderHashes>::insert(header_number, vec![header_hash]);
			<CanonicalHeaderHashes>::insert(header_number, header_hash);
			<Headers>::insert(header_hash, header.clone());
			<Infos>::insert(header_hash, HeaderInfo {
				total_difficulty: header.difficulty,
				parent_hash: header.parent_hash,
				number: U256::from(header.number),
			});
		}

		/// Add the block header to the client.
		/// `block_header` -- RLP-encoded Ethereum header;
		/// `dag_nodes` -- dag nodes with their merkle proofs.
		#[weight = 0]
		pub fn add_block_header(
			origin,
			block_header: Vec<u8>,
		) {
			let _signer = ensure_signed(origin)?;
			let header: types::BlockHeader = rlp::decode(block_header.as_slice()).unwrap();
			if let Some(trusted_signer) = Self::trusted_signer() {
				ensure!(
					_signer == trusted_signer,
					"Eth-client is deployed as trust mode, only trusted_signer can add a new header"
				);
			} else {
				let prev = Self::headers(header.parent_hash)
					.expect("Parent header should be present to add a new header");
				ensure!(
					Self::verify_header(header.clone(), prev.clone()),
					"The header is not valid"
				);
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
				let header_hash = header.hash.unwrap();
				let header_number = U256::from(header.number);
				if header_number + finalized_gc_threshold < best_info.number {
					panic!("Header is too old to have a chance to appear on the canonical chain.");
				}

				if let Some(parent_info) = Self::infos(header.parent_hash) {
					// Record this header in `all_hashes`.
					let mut all_hashes = Self::all_header_hashes(header_number);
					if all_hashes.len() > 0 {
						ensure!(all_hashes.iter().any(|x| x == &header_hash), "Header is already known.");
					}
					all_hashes.push(header_hash);
					<AllHeaderHashes>::insert(header_number, all_hashes);

					// Record full information about this header.
					<Headers>::insert(header_hash, header.clone());
					let info = HeaderInfo {
						total_difficulty: parent_info.total_difficulty + header.difficulty,
						parent_hash: header.parent_hash.clone(),
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
						let mut number = U256::from(header.number) - 1;
						let mut current_hash = info.clone().parent_hash;
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
			// It's a good idea to add logs to your offchain workers.
			// Using the `frame_support::debug` module you have access to the same API exposed by
			// the `log` crate.
			// Note that having logs compiled to WASM may cause the size of the blob to increase
			// significantly. You can use `RuntimeDebug` custom derive to hide details of the types
			// in WASM or use `debug::native` namespace to produce logs only when the worker is
			// running natively.
			debug::native::info!("Hello World from offchain workers!");
			// Since off-chain workers are just part of the runtime code, they have direct access
			// to the storage and other included pallets.
			//
			// We can easily import `frame_system` and retrieve a block hash of the parent block.
			let parent_hash = <system::Module<T>>::block_hash(block_number - 1u32.into());
			debug::debug!("Current block: {:?} (parent hash: {:?})", block_number, parent_hash);
			let header: types::BlockHeader = Self::fetch_block_header().unwrap();

			let mut stream = RlpStream::new();
			Self::rlp_append(header.clone(), &mut stream);
			let rlp_header: Vec<u8> = stream.out();
			let signer = Signer::<T, T::AuthorityId>::any_account();

			// `result` is in the type of `Option<(Account<T>, Result<(), ()>)>`. It is:
			//   - `None`: no account is available for sending transaction
			//   - `Some((account, Ok(())))`: transaction is successfully sent
			//   - `Some((account, Err(())))`: error occured when sending the transaction
			let result = signer.send_signed_transaction(|_acct|
				// This is the on-chain function
				Call::add_block_header(rlp_header.clone())
			);

			// Display error if the signed tx fails.
			if let Some((acc, res)) = result {
				if res.is_err() {
					debug::error!("failure: offchain_signed_tx: tx sent: {:?}", acc.id);
					// return Err(<Error<T>>::OffchainSignedTxError);
				}
				// Transaction is sent successfully
				// return Ok(());
			}

			// // The case of `None`: no account is available for sending
			// debug::error!("No local account available");
			// Err(<Error<T>>::NoLocalAcctForSigning)
		}
	}
}

fn hex_to_bytes(v: &[char]) -> Result<Vec<u8>, hex::FromHexError> {
	let v_no_prefix = if v.len() >= 2 && v[0] == '0' && v[1] == 'x' {
		&v[2..]
	} else {
		&v[..]
	};
	let v_u8 = v_no_prefix.iter().map(|c| *c as u8).collect::<Vec<u8>>();
	hex::decode(&v_u8[..])
}

impl<T: Trait> Module<T> {
	pub fn initialized() -> bool {
		Self::dags_start_epoch().is_some()
	}

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

	/// Remove hashes from the canonical chain that are at least as old as the given header number.
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

	/// Remove information about the headers that are at least as old as the given header number.
	fn gc_headers(mut header_number: U256) {
		loop {
			let all_headers = Self::all_header_hashes(header_number);
			if all_headers.is_empty() { break; }
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
	//0x823a4ce867a306eca6ecb523198293e46c7e137f4bf29af83590041afa365f11
	fn truncate_to_h128(arr: H256) -> H128 {
		let mut data = [0u8; 16];
		data.copy_from_slice(&(arr.0)[16..]);
		H128(data.into())
	}

	fn hash_h128(l: H128, r: H128) -> H128 {
		let mut data = [0u8; 64];
		data[16..32].copy_from_slice(&(l.0));
		data[48..64].copy_from_slice(&(r.0));

		Self::truncate_to_h128(types::sha256(&data).into())
	}

	pub fn apply_merkle_proof(index: u64, dag_nodes: Vec<H512>, proof: Vec<H128>) -> H128 {
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
		header: types::BlockHeader,
		prev: types::BlockHeader,
	) -> bool {
		let epoch = (header.number as usize / 30000) as u64;
		let epoch_info = StorageValueRef::persistent(b"light-client-worker::ethash-epoch");
		let stored_epoch = match epoch_info.get::<u64>() {
			Some(e) => e.unwrap(),
			None => epoch,
		};

		let mut d: Option<DAG> = None;
		let cache_info = StorageValueRef::persistent(b"light-client-worker::ethash-cache");
		// fetch cache or generate if it doesn't exist
		let mut cache = match cache_info.get::<Vec<u8>>() {
			Some(c) => c.unwrap(),
			None => {
				debug::native::info!("Starting cache generation!");
				let l_dag = DAG::new(header.number.into());
				debug::native::info!("Finished cache generation!");
				l_dag.cache
			}
		};

		// when the epoch changes, we need to regenerate the cache
		// otherwise we repopulate the light DAG with existing cache.
		if epoch > stored_epoch {
			debug::native::info!("Restarting cache generation due to epoch change!");
			epoch_info.set(&epoch);
			// regeneate cache and store the dag
			let l_dag = DAG::new(header.number.into());
			cache = l_dag.cache.clone();
			d = Some(l_dag);
		}

		let dag = match d {
			Some(light_dag) => light_dag,
			None => DAG::from_cache(cache, header.number.into()),
		};

		let (_mix_hash, result) = dag.hashimoto(header.partial_hash.unwrap().0.into(), header.nonce.0.into());
		let five_thousand = match U256::from_dec_str("5000") {
			Ok(r) => r,
			Err(_) => panic!("Invalid decimal conversion"),
		};
		//
		// See YellowPaper formula (50) in section 4.3.4
		// 1. Simplified difficulty check to conform adjusting difficulty bomb
		// 2. Added condition: header.parent_hash() == prev.hash()
		//
		U256::from_big_endian(&result.0) < cross_boundary(header.difficulty)
			&& (!Self::validate_ethash()
				|| (header.difficulty < header.difficulty * 101 / 100
					&& header.difficulty > header.difficulty * 99 / 100))
			&& header.gas_used <= header.gas_limit
			&& header.gas_limit < prev.gas_limit * 1025 / 1024
			&& header.gas_limit > prev.gas_limit * 1023 / 1024
			&& header.gas_limit >= five_thousand
			&& header.timestamp > prev.timestamp
			&& header.number == prev.number + 1
			&& header.parent_hash == prev.hash.unwrap()
			&& header.extra_data.len() <= 32
	}

	fn fetch_block_header() -> Result<types::BlockHeader, http::Error> {
		// Make a post request to an eth chain
		let body = br#"{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["latest", false],"id":1}"#;
		let request: http::Request = http::Request::post(
			"https://mainnet.infura.io/v3/b5f870422ee5454fb11937e947154cd2",
			[ &body[..] ].to_vec(),
		);
		let pending = request.send().unwrap();

		// wait indefinitely for response (TODO: timeout)
		let mut response = pending.wait().unwrap();
		let headers = response.headers().into_iter();
		assert_eq!(headers.current(), None);

		// and collect the body
		let body = response.body().collect::<Vec<u8>>();
		let body_str = sp_std::str::from_utf8(&body).map_err(|_| {
			debug::warn!("No UTF8 body");
			http::Error::Unknown
		}).unwrap();
		// decode JSON into object
		debug::native::info!("{:#?}", body_str);
		let val: JsonValue = lite_json::parse_json(&body_str).unwrap();
		let header: types::BlockHeader = Self::json_to_rlp(val);
		Ok(header)
	}

	pub fn rlp_append(header: types::BlockHeader, stream: &mut RlpStream) {
		stream.begin_list(15);
		stream.append(&header.parent_hash);
		stream.append(&header.uncles_hash);
		stream.append(&header.author);
		stream.append(&header.state_root);
		stream.append(&header.transactions_root);
		stream.append(&header.receipts_root);
		stream.append(&header.log_bloom);
		stream.append(&header.difficulty);
		stream.append(&header.number);
		stream.append(&header.gas_limit);
		stream.append(&header.gas_used);
		stream.append(&header.timestamp);
		stream.append(&header.extra_data);
		stream.append(&header.mix_hash);
		stream.append(&header.nonce);
	}

	pub fn json_to_rlp(json: JsonValue) -> types::BlockHeader {
		// get { "result": VAL }
		let block: Option<Vec<(Vec<char>, JsonValue)>> = match json {
			JsonValue::Object(obj) => {
				obj.into_iter()
					.find(|(k, _)| k.iter().map(|c| *c as u8).collect::<Vec<u8>>() == b"result".to_vec())
					.and_then(|v| {
						match v.1 {
							JsonValue::Object(block) => Some(block),
							_ => None,
						}
					})
			},
			_ => None
		};


		
		debug::native::info!("Decoding difficulty!");
		let decoded_difficulty_hex = Self::extract_property_from_block(block.clone(), b"difficulty".to_vec());
		let difficulty = U256::from_big_endian(&decoded_difficulty_hex[..]);

		debug::native::info!("Decoding extra_data!");
		let decoded_extra_data_hex = Self::extract_property_from_block(block.clone(), b"extraData".to_vec());

		debug::native::info!("Decoding gas_limit!");
		let decoded_gas_limit_hex = Self::extract_property_from_block(block.clone(), b"gasLimit".to_vec());
		let gas_limit = U256::from_big_endian(&decoded_gas_limit_hex[..]);

		debug::native::info!("Decoding gas_used!");
		let decoded_gas_used_hex = Self::extract_property_from_block(block.clone(), b"gasUsed".to_vec());
		let gas_used = U256::from_big_endian(&decoded_gas_used_hex[..]);

		debug::native::info!("Decoding hash!");
		let decoded_hash_hex = Self::extract_property_from_block(block.clone(), b"hash".to_vec());
		let mut temp_hash = [0; 32];
		for i in 0..decoded_hash_hex.len() {
			temp_hash[i] = decoded_hash_hex[i];
		}
		let hash = H256::from(temp_hash);

		debug::native::info!("Decoding logs_bloom!");
		let decoded_logs_bloom_hex = Self::extract_property_from_block(block.clone(), b"logsBloom".to_vec());
		let mut temp_logs_bloom = [0; 256];
		for i in 0..decoded_logs_bloom_hex.len() {
			temp_logs_bloom[i] = decoded_logs_bloom_hex[i];
		}
		let logs_bloom = Bloom::from(temp_logs_bloom);

		debug::native::info!("Decoding miner!");
		let decoded_miner_hex = Self::extract_property_from_block(block.clone(), b"miner".to_vec());
		let mut temp_miner = [0; 20];
		for i in 0..decoded_miner_hex.len() {
			temp_miner[i] = decoded_miner_hex[i];
		}
		let miner = H160::from(temp_miner);

		debug::native::info!("Decoding mix_hash!");
		let decoded_mix_hash_hex = Self::extract_property_from_block(block.clone(), b"mixHash".to_vec());
		let mut temp_mix_hash = [0; 32];
		for i in 0..decoded_mix_hash_hex.len() {
			temp_mix_hash[i] = decoded_mix_hash_hex[i];
		}
		let mix_hash = H256::from(temp_mix_hash);

		debug::native::info!("Decoding nonce!");
		let decoded_nonce_hex = Self::extract_property_from_block(block.clone(), b"nonce".to_vec());
		let mut temp_nonce = [0; 8];
		for i in 0..decoded_nonce_hex.len() {
			temp_nonce[i] = decoded_nonce_hex[i];
		}
		let nonce = H64::from(temp_nonce);

		debug::native::info!("Decoding number!");
		let decoded_number_hex = Self::extract_property_from_block(block.clone(), b"number".to_vec());
		let number = U256::from_big_endian(&decoded_number_hex[..]).as_u64();

		debug::native::info!("Decoding parent_hash!");
		let decoded_parent_hash_hex = Self::extract_property_from_block(block.clone(), b"parentHash".to_vec());
		let mut temp_parent_hash = [0; 32];
		for i in 0..decoded_parent_hash_hex.len() {
			temp_parent_hash[i] = decoded_parent_hash_hex[i];
		}
		let parent_hash = H256::from(temp_parent_hash);

		debug::native::info!("Decoding receipts_root!");
		let decoded_receipts_root_hex = Self::extract_property_from_block(block.clone(), b"receiptsRoot".to_vec());
		let mut temp_receipts_root = [0; 32];
		for i in 0..decoded_receipts_root_hex.len() {
			temp_receipts_root[i] = decoded_receipts_root_hex[i];
		}
		let receipts_root = H256::from(temp_receipts_root);

		debug::native::info!("Decoding sha3_uncles!");
		let decoded_sha3_uncles_hex = Self::extract_property_from_block(block.clone(), b"sha3Uncles".to_vec());
		let mut temp_sha3_uncles = [0; 32];
		for i in 0..decoded_sha3_uncles_hex.len() {
			temp_sha3_uncles[i] = decoded_sha3_uncles_hex[i];
		}
		let uncles_hash = H256::from(temp_sha3_uncles);

		debug::native::info!("Decoding state_root!");
		let decoded_state_root_hex = Self::extract_property_from_block(block.clone(), b"stateRoot".to_vec());
		let mut temp_state_root = [0; 32];
		for i in 0..decoded_state_root_hex.len() {
			temp_state_root[i] = decoded_state_root_hex[i];
		}
		let state_root = H256::from(temp_state_root);

		debug::native::info!("Decoding transactions_root!");
		let decoded_transactions_root_hex = Self::extract_property_from_block(block.clone(), b"transactionsRoot".to_vec());
		let mut temp_transactions_root = [0; 32];
		for i in 0..decoded_transactions_root_hex.len() {
			temp_transactions_root[i] = decoded_transactions_root_hex[i];
		}
		let transactions_root = H256::from(temp_transactions_root);

		debug::native::info!("Decoding timestamp!");
		let decoded_timestamp_hex = Self::extract_property_from_block(block.clone(), b"timestamp".to_vec());
		let timestamp = U256::from_big_endian(&decoded_timestamp_hex[..]).as_u64();


		let block = types::BlockHeader {
			parent_hash: parent_hash,
			uncles_hash: uncles_hash,
			author: miner,
			state_root: state_root,
			transactions_root: transactions_root,
			receipts_root: receipts_root,
			log_bloom: logs_bloom,
			difficulty: difficulty,
			number: number,
			gas_limit: gas_limit,
			gas_used: gas_used,
			timestamp: timestamp,
			extra_data: decoded_extra_data_hex,
			mix_hash: mix_hash,
			nonce: nonce,
			hash: Some(hash),
			partial_hash: None,
		};

		block
	}

	pub fn extract_property_from_block(block: Option<Vec<(Vec<char>, JsonValue)>>, property: Vec<u8>) -> Vec<u8> {
		let extracted_hex: Vec<char> = block.unwrap().into_iter()
			.find(|(k, _)| k.iter().map(|c| *c as u8).collect::<Vec<u8>>() == property)
			.and_then(|v| match v.1 {
				JsonValue::String(n) => Some(n),
				_ => None,
			})
			.unwrap();
		let decoded_hex = hex_to_bytes(&extracted_hex[..]).unwrap();
		decoded_hex
	}
}

#[allow(deprecated)] // ValidateUnsigned
impl<T: Trait> frame_support::unsigned::ValidateUnsigned for Module<T> {
	type Call = Call<T>;

	/// Validate unsigned call to this module.
	///
	/// By default unsigned transactions are disallowed, but implementing the validator
	/// here we make sure that some particular calls (the ones produced by offchain worker)
	/// are being whitelisted and marked as valid.
	fn validate_unsigned(
		_source: TransactionSource,
		_call: &Self::Call,
	) -> TransactionValidity {
		ValidTransaction::with_tag_prefix("ExampleOffchainWorker")
		// We set base priority to 2**20 and hope it's included before any other
		// transactions in the pool. Next we tweak the priority depending on how much
		// it differs from the current average. (the more it differs the more priority it
		// has).
		.priority(T::UnsignedPriority::get())
		// The transaction is only valid for next 5 blocks. After that it's
		// going to be revalidated by the pool.
		.longevity(5)
		// It's fine to propagate that transaction to other peers, which means it can be
		// created even by nodes that don't produce blocks.
		// Note that sometimes it's better to keep it for yourself (if you are the block
		// producer), since for instance in some schemes others may copy your solution and
		// claim a reward.
		.propagate(true)
		.build()
	}
}