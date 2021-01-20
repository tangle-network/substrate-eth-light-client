use ethereum_types::H128;
use sp_std::prelude::*;

/// Holds Storage Keys constants.
/// I don't like using a lot of Raw strings around.
/// this helps avoid misspiling keys.
pub mod storage_keys {
    pub const BLOCKS_QUEUE: &[u8] = b"light-client-worker::blocks_queue";
}

// AUTO GENERATED using `python ./scripts/roots.py <ROOTS_FILE_TXT>`
pub const DAG_START_EPOCH: u64 = 389;
lazy_static::lazy_static! {
    pub static ref ROOT_HASHES: Vec<H128> = vec![
        "0xbeaa602d3dd5708dca1901b6615c1205", // 389
        "0x176878a13808017e01639d3c249e4360", // 390
    ]
    .into_iter()
    .map(|v| &v[2..])
    .map(hex::decode)
    .flatten()
    .map(|b| H128::from_slice(&b))
    .collect();
}
