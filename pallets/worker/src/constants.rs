/// Holds Storage Keys constants.
/// I don't like using a lot of Raw strings around.
/// this helps avoid misspiling keys.
pub mod storage_keys {
    pub const BLOCKS_QUEUE: &[u8] = b"light-client-worker::blocks_queue";
}
