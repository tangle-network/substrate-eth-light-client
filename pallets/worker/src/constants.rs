/// Holds Storage Keys constants.
/// I don't like using a lot of Raw strings around.
/// this helps avoid misspiling keys.
pub mod storage_keys {
    /// Stores the current epoch.
    pub const STORED_EPOCH: &[u8] = b"light-client-worker::ethash-epoch";
    /// Stores DAG Cache for the current epoch.
    pub const DAG_CACHE: &[u8] = b"light-client-worker::ethash-cache";
    /// Stores the current epoch DAG Dataset iff the `USE_LEFT_DAG_DATASET` is
    /// set to true, otherwise it will contian the DAG Dataset for the next
    /// epoch.
    pub const LEFT_DAG_DATASET: &[u8] = b"light-client-worker::dataset-left";
    /// Stores the current epoch DAG Dataset iff the `USE_LEFT_DAG_DATASET` is
    /// set to false, otherwise it will contian the DAG Dataset for the next
    /// epoch.
    pub const RIGHT_DAG_DATASET: &[u8] = b"light-client-worker::dataset-right";
    /// A Toggle to switch between the diffrent datasets.
    pub const USE_LEFT_DAG_DATASET: &[u8] =
        b"light-client-worker::use-left-dataset";

    /// To Lock the DAG Dataset Generation process.
    pub const DAG_DATASET_LOCK: &[u8] = b"light-client-worker::dataset-lock";
}
