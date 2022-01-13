use core::{cmp, fmt, ops};

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::format;

use codec::{Decode, Encode};
use frame_support::debug;
use sp_runtime::offchain::http;
use sp_std::collections::vec_deque::VecDeque;
use sp_std::prelude::*;

use crate::types::{BlockHeader, InfuraBlockHeader};

pub trait BlockFetcher: Decode + Encode {
    type Error: fmt::Debug;

    fn fetch_latest(&self) -> Result<BlockHeader, Self::Error>;
    fn fetch_one(&self, block_number: u64) -> Result<BlockHeader, Self::Error>;
    fn fetch_many(
        &self,
        block_numbers: ops::RangeInclusive<u64>,
    ) -> Result<Vec<BlockHeader>, Self::Error>;
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct BlockQueue<F: BlockFetcher> {
    inner: VecDeque<BlockHeader>,
    last_seen_block_number: Option<u64>,
    block_fetcher: F,
}

impl<F: BlockFetcher> BlockQueue<F> {
    pub fn with_fetcher(block_fetcher: F) -> Self {
        Self {
            inner: VecDeque::new(),
            last_seen_block_number: None,
            block_fetcher,
        }
    }

    pub fn is_empty(&self) -> bool { self.inner.is_empty() }

    pub fn len(&self) -> usize { self.inner.len() }

    /// fetch next block from the queue and add new one to it from the
    /// `BlockFetcher`. if this the a new queue, it will fetch the latest
    /// header.
    pub fn fetch_next_block(&mut self) -> Result<BlockHeader, F::Error> {
        // debug::native::debug!("Fetching next block...");
        if let Some(last_seen_block_number) = &self.last_seen_block_number {
            // debug::native::debug!(
            //     "last seen block number is: {}",
            //     last_seen_block_number
            // );
            let next = self.block_fetcher.fetch_one(last_seen_block_number + 1);
            match next {
                Ok(block) => {
                    // debug::native::debug!(
                    //     "got block #{} adding to the queue.",
                    //     block.number
                    // );
                    self.last_seen_block_number = Some(block.number.as_u64());
                    self.inner.push_back(block);
                    let b = self
                        .inner
                        .pop_front()
                        .expect("queue have at least one header");
                    // debug::native::debug!(
                    //     "got block #{} from the queue",
                    //     b.number
                    // );
                    Ok(b)
                },
                Err(e) => {
                    // debug::native::warn!(
                    //     "got error while fetching #{}",
                    //     last_seen_block_number
                    // );
                    if let Some(front) = self.inner.pop_front() {
                        // debug::native::debug!(
                        //     "but we still have #{} on the queue, reading it.",
                        //     front.number
                        // );
                        Ok(front)
                    } else {
                        // debug::native::warn!("oh no, an empty queue!!!!");
                        Err(e)
                    }
                },
            }
        } else {
            // debug::native::info!("new queue, fetching latest block..");
            let latest = self.block_fetcher.fetch_latest()?;
            // debug::native::info!("got latest block: #{}", latest.number);
            self.last_seen_block_number = Some(latest.number.as_u64());
            Ok(latest)
        }
    }

    /// sync the current queue and fill up any missing headers.
    /// it simply fetch the latest block and compare it with last seen block
    /// number and then fetchs up to `limit` blocks from the `BlockFetcher`.
    ///
    /// returns back how many blocks got queued.
    pub fn sync_missing_blocks(
        &mut self,
        limit: usize,
    ) -> Result<u64, F::Error> {
        let maybe_lsbn = self.last_seen_block_number.as_mut();
        if let Some(last_seen_block_number) = maybe_lsbn {
            let latest = self.block_fetcher.fetch_latest()?;
            if *last_seen_block_number == latest.number.as_u64() {
                // no work is needed, we are in the latest block.
                return Ok(0);
            }
            let from = *last_seen_block_number + 1;
            let to = cmp::min(from + limit as u64, latest.number.as_u64());
            let blocks = self.block_fetcher.fetch_many(from..=to)?;

            for missing in blocks {
                *last_seen_block_number = missing.number.as_u64();
                self.inner.push_back(missing);
            }
            Ok(to - from)
        } else {
            // we know here that our queue is new and empty so fetch latest
            // block.
            let latest = self.block_fetcher.fetch_latest()?;
            self.last_seen_block_number = Some(latest.number.as_u64());
            self.inner.push_back(latest);
            Ok(1)
        }
    }

    /// push a block header to the queue again.
    pub fn push_front(&mut self, block_header: BlockHeader) {
        self.inner.push_front(block_header);
    }

    /// get a block header from the queue,
    /// without fetching any new blocks.
    pub fn pop_front(&mut self) -> Option<BlockHeader> {
        self.inner.pop_front()
    }
}

#[derive(Debug, Encode, Decode)]
pub struct Infura;

impl Infura {
    fn fetch_block(block: &str) -> Result<BlockHeader, http::Error> {
        // debug::native::debug!("INFURA: getBlockByNumber({})", block);
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getBlockByNumber",
            "params": [block, false],
            "id": 1,
        });
        let payload = serde_json::to_vec(&body);
        let url =
            "https://mainnet.infura.io/v3/b5f870422ee5454fb11937e947154cd2";
        let handle = http::Request::post(url, payload)
            .send()
            .map_err(|_| http::Error::Unknown)?;
        let response = handle.wait()?;
        let body: Vec<u8> = response.body().collect();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let result = json["result"].clone();
        if result.is_null() {
            // debug::native::warn!("INFURA: {}", json);
            return Err(http::Error::IoError);
        }
        let block: InfuraBlockHeader = serde_json::from_value(result).unwrap();
        Ok(block.into())
    }
}

impl BlockFetcher for Infura {
    type Error = http::Error;

    fn fetch_latest(&self) -> Result<BlockHeader, Self::Error> {
        Self::fetch_block("latest")
    }

    fn fetch_one(&self, block_number: u64) -> Result<BlockHeader, Self::Error> {
        let block_number = block_number as u32;
        let mut hexed = hex::encode(block_number.to_be_bytes());
        // remove leading zeros.
        while hexed.get(0..1) == Some("0") {
            hexed.remove(0);
        }
        let number = format!("0x{}", hexed);
        Self::fetch_block(&number)
    }

    fn fetch_many(
        &self,
        block_numbers: ops::RangeInclusive<u64>,
    ) -> Result<Vec<BlockHeader>, Self::Error> {
        let mut blocks = Vec::new();
        for n in block_numbers {
            let block = self.fetch_one(n)?;
            blocks.push(block);
        }
        Ok(blocks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethereum_types::*;

    #[derive(Debug, Clone, Encode, Decode)]
    struct MockedInfura(u64);

    fn mock_header_with(number: u64) -> BlockHeader {
        BlockHeader {
            parent_hash: H256::random(),
            uncles_hash: H256::random(),
            author: Address::random(),
            state_root: H256::random(),
            transactions_root: H256::random(),
            receipts_root: H256::random(),
            log_bloom: Bloom::random(),
            difficulty: U256::MAX,
            number: U256::from(number),
            gas_limit: 1000,
            gas_used: 1000,
            timestamp: 1610749011,
            extra_data: b"Mocked data for tests".to_vec(),
            mix_hash: H256::random(),
            nonce: H64::random(),
        }
    }

    impl BlockFetcher for MockedInfura {
        type Error = http::Error;

        fn fetch_latest(&self) -> Result<BlockHeader, Self::Error> {
            Ok(mock_header_with(self.0))
        }

        fn fetch_one(
            &self,
            block_number: u64,
        ) -> Result<BlockHeader, Self::Error> {
            Ok(mock_header_with(block_number))
        }

        fn fetch_many(
            &self,
            block_numbers: ops::RangeInclusive<u64>,
        ) -> Result<Vec<BlockHeader>, Self::Error> {
            let from = *block_numbers.start();
            let to = cmp::min(self.0, *block_numbers.end());
            Ok((from..=to).into_iter().map(mock_header_with).collect())
        }
    }

    impl BlockQueue<MockedInfura> {
        pub fn replace_fetcher(&mut self, f: MockedInfura) -> MockedInfura {
            std::mem::replace(&mut self.block_fetcher, f)
        }
    }

    #[test]
    fn empty() {
        let queue = BlockQueue::with_fetcher(MockedInfura(7));
        assert_eq!(queue.is_empty(), true);
    }

    #[test]
    fn fetch_next_block() {
        let mut queue = BlockQueue::with_fetcher(MockedInfura(7));
        assert_eq!(queue.is_empty(), true);

        let block = queue.fetch_next_block().unwrap();
        assert_eq!(block.number.as_u64(), 7);
        let block = queue.fetch_next_block().unwrap();
        assert_eq!(block.number.as_u64(), 8);
        let block = queue.fetch_next_block().unwrap();
        assert_eq!(block.number.as_u64(), 9);
    }

    #[test]
    fn fetch_next_block_with_push_back() {
        let mut queue = BlockQueue::with_fetcher(MockedInfura(7));
        assert_eq!(queue.is_empty(), true);

        let block = queue.fetch_next_block().unwrap();
        assert_eq!(block.number.as_u64(), 7);
        let block = queue.fetch_next_block().unwrap();
        assert_eq!(block.number.as_u64(), 8);
        // errr, the relayer is not ready for example.
        // push it again to the queue.
        queue.push_front(block);
        // now try again?.
        let block = queue.fetch_next_block().unwrap();
        assert_eq!(block.number.as_u64(), 8);
        // nice get the next one.
        let block = queue.fetch_next_block().unwrap();
        assert_eq!(block.number.as_u64(), 9);
    }

    #[test]
    fn sync_missing_blocks() {
        let mut queue = BlockQueue::with_fetcher(MockedInfura(7));
        // sync up any missing blocks.
        // since this an empty queue, it will fetch the latest block.
        // in our case it's 7 and add it to the queue.
        assert!(queue.sync_missing_blocks(10).is_ok());

        let block = queue.fetch_next_block().unwrap();
        assert_eq!(block.number.as_u64(), 7);
        let block = queue.fetch_next_block().unwrap();
        assert_eq!(block.number.as_u64(), 8);

        // now imagine we stoped for a while.
        // and we need to sync up quickly.
        queue.replace_fetcher(MockedInfura(12));
        // if we synced now.
        // we should get the missing blocks.
        let synced = queue.sync_missing_blocks(30).unwrap();
        assert_eq!(synced, 12 - 10);

        let block = queue.fetch_next_block().unwrap();
        assert_eq!(block.number.as_u64(), 9);
    }

    #[test]
    fn sync_empty_queue() {
        let mut queue = BlockQueue::with_fetcher(MockedInfura(7));
        assert_eq!(queue.is_empty(), true);

        let synced = queue.sync_missing_blocks(10).unwrap();
        assert_eq!(synced, 1);
    }

    #[test]
    fn full_sync() {
        let mut queue = BlockQueue::with_fetcher(MockedInfura(7));
        assert_eq!(queue.is_empty(), true);

        let s1 = queue.sync_missing_blocks(10).unwrap();
        assert_eq!(s1, 1);

        queue.replace_fetcher(MockedInfura(42));
        let mut synced = queue.sync_missing_blocks(10).unwrap();
        // full sync our queue.
        // don't do this in production, please :D
        while synced > 0 {
            synced = queue.sync_missing_blocks(10).unwrap();
        }

        assert_eq!(queue.len(), (42 - 7) + 1);

        for n in 7..=42 {
            let block = queue.pop_front();
            assert_eq!(block.unwrap().number.as_u64(), n);
        }
        // now the queue is empty again.
        assert!(queue.is_empty())
    }
}
