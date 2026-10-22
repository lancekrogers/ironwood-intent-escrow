//! An in-memory compact-block cache for `zcash_client_backend::sync::run`.
//!
//! No pinned crate ships a `BlockCache`, only a documentation example. The
//! payer wallet scans from a recent birthday, so a scan holds at most a few
//! thousand compact blocks, and they are dropped when the scan ends.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;
use zcash_client_backend::data_api::chain::{error, BlockCache, BlockSource};
use zcash_client_backend::data_api::scanning::ScanRange;
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_protocol::consensus::BlockHeight;

/// A block-cache failure.
#[derive(Debug, thiserror::Error)]
#[error("block_cache: {0}")]
pub struct CacheError(String);

/// Compact blocks keyed by height.
#[derive(Default)]
pub struct MemBlockCache {
    blocks: Mutex<BTreeMap<BlockHeight, CompactBlock>>,
}

impl MemBlockCache {
    fn lock(&self) -> Result<MutexGuard<'_, BTreeMap<BlockHeight, CompactBlock>>, CacheError> {
        self.blocks
            .lock()
            .map_err(|_| CacheError("the cache lock is poisoned".into()))
    }

    /// How many blocks the cache holds.
    pub fn len(&self) -> usize {
        self.lock().map(|b| b.len()).unwrap_or(0)
    }

    /// Whether the cache holds no blocks.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn height_of(block: &CompactBlock) -> Result<BlockHeight, CacheError> {
    u32::try_from(block.height)
        .map(BlockHeight::from_u32)
        .map_err(|_| CacheError(format!("block height {} is out of range", block.height)))
}

impl BlockSource for MemBlockCache {
    type Error = CacheError;

    fn with_blocks<F, WalletErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_block: F,
    ) -> Result<(), error::Error<WalletErrT, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), error::Error<WalletErrT, Self::Error>>,
    {
        let selected: Vec<CompactBlock> = {
            let blocks = self.lock().map_err(error::Error::BlockSource)?;
            blocks
                .range(from_height.unwrap_or(BlockHeight::from_u32(0))..)
                .take(limit.unwrap_or(usize::MAX))
                .map(|(_, block)| block.clone())
                .collect()
        };
        selected.into_iter().try_for_each(&mut with_block)
    }
}

#[async_trait]
impl BlockCache for MemBlockCache {
    fn get_tip_height(&self, range: Option<&ScanRange>) -> Result<Option<BlockHeight>, CacheError> {
        let blocks = self.lock()?;
        Ok(match range {
            Some(range) => blocks.range(range.block_range().clone()).next_back(),
            None => blocks.iter().next_back(),
        }
        .map(|(height, _)| *height))
    }

    async fn read(&self, range: &ScanRange) -> Result<Vec<CompactBlock>, CacheError> {
        let blocks = self.lock()?;
        let mut expected = range.block_range().start;
        let mut out = Vec::new();
        for (height, block) in blocks.range(range.block_range().clone()) {
            if *height != expected {
                break;
            }
            out.push(block.clone());
            expected = *height + 1;
        }
        Ok(out)
    }

    async fn insert(&self, compact_blocks: Vec<CompactBlock>) -> Result<(), CacheError> {
        let mut blocks = self.lock()?;
        for block in compact_blocks {
            blocks.insert(height_of(&block)?, block);
        }
        Ok(())
    }

    async fn delete(&self, range: ScanRange) -> Result<(), CacheError> {
        let mut blocks = self.lock()?;
        blocks.retain(|height, _| !range.block_range().contains(height));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_client_backend::data_api::scanning::ScanPriority;

    fn block(height: u64) -> CompactBlock {
        CompactBlock {
            height,
            ..CompactBlock::default()
        }
    }

    fn range(start: u32, end: u32) -> ScanRange {
        ScanRange::from_parts(
            BlockHeight::from_u32(start)..BlockHeight::from_u32(end),
            ScanPriority::Historic,
        )
    }

    #[tokio::test]
    async fn block_cache_reads_contiguous_blocks_and_deletes_a_range() {
        let cache = MemBlockCache::default();
        cache
            .insert(vec![block(10), block(11), block(13)])
            .await
            .unwrap();
        assert_eq!(cache.get_tip_height(None).unwrap(), Some(13.into()));
        assert_eq!(
            cache.get_tip_height(Some(&range(10, 12))).unwrap(),
            Some(11.into())
        );

        // The gap at 12 ends the read: short reads are allowed, gaps are not.
        let read: Vec<u64> = cache
            .read(&range(10, 14))
            .await
            .unwrap()
            .iter()
            .map(|b| b.height)
            .collect();
        assert_eq!(read, vec![10, 11]);

        cache.delete(range(11, 14)).await.unwrap();
        assert_eq!(cache.len(), 1);
        cache.truncate(BlockHeight::from_u32(9)).await.unwrap();
        assert!(cache.is_empty());
    }
}
