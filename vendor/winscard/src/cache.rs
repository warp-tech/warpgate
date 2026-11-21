use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Debug;

use uuid::Uuid;

use crate::WinScardResult;

/// `Smart Card Resource Manager` cache.
///
/// The Windows `Smart Card Resource Manager` cache is global: it is shared by every established
/// resource manager context, so the items written using one context are visible in all the others.
/// The cache items are scoped by the smart card identifier and the lookup name: different smart
/// cards have their own items even if the lookup names are the same.
///
/// See the [SCardReadCacheW] and [SCardWriteCacheW] functions documentation for more details.
///
/// [SCardReadCacheW]: https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardreadcachew
/// [SCardWriteCacheW]: https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardwritecachew
pub trait Cache: Debug {
    /// Reads the cache item value of the specified smart card.
    ///
    /// The implementation must return an error with the [ErrorKind::CacheItemNotFound] error kind
    /// if the item is not present in the cache, and an error with the [ErrorKind::CacheItemStale]
    /// error kind if the cached item is older than the requested `freshness_counter`.
    ///
    /// [ErrorKind::CacheItemNotFound]: crate::ErrorKind::CacheItemNotFound
    /// [ErrorKind::CacheItemStale]: crate::ErrorKind::CacheItemStale
    fn read(&self, card_id: Uuid, freshness_counter: u32, key: &str) -> WinScardResult<Vec<u8>>;

    /// Writes the cache item value of the specified smart card.
    ///
    /// An empty `value` means the item deletion: this is how the `Smart Card Minidriver`
    /// removes items from the cache.
    fn write(&mut self, card_id: Uuid, freshness_counter: u32, key: String, value: Vec<u8>);
}
