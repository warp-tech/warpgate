//! File Transfer Tracker
//!
//! Tracks active file transfers for a session, including hash calculation.

use std::collections::HashMap;
use std::time::Instant;

use sha2::{Digest, Sha256};

use super::types::TransferDirection;

/// Tracks active file transfers for a session
pub struct FileTransferTracker {
    /// Map of handle -> active transfer info
    active_transfers: HashMap<Vec<u8>, ActiveTransfer>,
    /// Hash threshold in bytes (skip hash for larger files)
    hash_threshold: u64,
}

struct ActiveTransfer {
    path: String,
    direction: TransferDirection,
    bytes_transferred: u64,
    hasher: Option<Sha256>,
    started_at: Instant,
}

/// Information about a completed file transfer
#[derive(Debug, Clone)]
pub struct TransferComplete {
    pub path: String,
    pub direction: TransferDirection,
    pub bytes_transferred: u64,
    pub hash: Option<String>,
    pub duration_ms: u64,
}

impl FileTransferTracker {
    /// Create a new tracker with the given hash threshold
    pub fn new(hash_threshold: u64) -> Self {
        Self {
            active_transfers: HashMap::new(),
            hash_threshold,
        }
    }

    /// Called when a file is opened
    pub fn file_opened(&mut self, handle: Vec<u8>, path: String, direction: TransferDirection) {
        let transfer = ActiveTransfer {
            path,
            direction,
            bytes_transferred: 0,
            hasher: Some(Sha256::new()),
            started_at: Instant::now(),
        };
        self.active_transfers.insert(handle, transfer);
    }

    /// Called when data is transferred (read or write)
    pub fn data_transferred(&mut self, handle: &[u8], data: &[u8]) {
        if let Some(transfer) = self.active_transfers.get_mut(handle) {
            transfer.bytes_transferred += data.len() as u64;

            // Update hash if under threshold
            if transfer.bytes_transferred <= self.hash_threshold {
                if let Some(hasher) = &mut transfer.hasher {
                    hasher.update(data);
                }
            } else {
                // Exceeded threshold, stop hashing
                transfer.hasher = None;
            }
        }
    }

    /// Called when a file is closed, returns transfer info
    pub fn file_closed(&mut self, handle: &[u8]) -> Option<TransferComplete> {
        self.active_transfers.remove(handle).map(|transfer| {
            let hash = transfer.hasher.map(|h| {
                let result = h.finalize();
                format!("sha256:{result:x}")
            });

            TransferComplete {
                path: transfer.path,
                direction: transfer.direction,
                bytes_transferred: transfer.bytes_transferred,
                hash,
                duration_ms: transfer.started_at.elapsed().as_millis() as u64,
            }
        })
    }

    /// Get info about an active transfer
    pub fn get_transfer(&self, handle: &[u8]) -> Option<(&str, TransferDirection, u64)> {
        self.active_transfers
            .get(handle)
            .map(|t| (t.path.as_str(), t.direction, t.bytes_transferred))
    }

    /// Check if any transfers are active
    pub fn has_active_transfers(&self) -> bool {
        !self.active_transfers.is_empty()
    }

    /// Get the number of active transfers
    pub fn active_transfer_count(&self) -> usize {
        self.active_transfers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_transfer() {
        let mut tracker = FileTransferTracker::new(10 * 1024 * 1024); // 10MB

        let handle = b"handle1".to_vec();
        tracker.file_opened(
            handle.clone(),
            "/tmp/test.txt".to_string(),
            TransferDirection::Download,
        );

        assert!(tracker.has_active_transfers());
        assert_eq!(tracker.active_transfer_count(), 1);

        // Transfer some data
        tracker.data_transferred(&handle, b"hello world");

        let info = tracker.get_transfer(&handle);
        assert!(info.is_some());
        let (path, direction, bytes) = info.unwrap();
        assert_eq!(path, "/tmp/test.txt");
        assert_eq!(direction, TransferDirection::Download);
        assert_eq!(bytes, 11);

        // Close the file
        let complete = tracker.file_closed(&handle);
        assert!(complete.is_some());
        let complete = complete.unwrap();
        assert_eq!(complete.path, "/tmp/test.txt");
        assert_eq!(complete.bytes_transferred, 11);
        assert!(complete.hash.is_some());
        assert!(complete.hash.unwrap().starts_with("sha256:"));

        assert!(!tracker.has_active_transfers());
    }

    #[test]
    fn test_large_file_no_hash() {
        let mut tracker = FileTransferTracker::new(100); // 100 bytes threshold

        let handle = b"handle2".to_vec();
        tracker.file_opened(
            handle.clone(),
            "/tmp/large.bin".to_string(),
            TransferDirection::Upload,
        );

        // Transfer more than the threshold
        tracker.data_transferred(&handle, &[0u8; 150]);

        let complete = tracker.file_closed(&handle);
        assert!(complete.is_some());
        let complete = complete.unwrap();
        assert_eq!(complete.bytes_transferred, 150);
        assert!(complete.hash.is_none()); // Hash should be None for large files
    }

    #[test]
    fn test_multiple_transfers() {
        let mut tracker = FileTransferTracker::new(10 * 1024 * 1024);

        let handle1 = b"h1".to_vec();
        let handle2 = b"h2".to_vec();

        tracker.file_opened(
            handle1.clone(),
            "/tmp/a.txt".to_string(),
            TransferDirection::Download,
        );
        tracker.file_opened(
            handle2.clone(),
            "/tmp/b.txt".to_string(),
            TransferDirection::Upload,
        );

        assert_eq!(tracker.active_transfer_count(), 2);

        tracker.data_transferred(&handle1, b"data1");
        tracker.data_transferred(&handle2, b"data2data2");

        let complete1 = tracker.file_closed(&handle1);
        assert!(complete1.is_some());
        assert_eq!(complete1.unwrap().bytes_transferred, 5);

        assert_eq!(tracker.active_transfer_count(), 1);

        let complete2 = tracker.file_closed(&handle2);
        assert!(complete2.is_some());
        assert_eq!(complete2.unwrap().bytes_transferred, 10);

        assert_eq!(tracker.active_transfer_count(), 0);
    }
}
