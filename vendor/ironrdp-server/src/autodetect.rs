//! Server-side auto-detect (RTT measurement) per [MS-RDPBCGR 2.2.14].
//!
//! The server periodically sends RTT Measure Request PDUs and records the
//! round-trip time from the client's response. Results are exposed via
//! [`AutoDetectManager::snapshot()`].
//!
//! [MS-RDPBCGR 2.2.14]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/dc672839-4f4e-40b1-a71c-cd6a959baa38

use std::collections::VecDeque;
use std::time::Instant;

use ironrdp_pdu::rdp::autodetect::{AutoDetectRequest, AutoDetectResponse};

/// Number of RTT samples to retain for averaging.
const RTT_WINDOW_SIZE: usize = 8;

/// Probes older than this are discarded as unresponsive.
pub(crate) const RTT_PROBE_MAX_AGE: core::time::Duration = core::time::Duration::from_secs(30);

/// Server-side auto-detect state machine.
///
/// Tracks outstanding RTT probes and computes round-trip statistics from
/// client responses. Call [`send_rtt_request()`](Self::send_rtt_request) to
/// generate a probe, then [`handle_response()`](Self::handle_response) when
/// the client replies.
pub struct AutoDetectManager {
    next_sequence: u16,
    pending_probes: Vec<(u16, Instant)>,
    rtt_samples: VecDeque<u32>,
}

impl AutoDetectManager {
    pub fn new() -> Self {
        Self {
            next_sequence: 0,
            pending_probes: Vec::new(),
            rtt_samples: VecDeque::with_capacity(RTT_WINDOW_SIZE),
        }
    }

    /// Generate an RTT Measure Request PDU for continuous detection.
    ///
    /// The caller must encode and send the returned [`AutoDetectRequest`] as
    /// a Share Data PDU on the IO channel. Timing information is tracked
    /// internally by [`AutoDetectManager`].
    pub fn send_rtt_request(&mut self) -> AutoDetectRequest {
        let seq = self.next_sequence;
        self.next_sequence = seq.wrapping_add(1);
        self.pending_probes.push((seq, Instant::now()));
        AutoDetectRequest::rtt_continuous(seq)
    }

    /// Process an RTT Measure Response from the client.
    ///
    /// Returns the measured RTT in milliseconds if the sequence number
    /// matches an outstanding probe, or `None` if it was unexpected.
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        reason = "RTT in ms fits in u32 for any plausible network latency"
    )]
    pub fn handle_response(&mut self, response: &AutoDetectResponse) -> Option<u32> {
        let AutoDetectResponse::RttResponse { sequence_number } = response else {
            return None;
        };

        let idx = self.pending_probes.iter().position(|(s, _)| *s == *sequence_number)?;
        let (_, sent_at) = self.pending_probes.remove(idx);

        let rtt_ms = sent_at.elapsed().as_millis() as u32;

        if self.rtt_samples.len() >= RTT_WINDOW_SIZE {
            self.rtt_samples.pop_front();
        }
        self.rtt_samples.push_back(rtt_ms);

        Some(rtt_ms)
    }

    /// Get current RTT statistics, or `None` if no measurements yet.
    pub fn snapshot(&self) -> Option<RttSnapshot> {
        if self.rtt_samples.is_empty() {
            return None;
        }

        let min = *self.rtt_samples.iter().min().unwrap_or(&0);
        let max = *self.rtt_samples.iter().max().unwrap_or(&0);
        let sum: u64 = self.rtt_samples.iter().map(|&v| u64::from(v)).sum();
        #[expect(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            reason = "average of u32 samples fits in u32"
        )]
        let avg = (sum / self.rtt_samples.len() as u64) as u32;

        Some(RttSnapshot {
            min_ms: min,
            max_ms: max,
            avg_ms: avg,
            sample_count: self.rtt_samples.len(),
        })
    }

    /// Number of outstanding probes awaiting response.
    pub fn pending_count(&self) -> usize {
        self.pending_probes.len()
    }

    /// Discard probes older than the given threshold to prevent unbounded growth.
    pub fn expire_stale_probes(&mut self, max_age: core::time::Duration) {
        self.pending_probes.retain(|(_, sent_at)| sent_at.elapsed() < max_age);
    }
}

impl Default for AutoDetectManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of RTT measurement results.
#[derive(Debug, Clone, Copy)]
pub struct RttSnapshot {
    /// Minimum observed RTT in milliseconds.
    pub min_ms: u32,
    /// Maximum observed RTT in milliseconds.
    pub max_ms: u32,
    /// Average RTT in milliseconds over the sample window.
    pub avg_ms: u32,
    /// Number of samples in the current window.
    pub sample_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtt_request_increments_sequence() {
        let mut mgr = AutoDetectManager::new();
        let req1 = mgr.send_rtt_request();
        let req2 = mgr.send_rtt_request();
        assert_eq!(req1.sequence_number(), 0);
        assert_eq!(req2.sequence_number(), 1);
        assert_eq!(mgr.pending_count(), 2);
    }

    #[test]
    fn rtt_response_computes_latency() {
        let mut mgr = AutoDetectManager::new();
        let req = mgr.send_rtt_request();

        let response = AutoDetectResponse::RttResponse {
            sequence_number: req.sequence_number(),
        };
        let rtt = mgr.handle_response(&response);
        assert!(rtt.is_some(), "should match the outstanding probe");
        assert_eq!(mgr.pending_count(), 0);
    }

    #[test]
    fn unknown_sequence_returns_none() {
        let mut mgr = AutoDetectManager::new();
        let _ = mgr.send_rtt_request();

        let response = AutoDetectResponse::RttResponse { sequence_number: 999 };
        assert!(mgr.handle_response(&response).is_none());
        assert_eq!(mgr.pending_count(), 1, "original probe should remain");
    }

    #[test]
    fn snapshot_returns_none_without_data() {
        let mgr = AutoDetectManager::new();
        assert!(mgr.snapshot().is_none());
    }

    #[test]
    fn snapshot_reflects_measurements() {
        let mut mgr = AutoDetectManager::new();

        for _ in 0..3 {
            let req = mgr.send_rtt_request();
            let response = AutoDetectResponse::RttResponse {
                sequence_number: req.sequence_number(),
            };
            let _ = mgr.handle_response(&response);
        }

        let snap = mgr.snapshot().expect("should have data after 3 measurements");
        assert_eq!(snap.sample_count, 3);
        assert!(snap.avg_ms < 100);
    }

    #[test]
    fn sequence_number_wraps() {
        let mut mgr = AutoDetectManager::new();
        mgr.next_sequence = u16::MAX;
        let req = mgr.send_rtt_request();
        assert_eq!(req.sequence_number(), u16::MAX);

        let req2 = mgr.send_rtt_request();
        assert_eq!(req2.sequence_number(), 0, "should wrap around");
    }

    #[test]
    fn stale_probe_expiry() {
        let mut mgr = AutoDetectManager::new();
        let _ = mgr.send_rtt_request();
        assert_eq!(mgr.pending_count(), 1);

        mgr.expire_stale_probes(core::time::Duration::ZERO);
        assert_eq!(mgr.pending_count(), 0);
    }
}
