//! Server-side auto-detect (RTT and bandwidth measurement) per [MS-RDPBCGR 2.2.14].
//!
//! The server periodically sends RTT Measure Request PDUs and records the
//! round-trip time from the client's response, and brackets ordinary traffic
//! with a Bandwidth Measure Start/Stop pair so the client can report the
//! bandwidth it observed: around a single large graphics write where there is
//! one (see [`AutoDetectManager::begin_bandwidth_measure()`]), otherwise over
//! a fixed window of RTT ticks. RTT results are exposed via
//! [`AutoDetectManager::snapshot()`]; both RTT and bandwidth are reported to
//! the client via [`AutoDetectManager::build_netchar_result()`].
//!
//! [MS-RDPBCGR 2.2.14]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/dc672839-4f4e-40b1-a71c-cd6a959baa38

use core::sync::atomic::AtomicU32;
use std::collections::VecDeque;
use std::sync::Arc;

use ironrdp_pdu::rdp::autodetect::{AutoDetectRequest, AutoDetectResponse};

/// Number of RTT samples to retain for averaging.
const RTT_WINDOW_SIZE: usize = 8;

/// Probes older than this are discarded as unresponsive.
pub(crate) const RTT_PROBE_MAX_AGE_MS: u64 = 30_000;

/// Run a bandwidth measurement once every this many RTT ticks. Bandwidth
/// changes far more slowly than RTT, so it is sampled less often than the
/// per-tick RTT probe.
const BW_MEASURE_INTERVAL_TICKS: u32 = 8;

/// Number of RTT ticks a bandwidth window stays open between Start and Stop.
///
/// [MS-RDPBCGR] 1.3.9 and 2.2.14.2.2 scope the Bandwidth Measure Payload
/// message to the connect-time transaction only; after the RDP Connection
/// Sequence, "the PDUs sent from server to client (between start and stop
/// messages) replace the payload messages". So the window has to stay open
/// long enough for ordinary traffic to fill it, rather than closing
/// immediately the way a synthetic payload would allow.
const BW_WINDOW_TICKS: u32 = 4;

/// Smallest graphics write worth bracketing with a bandwidth measurement.
///
/// A smaller write crosses even a slow link within the client's millisecond
/// timer resolution, so its figure says little about capacity.
pub(crate) const BW_BRACKET_MIN_BYTES: usize = 10 * 1024;

/// Minimum spacing between bandwidth measurements bracketed around a write.
const BW_BRACKET_MIN_INTERVAL_MS: u64 = 1_000;

/// Minimum spacing between Network Characteristics Result PDUs.
///
/// The reported figures are averaged over a window and change far more slowly
/// than the RTT probe cadence, so pacing the result independently keeps an
/// aggressive probe rate from turning into an equally aggressive stream of
/// unsolicited PDUs.
const NETCHAR_RESULT_MIN_INTERVAL_MS: u64 = 1_000;

/// Server-side auto-detect state machine.
///
/// Tracks outstanding RTT probes and computes round-trip statistics from
/// client responses. Call [`send_rtt_request()`](Self::send_rtt_request) to
/// generate a probe, then [`handle_response()`](Self::handle_response) when
/// the client replies.
///
/// The manager reads no clock of its own. Every method that needs the current time
/// takes `now_ms`, a caller-supplied monotonic millisecond counter whose epoch is
/// arbitrary as long as it is consistent across calls. Keeping time out of the state
/// machine makes RTT measurement exactly testable, leaves the type usable from targets
/// where the standard library has no clock (`std::time::Instant::now` panics on
/// `wasm32-unknown-unknown`), and keeps the crate a candidate for the no-I/O rules the
/// Core Tier crates follow.
pub struct AutoDetectManager {
    next_sequence: u16,
    /// Outstanding probes as `(sequence_number, sent_at_ms)`.
    pending_probes: Vec<(u16, u64)>,
    rtt_samples: VecDeque<u32>,
    /// State of an in-flight bandwidth measurement, if any. A new measurement
    /// is not started while one is outstanding.
    pending_bw: Option<PendingBandwidth>,
    /// Most recently measured bandwidth in kilobits per second.
    bandwidth_kbps: Option<u32>,
    /// Counts RTT ticks to pace bandwidth measurements (see [`BW_MEASURE_INTERVAL_TICKS`]).
    bw_tick_count: u32,
    /// When the last bracketed measurement began, for pacing brackets.
    last_bracket_start_ms: Option<u64>,
    /// When the last Network Characteristics Result was built, for pacing.
    last_netchar_result_ms: Option<u64>,
    /// Lowest RTT observed over the whole session, for the wire `baseRTT`.
    ///
    /// [MS-RDPBCGR] 2.2.14.1.5 defines that field as "the lowest detected
    /// round-trip time" with no window scoping, so it is tracked separately from
    /// the sliding window behind [`snapshot()`](Self::snapshot). A floor derived
    /// from the window can rise once a low sample is evicted, which would make
    /// the baseRTT / averageRTT pair unusable for the queueing-delay difference
    /// a client computes from it.
    min_rtt_ms: Option<u32>,
    /// Set when an RTT response updates the measured figures, cleared when a
    /// Network Characteristics Result reports them.
    ///
    /// Without it a client that stops answering leaves the last window values
    /// being advertised indefinitely, since they never age out of `rtt_samples`.
    rtt_is_fresh: bool,
    /// Set when a bandwidth measurement completes, cleared when a Network
    /// Characteristics Result reports it.
    ///
    /// Tracked separately from [`rtt_is_fresh`](Self::rtt_is_fresh): bandwidth
    /// measurements complete far less often than RTT samples arrive, so an RTT
    /// response alone must not re-arm reporting of a bandwidth figure that may
    /// be several measurements stale.
    bandwidth_is_fresh: bool,
}

/// Result of [`AutoDetectManager::handle_response()`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoDetectOutcome {
    /// An RTT Measure Response matched a pending probe; carries the measured RTT
    /// in milliseconds.
    Rtt(u32),
    /// A Bandwidth Measure Results matched the pending transaction. `None` means
    /// the measurement completed without a usable figure, and any previously
    /// stored bandwidth was cleared rather than left in place.
    Bandwidth(Option<u32>),
    /// The response did not match any pending probe or transaction.
    Unmatched,
}

/// State of an in-flight continuous bandwidth measurement.
enum PendingBandwidth {
    /// Start has been sent; the window stays open for this many more ticks
    /// before Stop is sent, so ordinary traffic can fill it.
    Open { sequence: u16, ticks_remaining: u32 },
    /// Start has been sent ahead of a single write; Stop follows it.
    /// `since_ms` is when it began, so [`AutoDetectManager::expire_stale_probes()`]
    /// can give up on a Stop that is never sent.
    Bracketing { sequence: u16, since_ms: u64 },
    /// Stop has been sent; awaiting the client's Bandwidth Measure Results.
    /// `since_ms` is when the wait began, so
    /// [`AutoDetectManager::expire_stale_probes()`] can give up on a client
    /// that never answers. A bracketed measurement carries over the time its
    /// Start was sent. A tick window has no clock when its Stop goes out, so
    /// it stays `None` until the first expiry pass that sees it stamps it.
    AwaitingResults { sequence: u16, since_ms: Option<u64> },
}

impl AutoDetectManager {
    pub fn new() -> Self {
        Self {
            next_sequence: 0,
            pending_probes: Vec::new(),
            rtt_samples: VecDeque::with_capacity(RTT_WINDOW_SIZE),
            pending_bw: None,
            bandwidth_kbps: None,
            bw_tick_count: 0,
            last_bracket_start_ms: None,
            last_netchar_result_ms: None,
            rtt_is_fresh: false,
            bandwidth_is_fresh: false,
            min_rtt_ms: None,
        }
    }

    /// Generate an RTT Measure Request PDU for continuous detection.
    ///
    /// The caller must encode and send the returned [`AutoDetectRequest`] on
    /// the MCS message channel, framed by a `SEC_AUTODETECT_REQ` security
    /// header ([MS-RDPBCGR] 2.2.14.3). `now_ms` is recorded as the send time
    /// and is what [`handle_response()`](Self::handle_response) measures against.
    pub fn send_rtt_request(&mut self, now_ms: u64) -> AutoDetectRequest {
        let seq = self.allocate_sequence();
        self.pending_probes.push((seq, now_ms));
        AutoDetectRequest::rtt_continuous(seq)
    }

    /// Advance the bandwidth measurement state machine by one tick, returning
    /// a PDU to send when the machine has one, or `None` otherwise.
    ///
    /// A measurement is a Start sent when one is due (paced to once every
    /// [`BW_MEASURE_INTERVAL_TICKS`] calls and suppressed while a prior one is
    /// outstanding), followed by a Stop sent [`BW_WINDOW_TICKS`] calls later.
    /// No payload PDU is sent between them: per [MS-RDPBCGR] 1.3.9, Continuous
    /// Auto-Detection's server-to-client message set for bandwidth measurement
    /// is Start and Stop only, and 2.2.14.2.2 states that after the RDP
    /// Connection Sequence the ordinary PDUs the server sends between them
    /// are what the client counts. The caller sends whichever PDU this
    /// returns on the MCS message channel; the client eventually replies with
    /// a Bandwidth Measure Results PDU, processed by
    /// [`handle_response()`](Self::handle_response).
    pub fn build_bandwidth_measure(&mut self) -> Option<AutoDetectRequest> {
        match &mut self.pending_bw {
            Some(PendingBandwidth::Open {
                sequence,
                ticks_remaining,
            }) => {
                if *ticks_remaining == 0 {
                    let sequence = *sequence;
                    self.pending_bw = Some(PendingBandwidth::AwaitingResults {
                        sequence,
                        since_ms: None,
                    });
                    return Some(AutoDetectRequest::bw_stop_continuous(sequence));
                }
                *ticks_remaining -= 1;
                None
            }
            Some(PendingBandwidth::AwaitingResults { .. } | PendingBandwidth::Bracketing { .. }) => None,
            None => {
                self.bw_tick_count = self.bw_tick_count.wrapping_add(1);
                if !self.bw_tick_count.is_multiple_of(BW_MEASURE_INTERVAL_TICKS) {
                    return None;
                }
                let seq = self.allocate_sequence();
                self.pending_bw = Some(PendingBandwidth::Open {
                    sequence: seq,
                    ticks_remaining: BW_WINDOW_TICKS,
                });
                Some(AutoDetectRequest::bw_start_continuous(seq))
            }
        }
    }

    /// Start a bandwidth measurement around the write the caller is about to
    /// make, returning the Bandwidth Measure Start to send immediately before
    /// it, or `None` when no measurement should start now.
    ///
    /// Continuous Auto-Detection counts the ordinary traffic between Start and
    /// Stop ([MS-RDPBCGR] 3.2.5.14), so a window that happens to span idle time
    /// measures how little the server sent, not what the link can carry.
    /// Bracketing one large write, and sending Stop right after it with
    /// [`end_bandwidth_measure()`](Self::end_bandwidth_measure), times a burst
    /// the link actually had to carry. All three must go out on the same
    /// ordered transport.
    ///
    /// Returns `None` for a write smaller than 10 KiB, while
    /// another measurement is outstanding, and within
    /// `BW_BRACKET_MIN_INTERVAL_MS` of the previous bracketed Start. Each
    /// successful call also holds off the tick window of
    /// [`build_bandwidth_measure()`](Self::build_bandwidth_measure) for another
    /// `BW_MEASURE_INTERVAL_TICKS` ticks, so it only measures while no large
    /// writes are coming.
    pub fn begin_bandwidth_measure(&mut self, write_len: usize, now_ms: u64) -> Option<AutoDetectRequest> {
        if write_len < BW_BRACKET_MIN_BYTES || self.pending_bw.is_some() {
            return None;
        }
        if let Some(last) = self.last_bracket_start_ms {
            if now_ms.saturating_sub(last) < BW_BRACKET_MIN_INTERVAL_MS {
                return None;
            }
        }
        self.last_bracket_start_ms = Some(now_ms);
        self.bw_tick_count = 0;
        let sequence = self.allocate_sequence();
        self.pending_bw = Some(PendingBandwidth::Bracketing {
            sequence,
            since_ms: now_ms,
        });
        Some(AutoDetectRequest::bw_start_continuous(sequence))
    }

    /// Finish the measurement [`begin_bandwidth_measure()`](Self::begin_bandwidth_measure)
    /// started, returning the Bandwidth Measure Stop to send right after the
    /// bracketed write, or `None` if no bracketed measurement is open.
    pub fn end_bandwidth_measure(&mut self) -> Option<AutoDetectRequest> {
        let Some(PendingBandwidth::Bracketing { sequence, since_ms }) = self.pending_bw else {
            return None;
        };
        self.pending_bw = Some(PendingBandwidth::AwaitingResults {
            sequence,
            since_ms: Some(since_ms),
        });
        Some(AutoDetectRequest::bw_stop_continuous(sequence))
    }

    /// Build a Network Characteristics Result reporting the measured network.
    ///
    /// Returns `None` until the network has actually been characterised, which
    /// means both an RTT sample and a completed bandwidth measurement. A result
    /// carrying RTT alone reports part of the picture as though it were the
    /// whole, so it is not sent; the same is true of the reference
    /// implementations, which return early with no bandwidth figure to report.
    ///
    /// Also returns `None` when one was sent less than
    /// [`NETCHAR_RESULT_MIN_INTERVAL_MS`] ago. The RTT probe cadence is set by
    /// the caller and can be far faster than the rate at which the reported
    /// figures meaningfully change, so the result is paced independently rather
    /// than emitted once per probe.
    ///
    /// Finally, returns `None` unless a client response has updated either
    /// figure since the last result. RTT samples do not age out of the
    /// window, and a completed bandwidth measurement is never invalidated by
    /// a later failed one on its own, so a client that stops answering would
    /// otherwise leave the last values being advertised forever. `snapshot()`
    /// still reports them, where staleness is the embedder's to judge, but
    /// they are not put on the wire as a current claim; a bandwidth
    /// measurement that completes without a usable figure clears
    /// `bandwidth_kbps` rather than leaving the previous one in place, so a
    /// run of failures withholds the result entirely instead of reporting an
    /// increasingly stale number.
    ///
    /// `baseRTT` is the lowest RTT seen over the whole session, not the lowest in
    /// the current window, so it never rises. `averageRTT` is the window average
    /// and does track current conditions; the difference between the two is what
    /// a client reads as queueing delay.
    ///
    /// Like [`send_rtt_request()`](Self::send_rtt_request), the caller sends the
    /// returned PDU on the MCS message channel. The client does not reply to it.
    pub fn build_netchar_result(&mut self, now_ms: u64) -> Option<AutoDetectRequest> {
        if !self.rtt_is_fresh && !self.bandwidth_is_fresh {
            return None;
        }
        let bandwidth_kbps = self.bandwidth_kbps?;
        let base_rtt_ms = self.min_rtt_ms?;
        let snapshot = self.snapshot()?;

        if let Some(last) = self.last_netchar_result_ms {
            if now_ms.saturating_sub(last) < NETCHAR_RESULT_MIN_INTERVAL_MS {
                return None;
            }
        }
        self.last_netchar_result_ms = Some(now_ms);
        self.rtt_is_fresh = false;
        self.bandwidth_is_fresh = false;

        let seq = self.allocate_sequence();
        Some(AutoDetectRequest::netchar_result(
            seq,
            base_rtt_ms,
            bandwidth_kbps,
            snapshot.avg_ms,
        ))
    }

    /// Process an Auto-Detect Response from the client.
    ///
    /// For an RTT Measure Response, records the sample and returns
    /// [`AutoDetectOutcome::Rtt`] with the measured RTT in milliseconds. For a
    /// Bandwidth Measure Results, records the computed bandwidth internally and
    /// returns [`AutoDetectOutcome::Bandwidth`]; its payload is `None` when the
    /// measurement completed without a usable figure, in which case any
    /// previously stored bandwidth was just cleared (see the note on
    /// [`build_netchar_result()`](Self::build_netchar_result)). Returns
    /// [`AutoDetectOutcome::Unmatched`] for an unexpected or unmatched response.
    ///
    /// `now_ms` is the receipt time on the same clock passed to
    /// [`send_rtt_request()`](Self::send_rtt_request).
    pub fn handle_response(&mut self, response: &AutoDetectResponse, now_ms: u64) -> AutoDetectOutcome {
        match response {
            AutoDetectResponse::RttResponse { sequence_number } => {
                let Some(idx) = self.pending_probes.iter().position(|(s, _)| *s == *sequence_number) else {
                    return AutoDetectOutcome::Unmatched;
                };
                let (_, sent_at_ms) = self.pending_probes.remove(idx);

                // Saturating rather than wrapping: a caller whose clock went backwards gets
                // a zero sample, not a nonsense one near u32::MAX.
                let rtt_ms = u32::try_from(now_ms.saturating_sub(sent_at_ms)).unwrap_or(u32::MAX);

                if self.rtt_samples.len() >= RTT_WINDOW_SIZE {
                    self.rtt_samples.pop_front();
                }
                self.rtt_samples.push_back(rtt_ms);
                self.min_rtt_ms = Some(self.min_rtt_ms.map_or(rtt_ms, |m| m.min(rtt_ms)));
                self.rtt_is_fresh = true;

                AutoDetectOutcome::Rtt(rtt_ms)
            }
            AutoDetectResponse::BandwidthMeasureResults {
                sequence_number,
                time_delta_ms,
                byte_count,
                ..
            } => {
                let awaiting = matches!(
                    self.pending_bw,
                    Some(PendingBandwidth::AwaitingResults { sequence, .. }) if sequence == *sequence_number
                );
                if !awaiting {
                    return AutoDetectOutcome::Unmatched;
                }
                self.pending_bw = None;
                // A transaction that completes without a usable figure clears the
                // previous one rather than leaving it in place, so a run of failures
                // withholds the result (see `build_netchar_result`) instead of
                // reporting an increasingly stale bandwidth.
                self.bandwidth_kbps = measured_bandwidth_kbps(*time_delta_ms, *byte_count);
                if self.bandwidth_kbps.is_some() {
                    self.bandwidth_is_fresh = true;
                }
                AutoDetectOutcome::Bandwidth(self.bandwidth_kbps)
            }
            _ => AutoDetectOutcome::Unmatched,
        }
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

    /// Session-lifetime lowest RTT in milliseconds (`baseRTT` per
    /// [MS-RDPBCGR] 2.2.14.1.5), or `None` if no measurement has landed yet.
    /// Unlike [`Self::snapshot`]'s `min_ms`, this never rises as samples age
    /// out of the window: it is the floor over the whole session.
    pub fn baseline_rtt_ms(&self) -> Option<u32> {
        self.min_rtt_ms
    }

    /// Number of outstanding probes awaiting response.
    pub fn pending_count(&self) -> usize {
        self.pending_probes.len()
    }

    /// Most recently measured bandwidth in kilobits per second, or `None` if
    /// no bandwidth measurement has completed yet. Unlike
    /// [`Self::build_netchar_result`], this is not gated on freshness or
    /// pacing: it reports the last completed figure even if a subsequent
    /// failed measurement or an idle client has left it unrefreshed for a
    /// while, the same relationship [`Self::snapshot`] has to RTT. Staleness
    /// is the caller's to judge.
    pub fn bandwidth_kbps(&self) -> Option<u32> {
        self.bandwidth_kbps
    }

    /// Discard probes older than `max_age_ms` to prevent unbounded growth, and
    /// give up on a bandwidth measurement that has waited that long.
    ///
    /// A measurement is otherwise only finished by the client's results, or for
    /// a bracketed one by [`end_bandwidth_measure()`](Self::end_bandwidth_measure)
    /// first, so a client that never answers or a Stop that is never sent would
    /// stop bandwidth measurement for the rest of the session. A tick window
    /// that is still open is left alone, since it sends its own Stop. Results
    /// that arrive after this are unmatched.
    ///
    /// `now_ms` is on the same clock passed to
    /// [`send_rtt_request()`](Self::send_rtt_request).
    pub fn expire_stale_probes(&mut self, now_ms: u64, max_age_ms: u64) {
        self.pending_probes
            .retain(|(_, sent_at_ms)| now_ms.saturating_sub(*sent_at_ms) < max_age_ms);

        let expired = match &mut self.pending_bw {
            Some(PendingBandwidth::Bracketing { since_ms, .. }) => now_ms.saturating_sub(*since_ms) >= max_age_ms,
            Some(PendingBandwidth::AwaitingResults { since_ms, .. }) => match *since_ms {
                None => {
                    *since_ms = Some(now_ms);
                    false
                }
                Some(since) => now_ms.saturating_sub(since) >= max_age_ms,
            },
            Some(PendingBandwidth::Open { .. }) | None => false,
        };
        if expired {
            self.pending_bw = None;
        }
    }

    /// Returns the sequence number for the next request and advances the
    /// counter, wrapping at `u16::MAX`.
    fn allocate_sequence(&mut self) -> u16 {
        let sequence = self.next_sequence;
        self.next_sequence = sequence.wrapping_add(1);
        sequence
    }
}

/// Bandwidth from a Bandwidth Measure Results, in kilobits per second, or
/// `None` when the client counted no bytes.
///
/// The client's timer has millisecond resolution, so a burst that crosses a
/// fast link within one millisecond reports a zero time. That is a real
/// measurement, bounded below by one millisecond, not a failed one.
///
/// This differs from `AutoDetectResponse::computed_bandwidth_kbps` in
/// `ironrdp-pdu` on purpose. That helper returns `None` for a zero time, which
/// would make exactly those bursts failed measurements that clear the figure,
/// and it returns `Some(0)` for zero bytes, where a measurement that counted
/// nothing should clear the figure instead of reporting a dead link.
/// MS-RDPBCGR 3.3.5.14 gives the formula, (byteCount * 8) / timeDelta, but
/// doesn't say what a zero timeDelta means.
///
/// A figure too large for a `u32` saturates at `u32::MAX`, where that helper
/// wraps, because the client supplies both numbers.
/// `RdpServer::autodetect_bandwidth_handle` also uses `u32::MAX` for not
/// measured, so a figure that large reads as no measurement there.
fn measured_bandwidth_kbps(time_delta_ms: u32, byte_count: u32) -> Option<u32> {
    if byte_count == 0 {
        return None;
    }
    let kbps = u64::from(byte_count) * 8 / u64::from(time_delta_ms.max(1));
    Some(u32::try_from(kbps).unwrap_or(u32::MAX))
}

impl Default for AutoDetectManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of RTT measurement results.
#[derive(Debug, Clone, Copy)]
pub struct RttSnapshot {
    /// Minimum RTT in milliseconds over the current window.
    ///
    /// Not the `baseRTT` sent on the wire, which is the session-lifetime lowest
    /// per [MS-RDPBCGR] 2.2.14.1.5. This one can rise as low samples age out.
    pub min_ms: u32,
    /// Maximum observed RTT in milliseconds.
    pub max_ms: u32,
    /// Average RTT in milliseconds over the sample window.
    pub avg_ms: u32,
    /// Number of samples in the current window.
    pub sample_count: usize,
}

/// The latest auto-detect measurements of one connection, written by the server
/// as they arrive.
///
/// [`Default`] creates handles at their initial values: no measurement yet,
/// generation 0. The server creates them that way for each connection, so a
/// new connection never sees the figures of the one before it. They stay at
/// those values while auto-detect is disabled (see
/// [`RdpServer::enable_autodetect`](crate::RdpServer::enable_autodetect)).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AutoDetectHandles {
    /// Latest round-trip time in milliseconds, or `u32::MAX` until the first
    /// measurement. Updated on each RTT Measure Response, so a reader gets a
    /// fresh, frame-traffic-independent network RTT for flow control.
    pub rtt: Arc<AtomicU32>,

    /// Lowest RTT of the connection in milliseconds (`baseRTT` per
    /// [MS-RDPBCGR] 2.2.14.1.5), or `u32::MAX` until the first measurement.
    /// Updated at the same point as [`Self::rtt`], but unlike it this figure
    /// never rises: pair it with that figure to derive queueing delay
    /// (`averageRTT - baseRTT`), which `rtt` alone cannot give since it is a
    /// sliding-window value that rises as low samples age out.
    pub baseline_rtt: Arc<AtomicU32>,

    /// Latest measured bandwidth in kilobits per second, or `u32::MAX` until
    /// the first measurement completes. Updated whenever a Bandwidth Measure
    /// Results response completes a measurement, with the figure the server
    /// also reports to the client on the wire; a measurement without a usable
    /// figure sets it back to `u32::MAX`.
    pub bandwidth: Arc<AtomicU32>,

    /// Pairs with [`Self::bandwidth`]: increments every time that figure is
    /// republished, since the figure itself repeats too often to be its own
    /// freshness signal. Load this with `Ordering::Acquire` to detect a fresh
    /// measurement window, then read the bandwidth: the server increments this
    /// with `Ordering::Release` after storing the value, so the bandwidth read
    /// is at least as new as the generation observed. It is not an exact pair:
    /// if the next window closes between the two reads, the value can already
    /// belong to that later window.
    ///
    /// Starts at 0 with each connection, so compare it only with generations
    /// read from this same handle.
    pub bandwidth_generation: Arc<AtomicU32>,
}

impl Default for AutoDetectHandles {
    fn default() -> Self {
        Self {
            rtt: Arc::new(AtomicU32::new(u32::MAX)),
            baseline_rtt: Arc::new(AtomicU32::new(u32::MAX)),
            bandwidth: Arc::new(AtomicU32::new(u32::MAX)),
            bandwidth_generation: Arc::new(AtomicU32::new(0)),
        }
    }
}
