//! Dirty rect tracker for progressive encoding in RDP web client
//!
//! Protocol: changes go out as JPEG immediately and mark their respective
//! rects as dirty. Once a dirty rect has settled for a while, it (merged with other
//! settled neighbours) gets sent as PNG.

use std::time::{Duration, Instant};

use warpgate_core::DesktopRect;

/// How to wakt until a PNG retransmit
pub const SETTLE: Duration = Duration::from_secs(5);

/// Tile size px
const TILE: u16 = 64;

pub struct DirtyTracker {
    width: u16,
    height: u16,
    /// Row major, deadline for when the tile is due for refinement
    tiles: Vec<Option<Instant>>,
}

impl DirtyTracker {
    pub const fn new() -> Self {
        Self {
            width: 0,
            height: 0,
            tiles: Vec::new(),
        }
    }

    pub fn resize(&mut self, width: u16, height: u16) {
        if self.width == (width) && self.height == (height) {
            return;
        }
        self.width = width;
        self.height = height;
        self.tiles.clear();
        self.tiles.resize(
            (self.cols() as usize).saturating_mul(self.rows() as usize),
            None,
        );
    }

    const fn cols(&self) -> u16 {
        self.width.div_ceil(TILE)
    }

    const fn rows(&self) -> u16 {
        self.height.div_ceil(TILE)
    }

    /// Mark rect as dirty
    pub fn touch(&mut self, rect: DesktopRect, now: Instant) {
        let Some((col0, row0, col1, row1)) = self.tile_span(rect) else {
            return;
        };
        let due = now + SETTLE;
        for row in row0..row1 {
            for col in col0..col1 {
                let index = self.index(col, row);
                if let Some(slot) = self.tiles.get_mut(index) {
                    *slot = Some(due);
                }
            }
        }
    }

    /// Take the areas that have settled and untrack them
    pub fn take_settled(&mut self, now: Instant) -> Vec<DesktopRect> {
        let mut out = Vec::new();
        for row in 0..self.rows() {
            for col in 0..self.cols() {
                if !self.is_settled(col, row, now) {
                    continue;
                }
                // Grow right, then down as far as the full width stays settled, so a large
                // quiet area becomes one rect instead of hundreds of tile-sized ones.
                let mut w = 1;
                while self.is_settled(col + w, row, now) {
                    w += 1;
                }
                let mut h = 1;
                while (col..col + w).all(|c| self.is_settled(c, row + h, now)) {
                    h += 1;
                }
                for r in row..row + h {
                    for c in col..col + w {
                        let index = self.index(c, r);
                        if let Some(slot) = self.tiles.get_mut(index) {
                            *slot = None;
                        }
                    }
                }
                if let Some(rect) = self.pixel_rect(col, row, w, h) {
                    out.push(rect);
                }
            }
        }
        out
    }

    /// Predict when the next take_settled() could return something at the earliest
    pub fn next_due(&self) -> Option<Instant> {
        self.tiles.iter().flatten().min().copied()
    }

    const fn index(&self, col: u16, row: u16) -> usize {
        (row as usize) * (self.cols() as usize) + (col as usize)
    }

    fn is_settled(&self, col: u16, row: u16, now: Instant) -> bool {
        if col >= self.cols() || row >= self.rows() {
            return false;
        }
        matches!(self.tiles.get(self.index(col, row)), Some(&Some(due)) if due <= now)
    }

    /// `(col0, row0, col1, row1)` tile range covering rect
    fn tile_span(&self, rect: DesktopRect) -> Option<(u16, u16, u16, u16)> {
        if self.cols() == 0 || self.rows() == 0 {
            return None;
        }
        let x0 = rect.x.min(self.width);
        let y0 = rect.y.min(self.height);
        let x1 = (rect.x + rect.width).min(self.width);
        let y1 = (rect.y + rect.height).min(self.height);
        if x1 <= x0 || y1 <= y0 {
            return None;
        }
        Some((x0 / TILE, y0 / TILE, x1.div_ceil(TILE), y1.div_ceil(TILE)))
    }

    /// tiles to pixels
    fn pixel_rect(&self, col: u16, row: u16, w: u16, h: u16) -> Option<DesktopRect> {
        let x = col * TILE;
        let y = row * TILE;
        let width = ((col + w) * TILE).min(self.width).checked_sub(x)?;
        let height = ((row + h) * TILE).min(self.height).checked_sub(y)?;
        if width == 0 || height == 0 {
            return None;
        }
        Some(DesktopRect {
            x,
            y,
            width,
            height,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(x: u16, y: u16, width: u16, height: u16) -> DesktopRect {
        DesktopRect {
            x,
            y,
            width,
            height,
        }
    }

    /// 1280x768 → a 20x12 grid of 64px tiles.
    fn tracker() -> (DirtyTracker, Instant) {
        let mut t = DirtyTracker::new();
        t.resize(1280, 768);
        (t, Instant::now())
    }

    fn covers(rects: &[DesktopRect], x: u16, y: u16) -> bool {
        rects
            .iter()
            .any(|r| x >= r.x && x < r.x + r.width && y >= r.y && y < r.y + r.height)
    }

    #[test]
    fn settles_after_the_quiet_period() {
        let (mut t, t0) = tracker();
        t.touch(rect(0, 0, 128, 128), t0);

        assert!(
            t.take_settled(t0 + SETTLE - Duration::from_millis(1))
                .is_empty()
        );
        assert_eq!(t.take_settled(t0 + SETTLE), vec![rect(0, 0, 128, 128)]);
        // Refined once, then forgotten.
        assert!(t.take_settled(t0 + SETTLE * 10).is_empty());
    }

    /// The regression this grid exists for: a full-screen repaint followed by a clock
    /// ticking in the corner. Merging regions would reset the whole screen every second and
    /// never refine anything.
    #[test]
    fn a_busy_corner_does_not_hold_the_rest_of_the_screen_dirty() {
        let (mut t, t0) = tracker();
        t.touch(rect(0, 0, 1280, 768), t0);

        // Clock repaints every second, well inside the settle window.
        for tick in 1..=4 {
            t.touch(rect(1200, 730, 60, 20), t0 + Duration::from_secs(tick));
        }

        let settled = t.take_settled(t0 + SETTLE);
        assert!(!settled.is_empty(), "the quiet screen must still refine");
        assert!(covers(&settled, 0, 0), "top-left is quiet and must refine");
        assert!(
            covers(&settled, 640, 384),
            "the middle is quiet and must refine"
        );
        assert!(
            !covers(&settled, 1216, 736),
            "the ticking clock must not be refined while it is still changing"
        );
    }

    #[test]
    fn an_overlapping_update_resets_only_the_tiles_it_touches() {
        let (mut t, t0) = tracker();
        t.touch(rect(0, 0, 256, 64), t0);
        t.touch(rect(0, 0, 64, 64), t0 + Duration::from_secs(4));

        // The untouched remainder settles on the original schedule...
        let first = t.take_settled(t0 + SETTLE);
        assert!(covers(&first, 128, 0));
        assert!(!covers(&first, 0, 0));

        // ...and the re-touched tile settles 4s later.
        let second = t.take_settled(t0 + Duration::from_secs(9));
        assert!(covers(&second, 0, 0));
    }

    #[test]
    fn adjacent_settled_tiles_coalesce_into_one_rect() {
        let (mut t, t0) = tracker();
        t.touch(rect(0, 0, 256, 128), t0);
        assert_eq!(t.take_settled(t0 + SETTLE), vec![rect(0, 0, 256, 128)]);
    }

    #[test]
    fn disjoint_areas_settle_independently() {
        let (mut t, t0) = tracker();
        t.touch(rect(0, 0, 64, 64), t0);
        t.touch(rect(640, 384, 64, 64), t0 + Duration::from_secs(2));

        assert_eq!(t.take_settled(t0 + SETTLE), vec![rect(0, 0, 64, 64)]);
        assert_eq!(
            t.take_settled(t0 + Duration::from_secs(7)),
            vec![rect(640, 384, 64, 64)]
        );
    }

    #[test]
    fn next_due_is_the_earliest_deadline() {
        let (mut t, t0) = tracker();
        assert!(t.next_due().is_none());

        t.touch(rect(0, 0, 64, 64), t0);
        t.touch(rect(640, 0, 64, 64), t0 + Duration::from_secs(3));
        assert_eq!(t.next_due(), Some(t0 + SETTLE));

        t.take_settled(t0 + SETTLE);
        assert_eq!(t.next_due(), Some(t0 + Duration::from_secs(3) + SETTLE));
    }

    /// A partial edge tile must report only the pixels that exist, or the refinement would
    /// claim a rect wider than the surface.
    #[test]
    fn edge_tiles_are_clipped_to_the_surface() {
        let mut t = DirtyTracker::new();
        t.resize(100, 100);
        let t0 = Instant::now();
        t.touch(rect(0, 0, 100, 100), t0);
        assert_eq!(t.take_settled(t0 + SETTLE), vec![rect(0, 0, 100, 100)]);
    }

    #[test]
    fn touches_outside_the_surface_are_ignored() {
        let (mut t, t0) = tracker();
        t.touch(rect(0, 0, 0, 0), t0);
        t.touch(rect(2000, 2000, 64, 64), t0);
        assert!(t.next_due().is_none());
    }

    /// Before the first resize there is no grid; touching must not panic or record anything.
    #[test]
    fn touches_before_the_first_resize_are_ignored() {
        let mut t = DirtyTracker::new();
        t.touch(rect(0, 0, 64, 64), Instant::now());
        assert!(t.next_due().is_none());
    }

    /// Backends re-announce their size on reconnect; that must not silently cancel
    /// refinements that were already pending.
    #[test]
    fn a_resize_to_the_same_size_keeps_pending_regions() {
        let (mut t, t0) = tracker();
        t.touch(rect(0, 0, 128, 128), t0);
        t.resize(1280, 768);
        assert_eq!(t.take_settled(t0 + SETTLE), vec![rect(0, 0, 128, 128)]);
    }

    #[test]
    fn resize_drops_everything_tracked() {
        let (mut t, t0) = tracker();
        t.touch(rect(0, 0, 128, 128), t0);
        t.resize(800, 600);
        assert!(t.next_due().is_none());
        assert!(t.take_settled(t0 + SETTLE * 10).is_empty());
    }
}
