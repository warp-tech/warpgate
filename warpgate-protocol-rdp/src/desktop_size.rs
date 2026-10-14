use tracing::warn;
use warpgate_desktop_ui::DEFAULT_SIZE;

pub(crate) const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MIN_DESKTOP_DIM: u16 = 200; // MS-RDPBCGR limit
pub(crate) const MAX_DESKTOP_DIM: u16 = 8192; // our limit

pub(crate) fn bound_desktop_size(width: u16, height: u16) -> (u16, u16) {
    let width = width.clamp(MIN_DESKTOP_DIM, MAX_DESKTOP_DIM);
    let height = height.clamp(MIN_DESKTOP_DIM, MAX_DESKTOP_DIM);
    if usize::from(width) * usize::from(height) * 4 > MAX_FRAME_BYTES {
        warn!(
            width,
            height, "viewer requested a desktop too large to frame; using the default"
        );
        return DEFAULT_SIZE;
    }
    (width, height)
}
