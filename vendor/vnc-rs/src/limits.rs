use crate::{Rect, VncError};
use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) const MAX_PIXELS: usize = 8_294_400;
pub(crate) const MAX_DIMENSION: u16 = 8192;
pub(crate) const MAX_COMPRESSED: usize = 64 * 1024 * 1024;
pub(crate) const MAX_TEXT: usize = 1024 * 1024;
pub(crate) const MAX_NAME: usize = 4096;

pub(crate) fn dimensions(width: u16, height: u16) -> Result<(), VncError> {
    if width == 0
        || height == 0
        || width > MAX_DIMENSION
        || height > MAX_DIMENSION
        || usize::from(width) * usize::from(height) > MAX_PIXELS
    {
        return Err(VncError::InvalidImageData);
    }
    Ok(())
}

pub(crate) fn rectangle(rect: &Rect, screen: (u16, u16)) -> Result<(), VncError> {
    dimensions(rect.width, rect.height)?;
    if u32::from(rect.x) + u32::from(rect.width) > u32::from(screen.0)
        || u32::from(rect.y) + u32::from(rect.height) > u32::from(screen.1)
    {
        return Err(VncError::InvalidImageData);
    }
    Ok(())
}

pub(crate) async fn string<S: AsyncRead + Unpin>(
    reader: &mut S,
    limit: usize,
) -> Result<String, VncError> {
    let length = reader.read_u32().await? as usize;
    if length > limit {
        return Err(VncError::General("VNC string exceeds size limit".into()));
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes).await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}
