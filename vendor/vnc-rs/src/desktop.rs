//! Negotiated desktop layout and resize results. Geometry is always server-confirmed.
use crate::{limits::dimensions, Rect, VncError};
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScreenLayout {
    pub id: u32,
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopLayout {
    pub width: u16,
    pub height: u16,
    pub screens: Vec<ScreenLayout>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopReason {
    Server,
    ThisClient,
    OtherClient,
    Unknown(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopStatus {
    Success,
    Prohibited,
    OutOfResources,
    InvalidLayout,
    Forwarded,
    Unknown(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopUpdate {
    pub reason: DesktopReason,
    pub status: DesktopStatus,
    /// Absent on failed/forwarded replies, whose geometry is undefined on the wire.
    pub layout: Option<DesktopLayout>,
}

// Bound retained layouts, including each screen allocation, while accepting queued
// single-screen updates across the full u16 framebuffer rectangle count.
#[derive(Default)]
pub(crate) struct UpdateBatch {
    updates: Vec<DesktopUpdate>,
    retained_bytes: usize,
}

impl UpdateBatch {
    const MAX_RETAINED_BYTES: usize = 4 * 1024 * 1024;

    pub(crate) fn push(&mut self, update: DesktopUpdate) -> Result<(), VncError> {
        let screens = update
            .layout
            .as_ref()
            .map_or(0, |layout| layout.screens.capacity());
        let bytes = screens
            .checked_mul(std::mem::size_of::<ScreenLayout>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<DesktopUpdate>()))
            .and_then(|bytes| bytes.checked_add(self.retained_bytes))
            .filter(|bytes| *bytes <= Self::MAX_RETAINED_BYTES)
            .ok_or(VncError::InvalidImageData)?;
        self.updates.push(update);
        self.retained_bytes = bytes;
        Ok(())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.updates.is_empty()
    }

    pub(crate) fn into_updates(self) -> Vec<DesktopUpdate> {
        self.updates
    }
}

impl DesktopLayout {
    pub(crate) fn validate(&self) -> Result<(), VncError> {
        dimensions(self.width, self.height)?;
        if self.screens.len() > 255 {
            return Err(VncError::InvalidImageData);
        }
        for (index, s) in self.screens.iter().enumerate() {
            if s.width == 0
                || s.height == 0
                || u32::from(s.x) + u32::from(s.width) > u32::from(self.width)
                || u32::from(s.y) + u32::from(s.height) > u32::from(self.height)
            {
                return Err(VncError::InvalidImageData);
            }
            if self.screens[..index].iter().any(|other| other.id == s.id) {
                return Err(VncError::InvalidImageData);
            }
        }
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn resized(&self, width: u16, height: u16) -> Result<Self, ResizeError> {
        dimensions(width, height).map_err(|_| ResizeError::InvalidDimensions)?;
        let [screen] = self.screens.as_slice() else {
            return Err(ResizeError::UnsupportedLayout);
        };
        if screen.x != 0
            || screen.y != 0
            || screen.width != self.width
            || screen.height != self.height
        {
            return Err(ResizeError::UnsupportedLayout);
        }
        Ok(Self {
            width,
            height,
            screens: vec![ScreenLayout {
                width,
                height,
                ..*screen
            }],
        })
    }
}

impl DesktopUpdate {
    pub(crate) async fn read<S: AsyncRead + Unpin>(
        reader: &mut S,
        rect: Rect,
    ) -> Result<Self, VncError> {
        let count = reader.read_u8().await?;
        let mut padding = [0; 3];
        reader.read_exact(&mut padding).await?;
        let mut screens = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            screens.push(ScreenLayout {
                id: reader.read_u32().await?,
                x: reader.read_u16().await?,
                y: reader.read_u16().await?,
                width: reader.read_u16().await?,
                height: reader.read_u16().await?,
                flags: reader.read_u32().await?,
            });
        }
        let reason = match rect.x {
            0 => DesktopReason::Server,
            1 => DesktopReason::ThisClient,
            2 => DesktopReason::OtherClient,
            n => DesktopReason::Unknown(n),
        };
        let status = if reason != DesktopReason::ThisClient {
            DesktopStatus::Success
        } else {
            match rect.y {
                0 => DesktopStatus::Success,
                1 => DesktopStatus::Prohibited,
                2 => DesktopStatus::OutOfResources,
                3 => DesktopStatus::InvalidLayout,
                4 => DesktopStatus::Forwarded,
                n => DesktopStatus::Unknown(n),
            }
        };
        let layout = if status == DesktopStatus::Success {
            let layout = DesktopLayout {
                width: rect.width,
                height: rect.height,
                screens,
            };
            layout.validate()?;
            Some(layout)
        } else {
            None
        };
        Ok(Self {
            reason,
            status,
            layout,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResizeError {
    #[error("server has not advertised desktop resizing")]
    Unsupported,
    #[error("only a single screen covering the desktop can be resized")]
    UnsupportedLayout,
    #[error("desktop dimensions exceed decoder limits")]
    InvalidDimensions,
    #[error("another resize is pending")]
    Busy,
    #[error("resize denied: {0:?}")]
    Denied(DesktopStatus),
    #[error("resize could not be dispatched before the deadline")]
    DispatchTimeout,
    #[error("resize was not confirmed before the deadline; do not retry blindly")]
    Timeout,
    #[error("resize outcome is uncertain; reconnect and observe before retrying")]
    Uncertain,
    #[error("connection closed before resize could be dispatched")]
    Disconnected,
}
