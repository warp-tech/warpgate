use core::cmp::{max, min};

use ironrdp_core::{Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, ensure_fixed_part_size};

pub(crate) mod private {
    pub struct BaseRectangle {
        pub left: u16,
        pub top: u16,
        pub right: u16,
        pub bottom: u16,
    }

    impl BaseRectangle {
        pub fn empty() -> Self {
            Self {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            }
        }
    }

    pub trait RectangleImpl: Sized {
        fn from_base(rect: BaseRectangle) -> Self;
        fn to_base(&self) -> BaseRectangle;

        fn left(&self) -> u16;
        fn top(&self) -> u16;
        fn right(&self) -> u16;
        fn bottom(&self) -> u16;
    }
}

use private::{BaseRectangle, RectangleImpl};

pub trait Rectangle: RectangleImpl {
    fn width(&self) -> u16;
    fn height(&self) -> u16;

    fn empty() -> Self {
        Self::from_base(BaseRectangle::empty())
    }

    fn union_all(rectangles: &[Self]) -> Self {
        Self::from_base(BaseRectangle {
            left: rectangles.iter().map(|r| r.left()).min().unwrap_or(0),
            top: rectangles.iter().map(|r| r.top()).min().unwrap_or(0),
            right: rectangles.iter().map(|r| r.right()).max().unwrap_or(0),
            bottom: rectangles.iter().map(|r| r.bottom()).max().unwrap_or(0),
        })
    }

    fn intersect(&self, other: &Self) -> Option<Self> {
        let a = self.to_base();
        let b = other.to_base();

        let result = BaseRectangle {
            left: max(a.left, b.left),
            top: max(a.top, b.top),
            right: min(a.right, b.right),
            bottom: min(a.bottom, b.bottom),
        };

        if result.left <= result.right && result.top <= result.bottom {
            Some(Self::from_base(result))
        } else {
            None
        }
    }

    #[must_use]
    fn union(&self, other: &Self) -> Self {
        let a = self.to_base();
        let b = other.to_base();

        let result = BaseRectangle {
            left: min(a.left, b.left),
            top: min(a.top, b.top),
            right: max(a.right, b.right),
            bottom: max(a.bottom, b.bottom),
        };

        Self::from_base(result)
    }
}

/// An **inclusive** rectangle.
///
/// This struct is defined as an **inclusive** rectangle.
/// That is, the pixel at coordinate (right, bottom) is included in the rectangle.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct InclusiveRectangle {
    pub left: u16,
    pub top: u16,
    pub right: u16,
    pub bottom: u16,
}

/// An **exclusive** rectangle.
/// This struct is defined as an **exclusive** rectangle.
/// That is, the pixel at coordinate (right, bottom) is not included in the rectangle.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ExclusiveRectangle {
    pub left: u16,
    pub top: u16,
    pub right: u16,
    pub bottom: u16,
}

macro_rules! impl_rectangle {
    ($type:ty) => {
        impl RectangleImpl for $type {
            fn from_base(rect: BaseRectangle) -> Self {
                Self {
                    left: rect.left,
                    top: rect.top,
                    right: rect.right,
                    bottom: rect.bottom,
                }
            }

            fn to_base(&self) -> BaseRectangle {
                BaseRectangle {
                    left: self.left,
                    top: self.top,
                    right: self.right,
                    bottom: self.bottom,
                }
            }

            fn left(&self) -> u16 {
                self.left
            }
            fn top(&self) -> u16 {
                self.top
            }
            fn right(&self) -> u16 {
                self.right
            }
            fn bottom(&self) -> u16 {
                self.bottom
            }
        }
    };
}

impl_rectangle!(InclusiveRectangle);
impl_rectangle!(ExclusiveRectangle);

impl Rectangle for InclusiveRectangle {
    /// INVARIANT: `0 < output (width)`
    fn width(&self) -> u16 {
        self.right - self.left + 1
    }

    /// INVARIANT: `0 < output (height)`
    fn height(&self) -> u16 {
        self.bottom - self.top + 1
    }
}

impl Rectangle for ExclusiveRectangle {
    fn width(&self) -> u16 {
        self.right - self.left
    }

    fn height(&self) -> u16 {
        self.bottom - self.top
    }
}

impl InclusiveRectangle {
    const NAME: &'static str = "InclusiveRectangle";

    pub const FIXED_PART_SIZE: usize = 2 /* left */ + 2 /* top */ + 2 /* right */ + 2 /* bottom */;

    pub const ENCODED_SIZE: usize = Self::FIXED_PART_SIZE;
}

impl Encode for InclusiveRectangle {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(self.left);
        dst.write_u16(self.top);
        dst.write_u16(self.right);
        dst.write_u16(self.bottom);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for InclusiveRectangle {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let left = src.read_u16();
        let top = src.read_u16();
        let right = src.read_u16();
        let bottom = src.read_u16();

        Ok(Self {
            left,
            top,
            right,
            bottom,
        })
    }
}

impl ExclusiveRectangle {
    const NAME: &'static str = "ExclusiveRectangle";
    const FIXED_PART_SIZE: usize = 2 /* left */ + 2 /* top */ + 2 /* right */ + 2 /* bottom */;

    pub const ENCODED_SIZE: usize = Self::FIXED_PART_SIZE;
}

impl Encode for ExclusiveRectangle {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(self.left);
        dst.write_u16(self.top);
        dst.write_u16(self.right);
        dst.write_u16(self.bottom);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for ExclusiveRectangle {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let left = src.read_u16();
        let top = src.read_u16();
        let right = src.read_u16();
        let bottom = src.read_u16();

        Ok(Self {
            left,
            top,
            right,
            bottom,
        })
    }
}
