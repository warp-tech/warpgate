#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct Rect {
    pub x: usize,
    pub y: usize,
    pub width: usize,
    pub height: usize,
}

impl Rect {
    pub fn new(x: usize, y: usize, width: usize, height: usize) -> Self {
        Self { x, y, width, height }
    }

    #[must_use]
    pub fn add_xy(mut self, x: usize, y: usize) -> Self {
        self.x += x;
        self.y += y;
        self
    }

    fn intersect(&self, other: &Rect) -> Option<Rect> {
        let x = self.x.max(other.x);
        let y = self.y.max(other.y);
        let width = (self.x + self.width).min(other.x + other.width);
        if width <= x {
            return None;
        }
        let width = width - x;
        let height = (self.y + self.height).min(other.y + other.height);
        if height <= y {
            return None;
        }
        let height = height - y;

        Some(Rect::new(x, y, width, height))
    }
}

const TILE_SIZE: usize = 64;

fn find_different_tiles<const BPP: usize>(
    image1: &[u8],
    stride1: usize,
    image2: &[u8],
    stride2: usize,
    width: usize,
    height: usize,
) -> Vec<bool> {
    assert!(stride1 >= width * BPP);
    assert!(stride2 >= width * BPP);
    assert!(image1.len() >= (height - 1) * stride1 + width * BPP);
    assert!(image2.len() >= (height - 1) * stride2 + width * BPP);

    let tiles_x = width.div_ceil(TILE_SIZE);
    let tiles_y = height.div_ceil(TILE_SIZE);
    let mut tile_differences = vec![false; tiles_x * tiles_y];

    tile_differences.iter_mut().enumerate().for_each(|(idx, diff)| {
        let tile_start_x = (idx % tiles_x) * TILE_SIZE;
        let tile_end_x = (tile_start_x + TILE_SIZE).min(width);
        let tile_start_y = (idx / tiles_x) * TILE_SIZE;
        let tile_end_y = (tile_start_y + TILE_SIZE).min(height);

        // Check for any difference in tile using slice comparisons
        let has_diff = (tile_start_y..tile_end_y).any(|y| {
            let row_start1 = y * stride1;
            let row_start2 = y * stride2;
            let tile_row_start1 = row_start1 + tile_start_x * BPP;
            let tile_row_end1 = row_start1 + tile_end_x * BPP;
            let tile_row_start2 = row_start2 + tile_start_x * BPP;
            let tile_row_end2 = row_start2 + tile_end_x * BPP;

            image1[tile_row_start1..tile_row_end1] != image2[tile_row_start2..tile_row_end2]
        });

        *diff = has_diff;
    });

    tile_differences
}

fn find_different_rects<const BPP: usize>(
    image1: &[u8],
    stride1: usize,
    image2: &[u8],
    stride2: usize,
    width: usize,
    height: usize,
) -> Vec<Rect> {
    let mut tile_differences = find_different_tiles::<BPP>(image1, stride1, image2, stride2, width, height);

    let mod_width = width % TILE_SIZE;
    let mod_height = height % TILE_SIZE;
    let tiles_x = width.div_ceil(TILE_SIZE);
    let tiles_y = height.div_ceil(TILE_SIZE);

    let mut rectangles = Vec::new();
    let mut current_idx = 0;
    let total_tiles = tiles_x * tiles_y;

    // Process tiles in linear fashion to find rectangular regions
    while current_idx < total_tiles {
        if !tile_differences[current_idx] {
            current_idx += 1;
            continue;
        }

        let start_y = current_idx / tiles_x;
        let start_x = current_idx % tiles_x;

        // Expand horizontally as much as possible
        let mut max_width = 1;
        while start_x + max_width < tiles_x && tile_differences[current_idx + max_width] {
            max_width += 1;
        }

        // Expand vertically as much as possible
        let mut max_height = 1;
        'vertical: while start_y + max_height < tiles_y {
            for x in 0..max_width {
                let check_idx = (start_y + max_height) * tiles_x + start_x + x;
                if !tile_differences[check_idx] {
                    break 'vertical;
                }
            }
            max_height += 1;
        }

        // Calculate pixel coordinates
        let pixel_x = start_x * TILE_SIZE;
        let pixel_y = start_y * TILE_SIZE;

        let pixel_width = if start_x + max_width == tiles_x && mod_width > 0 {
            (max_width - 1) * TILE_SIZE + mod_width
        } else {
            max_width * TILE_SIZE
        };

        let pixel_height = if start_y + max_height == tiles_y && mod_height > 0 {
            (max_height - 1) * TILE_SIZE + mod_height
        } else {
            max_height * TILE_SIZE
        };

        rectangles.push(Rect {
            x: pixel_x,
            y: pixel_y,
            width: pixel_width,
            height: pixel_height,
        });

        // Mark tiles as processed
        for y in 0..max_height {
            for x in 0..max_width {
                let idx = (start_y + y) * tiles_x + start_x + x;
                tile_differences[idx] = false;
            }
        }

        current_idx += max_width;
    }

    rectangles
}

/// Helper function to find different regions in two images.
///
/// This function takes two images as input and returns a list of rectangles
/// representing the different regions between the two images, in image2 coordinates.
///
/// ```text
///     ┌───────────────────────────────────────────┐
///     │ image1                                    │
///     │                                           │
///     │                    (x,y)                  │
///     │                     ┌───────────────┐     │
///     │                     │ image2        │     │
///     │                     │               │     │
///     │                     │               │     │
///     │                     │               │     │
///     │                     │               │     │
///     │                     │               │     │
///     │                     └───────────────┘     │
///     │                                           │
///     └───────────────────────────────────────────┘
/// ```
#[expect(clippy::too_many_arguments)]
pub fn find_different_rects_sub<const BPP: usize>(
    image1: &[u8],
    stride1: usize,
    width1: usize,
    height1: usize,
    image2: &[u8],
    stride2: usize,
    width2: usize,
    height2: usize,
    x: usize,
    y: usize,
) -> Vec<Rect> {
    let rect1 = Rect::new(0, 0, width1, height1);
    let rect2 = Rect::new(x, y, width2, height2);
    let Some(inter) = rect1.intersect(&rect2) else {
        return vec![];
    };

    let image1 = &image1[y * stride1 + x * BPP..];
    find_different_rects::<BPP>(image1, stride1, image2, stride2, inter.width, inter.height)
}

#[cfg(test)]
mod tests {
    use bytemuck::cast_slice;

    use super::*;

    #[test]
    fn test_intersect() {
        let r1 = Rect::new(0, 0, 640, 480);
        let r2 = Rect::new(10, 10, 10, 10);
        let r3 = Rect::new(630, 470, 20, 20);

        assert_eq!(r1.intersect(&r1).as_ref(), Some(&r1));
        assert_eq!(r1.intersect(&r2).as_ref(), Some(&r2));
        assert_eq!(r1.intersect(&r3), Some(Rect::new(630, 470, 10, 10)));
        assert_eq!(r2.intersect(&r3), None);
    }

    #[test]
    fn test_single_tile() {
        const SIZE: usize = 128;
        let image1 = vec![0u32; SIZE * SIZE];
        let mut image2 = vec![0u32; SIZE * SIZE];
        image2[65 * 128 + 65] = 1;
        let result =
            find_different_rects::<4>(cast_slice(&image1), SIZE * 4, cast_slice(&image2), SIZE * 4, SIZE, SIZE);
        assert_eq!(
            result,
            vec![Rect {
                x: 64,
                y: 64,
                width: 64,
                height: 64
            }]
        );
    }

    #[test]
    fn test_adjacent_tiles() {
        const SIZE: usize = 256;
        let image1 = vec![0u32; SIZE * SIZE];
        let mut image2 = vec![0u32; SIZE * SIZE];
        // Modify two adjacent tiles
        image2[65 * SIZE + 65] = 1;
        image2[65 * SIZE + 129] = 1;
        let result =
            find_different_rects::<4>(cast_slice(&image1), SIZE * 4, cast_slice(&image2), SIZE * 4, SIZE, SIZE);
        assert_eq!(
            result,
            vec![Rect {
                x: 64,
                y: 64,
                width: 128,
                height: 64
            }]
        );
    }

    #[test]
    fn test_edge_tiles() {
        const SIZE: usize = 100;
        let image1 = vec![0u32; SIZE * SIZE];
        let mut image2 = vec![0u32; SIZE * SIZE];
        image2[65 * SIZE + 65] = 1;
        let result =
            find_different_rects::<4>(cast_slice(&image1), SIZE * 4, cast_slice(&image2), SIZE * 4, SIZE, SIZE);
        assert_eq!(
            result,
            vec![Rect {
                x: 64,
                y: 64,
                width: 36,
                height: 36
            }]
        );
    }

    #[test]
    fn test_large() {
        const SIZE: usize = 4096;
        let image1 = vec![0u32; SIZE * SIZE];
        let mut image2 = vec![0u32; SIZE * SIZE];
        image2[95 * 100 + 95] = 1;
        let _result =
            find_different_rects::<4>(cast_slice(&image1), SIZE * 4, cast_slice(&image2), SIZE * 4, SIZE, SIZE);
    }

    #[test]
    fn test_sub_diff() {
        let image1 = vec![0u32; 2048 * 2048];
        let mut image2 = vec![0u32; 1024 * 1024];
        image2[0] = 1;
        image2[1024 * 65 + 512 - 1] = 1;

        let res = find_different_rects_sub::<4>(
            cast_slice(&image1),
            2048 * 4,
            2048,
            2048,
            cast_slice(&image2),
            1024 * 4,
            512,
            512,
            1024,
            1024,
        );
        assert_eq!(
            res,
            vec![
                Rect {
                    x: 0,
                    y: 0,
                    width: 64,
                    height: 64
                },
                Rect {
                    x: 448,
                    y: 64,
                    width: 64,
                    height: 64
                }
            ]
        )
    }
}
