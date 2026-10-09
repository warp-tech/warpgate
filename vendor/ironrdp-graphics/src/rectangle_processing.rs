use core::cmp::{max, min};

use ironrdp_pdu::geometry::{InclusiveRectangle, Rectangle as _};

// TODO(@pacmancoder): This code currently works only on `InclusiveRectangle`, but it should be
// made generic over `Rectangle` trait

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region {
    pub extents: InclusiveRectangle,
    pub rectangles: Vec<InclusiveRectangle>,
}

impl Region {
    pub fn new() -> Self {
        Self {
            extents: InclusiveRectangle::empty(),
            rectangles: Vec::new(),
        }
    }

    pub fn union_rectangle(&mut self, rectangle: InclusiveRectangle) {
        if self.rectangles.is_empty() {
            *self = Self::from(rectangle);
        } else {
            let mut dst = Vec::with_capacity(self.rectangles.len() + 1);

            handle_rectangle_higher_relative_to_extents(&rectangle, &self.extents, &mut dst);

            // treat possibly overlapping region
            let bands = split_bands(self.rectangles.as_slice());
            let mut bands = bands.as_slice();
            while let Some((band, bands_new)) = bands.split_first() {
                bands = bands_new;

                let top_inter_band = if band[0].bottom <= rectangle.top
                    || rectangle.bottom <= band[0].top
                    || rectangle_in_band(band, &rectangle)
                {
                    // `rectangle` is lower, higher, or in the current band
                    dst.extend_from_slice(band);

                    rectangle.top
                } else {
                    handle_rectangle_that_overlaps_band(&rectangle, band, &mut dst);

                    band[0].bottom
                };

                if !bands.is_empty() {
                    let next_band = bands[0];
                    handle_rectangle_between_bands(&rectangle, band, next_band, &mut dst, top_inter_band);
                }
            }

            handle_rectangle_lower_relative_to_extents(&rectangle, &self.extents, &mut dst);

            self.rectangles = dst;
            self.extents = self.extents.union(&rectangle);

            self.simplify();
        }
    }

    #[must_use]
    pub fn intersect_rectangle(&self, rectangle: &InclusiveRectangle) -> Self {
        match self.rectangles.len() {
            0 => Self::new(),
            1 => self.extents.intersect(rectangle).map(Self::from).unwrap_or_default(),
            _ => {
                let rectangles = self
                    .rectangles
                    .iter()
                    .take_while(|r| r.top <= rectangle.bottom)
                    .filter_map(|r| r.intersect(rectangle))
                    .collect::<Vec<_>>();
                let extents = InclusiveRectangle::union_all(rectangles.as_slice());

                let mut region = Self { rectangles, extents };
                region.simplify();

                region
            }
        }
    }

    fn simplify(&mut self) {
        /* Simplify consecutive bands that touch and have the same items
         *
         *  ====================          ====================
         *     | 1 |  | 2   |               |   |  |     |
         *  ====================            |   |  |     |
         *     | 1 |  | 2   |	   ====>    | 1 |  |  2  |
         *  ====================            |   |  |     |
         *     | 1 |  | 2   |               |   |  |     |
         *  ====================          ====================
         *
         */

        if self.rectangles.len() < 2 {
            return;
        }

        let mut current_band_start = 0;
        while current_band_start < self.rectangles.len()
            && current_band_start + get_current_band(&self.rectangles[current_band_start..]).len()
                < self.rectangles.len()
        {
            let current_band = get_current_band(&self.rectangles[current_band_start..]);
            let next_band = get_current_band(&self.rectangles[current_band_start + current_band.len()..]);

            if current_band[0].bottom == next_band[0].top && bands_internals_equal(current_band, next_band) {
                let first_band_len = current_band.len();
                let second_band_len = next_band.len();
                let second_band_bottom = next_band[0].bottom;
                self.rectangles
                    .drain(current_band_start + first_band_len..current_band_start + first_band_len + second_band_len);
                self.rectangles
                    .iter_mut()
                    .skip(current_band_start)
                    .take(first_band_len)
                    .for_each(|r| r.bottom = second_band_bottom);
            } else {
                current_band_start += current_band.len();
            }
        }
    }
}

impl Default for Region {
    fn default() -> Self {
        Self::new()
    }
}

impl From<InclusiveRectangle> for Region {
    fn from(r: InclusiveRectangle) -> Self {
        Self {
            extents: r.clone(),
            rectangles: vec![r],
        }
    }
}

fn handle_rectangle_higher_relative_to_extents(
    rectangle: &InclusiveRectangle,
    extents: &InclusiveRectangle,
    dst: &mut Vec<InclusiveRectangle>,
) {
    if rectangle.top < extents.top {
        dst.push(InclusiveRectangle {
            top: rectangle.top,
            bottom: min(extents.top, rectangle.bottom),
            left: rectangle.left,
            right: rectangle.right,
        });
    }
}

fn handle_rectangle_lower_relative_to_extents(
    rectangle: &InclusiveRectangle,
    extents: &InclusiveRectangle,
    dst: &mut Vec<InclusiveRectangle>,
) {
    if extents.bottom < rectangle.bottom {
        dst.push(InclusiveRectangle {
            top: max(extents.bottom, rectangle.top),
            bottom: rectangle.bottom,
            left: rectangle.left,
            right: rectangle.right,
        });
    }
}

fn handle_rectangle_that_overlaps_band(
    rectangle: &InclusiveRectangle,
    band: &[InclusiveRectangle],
    dst: &mut Vec<InclusiveRectangle>,
) {
    /* rect overlaps the band:
                         |    |  |    |
       ====^=================|    |==|    |=========================== band
       |   top split     |    |  |    |
       v                 | 1  |  | 2  |
       ^                 |    |  |    |  +----+   +----+
       |   merge zone    |    |  |    |  |    |   | 4  |
       v                 +----+  |    |  |    |   +----+
       ^                         |    |  | 3  |
       |   bottom split          |    |  |    |
       ====v=========================|    |==|    |===================
                                 |    |  |    |

        possible cases:
        1) no top split, merge zone then a bottom split. The band will be split
           in two
        2) not band split, only the merge zone, band merged with rect but not split
        3) a top split, the merge zone and no bottom split. The band will be split
           in two
        4) a top split, the merge zone and also a bottom split. The band will be
           split in 3, but the coalesce algorithm may merge the created bands
    */

    let band_top = band[0].top;
    let band_bottom = band[0].bottom;

    if band_top < rectangle.top {
        // split current band by the current band top and `rectangle.top` (case 3, 4)
        copy_band(band, dst, band_top, rectangle.top);
    }

    // split the merge zone (all cases)
    copy_band_with_union(
        band,
        dst,
        max(rectangle.top, band_top),
        min(rectangle.bottom, band_bottom),
        rectangle,
    );

    // split current band by the `rectangle.bottom` and the current band bottom (case 1, 4)
    if rectangle.bottom < band_bottom {
        copy_band(band, dst, rectangle.bottom, band_bottom);
    }
}

fn handle_rectangle_between_bands(
    rectangle: &InclusiveRectangle,
    band: &[InclusiveRectangle],
    next_band: &[InclusiveRectangle],
    dst: &mut Vec<InclusiveRectangle>,
    top_inter_band: u16,
) {
    /* test if a piece of rect should be inserted as a new band between
     * the current band and the next one. band n and n+1 shouldn't touch.
     *
     * ==============================================================
     *                                                        band n
     *            +------+                    +------+
     * ===========| rect |====================|      |===============
     *            |      |    +------+        |      |
     *            +------+    | rect |        | rect |
     *                        +------+        |      |
     * =======================================|      |================
     *                                        +------+         band n+1
     * ===============================================================
     *
     */

    let band_bottom = band[0].bottom;

    let next_band_top = next_band[0].top;
    if next_band_top != band_bottom && band_bottom < rectangle.bottom && rectangle.top < next_band_top {
        dst.push(InclusiveRectangle {
            top: top_inter_band,
            bottom: min(next_band_top, rectangle.bottom),
            left: rectangle.left,
            right: rectangle.right,
        });
    }
}

fn rectangle_in_band(band: &[InclusiveRectangle], rectangle: &InclusiveRectangle) -> bool {
    // part of `rectangle` is higher or lower
    if rectangle.top < band[0].top || band[0].bottom < rectangle.bottom {
        return false;
    }

    for source_rectangle in band {
        if source_rectangle.left <= rectangle.left {
            if rectangle.right <= source_rectangle.right {
                return true;
            }
        } else {
            // as the band is sorted from left to right,
            // once we've seen an item that is after `rectangle.left`
            // we are sure that the result is false
            return false;
        }
    }

    false
}

fn copy_band_with_union(
    mut band: &[InclusiveRectangle],
    dst: &mut Vec<InclusiveRectangle>,
    band_top: u16,
    band_bottom: u16,
    union_rectangle: &InclusiveRectangle,
) {
    /* merges a band with the given rect
     * Input:
     *                   unionRect
     *               |                |
     *               |                |
     * ==============+===============+================================
     *   |Item1|  |Item2| |Item3|  |Item4|    |Item5|            Band
     * ==============+===============+================================
     *    before     |    overlap     |          after
     *
     * Resulting band:
     *   +-----+  +----------------------+    +-----+
     *   |Item1|  |      Item2           |    |Item3|
     *   +-----+  +----------------------+    +-----+
     *
     *  We first copy as-is items that are before Item2, the first overlapping
     *  item.
     *  Then we find the last one that overlap unionRect to aggregate Item2, Item3
     *  and Item4 to create Item2.
     *  Finally Item5 is copied as Item3.
     *
     *  When no unionRect is provided, we skip the two first steps to just copy items
     */

    let items_before_union_rectangle = band
        .iter()
        .map(|r| InclusiveRectangle {
            top: band_top,
            bottom: band_bottom,
            left: r.left,
            right: r.right,
        })
        .take_while(|r| r.right < union_rectangle.left);
    let items_before_union_rectangle_len = items_before_union_rectangle.clone().map(|_| 1).sum::<usize>();
    dst.extend(items_before_union_rectangle);
    band = &band[items_before_union_rectangle_len..];

    // treat items overlapping with `union_rectangle`
    let left = min(
        band.first().map(|r| r.left).unwrap_or(union_rectangle.left),
        union_rectangle.left,
    );
    let mut right = union_rectangle.right;
    while !band.is_empty() {
        if band[0].right >= union_rectangle.right {
            if band[0].left < union_rectangle.right {
                right = band[0].right;
                band = &band[1..];
            }
            break;
        }
        band = &band[1..];
    }
    dst.push(InclusiveRectangle {
        top: band_top,
        bottom: band_bottom,
        left,
        right,
    });

    // treat remaining items on the same band
    copy_band(band, dst, band_top, band_bottom);
}

fn copy_band(band: &[InclusiveRectangle], dst: &mut Vec<InclusiveRectangle>, band_top: u16, band_bottom: u16) {
    dst.extend(band.iter().map(|r| InclusiveRectangle {
        top: band_top,
        bottom: band_bottom,
        left: r.left,
        right: r.right,
    }));
}

fn split_bands(mut rectangles: &[InclusiveRectangle]) -> Vec<&[InclusiveRectangle]> {
    let mut bands = Vec::new();
    while !rectangles.is_empty() {
        let band = get_current_band(rectangles);
        rectangles = &rectangles[band.len()..];
        bands.push(band);
    }

    bands
}

fn get_current_band(rectangles: &[InclusiveRectangle]) -> &[InclusiveRectangle] {
    let band_top = rectangles[0].top;

    for i in 1..rectangles.len() {
        if rectangles[i].top != band_top {
            return &rectangles[..i];
        }
    }

    rectangles
}

fn bands_internals_equal(first_band: &[InclusiveRectangle], second_band: &[InclusiveRectangle]) -> bool {
    if first_band.len() != second_band.len() {
        return false;
    }

    for (first_band_rect, second_band_rect) in first_band.iter().zip(second_band.iter()) {
        if first_band_rect.left != second_band_rect.left || first_band_rect.right != second_band_rect.right {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use super::*;

    static REGION_FOR_RECTANGLES_INTERSECTION: LazyLock<Region> = LazyLock::new(|| Region {
        extents: InclusiveRectangle {
            left: 1,
            top: 1,
            right: 11,
            bottom: 9,
        },
        rectangles: vec![
            InclusiveRectangle {
                left: 1,
                top: 1,
                right: 5,
                bottom: 3,
            },
            InclusiveRectangle {
                left: 7,
                top: 1,
                right: 8,
                bottom: 3,
            },
            InclusiveRectangle {
                left: 9,
                top: 1,
                right: 11,
                bottom: 3,
            },
            InclusiveRectangle {
                left: 7,
                top: 3,
                right: 11,
                bottom: 4,
            },
            InclusiveRectangle {
                left: 3,
                top: 4,
                right: 6,
                bottom: 6,
            },
            InclusiveRectangle {
                left: 7,
                top: 4,
                right: 11,
                bottom: 6,
            },
            InclusiveRectangle {
                left: 1,
                top: 6,
                right: 3,
                bottom: 8,
            },
            InclusiveRectangle {
                left: 4,
                top: 6,
                right: 5,
                bottom: 8,
            },
            InclusiveRectangle {
                left: 6,
                top: 6,
                right: 10,
                bottom: 8,
            },
            InclusiveRectangle {
                left: 4,
                top: 8,
                right: 5,
                bottom: 9,
            },
            InclusiveRectangle {
                left: 6,
                top: 8,
                right: 10,
                bottom: 9,
            },
        ],
    });

    #[test]
    fn union_rectangle_sets_extents_and_single_rectangle_for_empty_region() {
        let mut region = Region::new();

        let input_rectangle = InclusiveRectangle {
            left: 5,
            top: 1,
            right: 9,
            bottom: 2,
        };

        let expected_region = Region {
            extents: input_rectangle.clone(),
            rectangles: vec![input_rectangle.clone()],
        };

        region.union_rectangle(input_rectangle);
        assert_eq!(expected_region, region);
    }

    #[test]
    fn union_rectangle_places_new_rectangle_higher_relative_to_band() {
        let existing_band_rectangle = InclusiveRectangle {
            left: 2,
            top: 3,
            right: 7,
            bottom: 7,
        };
        let mut region = Region {
            extents: existing_band_rectangle.clone(),
            rectangles: vec![existing_band_rectangle.clone()],
        };

        let input_rectangle = InclusiveRectangle {
            left: 5,
            top: 1,
            right: 9,
            bottom: 2,
        };

        let expected_region = Region {
            extents: InclusiveRectangle {
                left: 2,
                top: 1,
                right: 9,
                bottom: 7,
            },
            rectangles: vec![input_rectangle.clone(), existing_band_rectangle],
        };

        region.union_rectangle(input_rectangle);
        assert_eq!(expected_region, region);
    }

    #[test]
    fn union_rectangle_places_new_rectangle_lower_relative_to_band() {
        let existing_band_rectangle = InclusiveRectangle {
            left: 2,
            top: 3,
            right: 7,
            bottom: 7,
        };
        let mut region = Region {
            extents: existing_band_rectangle.clone(),
            rectangles: vec![existing_band_rectangle.clone()],
        };

        let input_rectangle = InclusiveRectangle {
            left: 1,
            top: 8,
            right: 4,
            bottom: 10,
        };

        let expected_region = Region {
            extents: InclusiveRectangle {
                left: 1,
                top: 3,
                right: 7,
                bottom: 10,
            },
            rectangles: vec![existing_band_rectangle, input_rectangle.clone()],
        };

        region.union_rectangle(input_rectangle);
        assert_eq!(expected_region, region);
    }

    #[test]
    fn union_rectangle_does_not_add_new_rectangle_which_is_inside_a_band() {
        let existing_band_rectangle = InclusiveRectangle {
            left: 2,
            top: 3,
            right: 7,
            bottom: 7,
        };
        let mut region = Region {
            extents: existing_band_rectangle.clone(),
            rectangles: vec![existing_band_rectangle.clone()],
        };

        let input_rectangle = InclusiveRectangle {
            left: 5,
            top: 4,
            right: 6,
            bottom: 5,
        };

        let expected_region = Region {
            extents: existing_band_rectangle.clone(),
            rectangles: vec![existing_band_rectangle],
        };

        region.union_rectangle(input_rectangle);
        assert_eq!(expected_region, region);
    }

    #[test]
    fn union_rectangle_cuts_new_rectangle_top_part_which_crosses_band_on_top() {
        let existing_band_rectangle = InclusiveRectangle {
            left: 2,
            top: 3,
            right: 7,
            bottom: 7,
        };
        let mut region = Region {
            extents: existing_band_rectangle.clone(),
            rectangles: vec![existing_band_rectangle],
        };

        let input_rectangle = InclusiveRectangle {
            left: 1,
            top: 2,
            right: 4,
            bottom: 4,
        };

        let expected_region = Region {
            extents: InclusiveRectangle {
                left: 1,
                top: 2,
                right: 7,
                bottom: 7,
            },
            rectangles: vec![
                InclusiveRectangle {
                    left: 1,
                    top: 2,
                    right: 4,
                    bottom: 3,
                },
                InclusiveRectangle {
                    left: 1,
                    top: 3,
                    right: 7,
                    bottom: 4,
                },
                InclusiveRectangle {
                    left: 2,
                    top: 4,
                    right: 7,
                    bottom: 7,
                },
            ],
        };

        region.union_rectangle(input_rectangle);
        assert_eq!(expected_region, region);
    }

    #[test]
    fn union_rectangle_cuts_new_rectangle_lower_part_which_crosses_band_on_bottom() {
        let existing_band_rectangle = InclusiveRectangle {
            left: 2,
            top: 3,
            right: 7,
            bottom: 7,
        };
        let mut region = Region {
            extents: existing_band_rectangle.clone(),
            rectangles: vec![existing_band_rectangle],
        };

        let input_rectangle = InclusiveRectangle {
            left: 5,
            top: 6,
            right: 9,
            bottom: 8,
        };

        let expected_region = Region {
            extents: InclusiveRectangle {
                left: 2,
                top: 3,
                right: 9,
                bottom: 8,
            },
            rectangles: vec![
                InclusiveRectangle {
                    left: 2,
                    top: 3,
                    right: 7,
                    bottom: 6,
                },
                InclusiveRectangle {
                    left: 2,
                    top: 6,
                    right: 9,
                    bottom: 7,
                },
                InclusiveRectangle {
                    left: 5,
                    top: 7,
                    right: 9,
                    bottom: 8,
                },
            ],
        };

        region.union_rectangle(input_rectangle);
        assert_eq!(expected_region, region);
    }

    #[test]
    fn union_rectangle_cuts_new_rectangle_higher_and_lower_part_which_crosses_band_on_top_and_bottom() {
        let existing_band_rectangle = InclusiveRectangle {
            left: 2,
            top: 3,
            right: 7,
            bottom: 7,
        };
        let mut region = Region {
            extents: existing_band_rectangle.clone(),
            rectangles: vec![existing_band_rectangle],
        };

        let input_rectangle = InclusiveRectangle {
            left: 3,
            top: 1,
            right: 5,
            bottom: 11,
        };

        let expected_region = Region {
            extents: InclusiveRectangle {
                left: 2,
                top: 1,
                right: 7,
                bottom: 11,
            },
            rectangles: vec![
                InclusiveRectangle {
                    left: 3,
                    top: 1,
                    right: 5,
                    bottom: 3,
                },
                InclusiveRectangle {
                    left: 2,
                    top: 3,
                    right: 7,
                    bottom: 7,
                },
                InclusiveRectangle {
                    left: 3,
                    top: 7,
                    right: 5,
                    bottom: 11,
                },
            ],
        };

        region.union_rectangle(input_rectangle);
        assert_eq!(expected_region, region);
    }

    #[test]
    fn union_rectangle_inserts_new_rectangle_in_band_of_3_rectangles_without_merging_with_rectangles() {
        let mut region = Region {
            extents: InclusiveRectangle {
                left: 2,
                top: 3,
                right: 15,
                bottom: 7,
            },
            rectangles: vec![
                InclusiveRectangle {
                    left: 2,
                    top: 3,
                    right: 7,
                    bottom: 7,
                },
                InclusiveRectangle {
                    left: 8,
                    top: 3,
                    right: 9,
                    bottom: 7,
                },
                InclusiveRectangle {
                    left: 12,
                    top: 3,
                    right: 15,
                    bottom: 7,
                },
            ],
        };

        let input_rectangle = InclusiveRectangle {
            left: 10,
            top: 3,
            right: 11,
            bottom: 7,
        };
        let expected_region = Region {
            extents: InclusiveRectangle {
                left: 2,
                top: 3,
                right: 15,
                bottom: 7,
            },
            rectangles: vec![
                InclusiveRectangle {
                    left: 2,
                    top: 3,
                    right: 7,
                    bottom: 7,
                },
                InclusiveRectangle {
                    left: 8,
                    top: 3,
                    right: 9,
                    bottom: 7,
                },
                InclusiveRectangle {
                    left: 10,
                    top: 3,
                    right: 11,
                    bottom: 7,
                },
                InclusiveRectangle {
                    left: 12,
                    top: 3,
                    right: 15,
                    bottom: 7,
                },
            ],
        };

        region.union_rectangle(input_rectangle);
        assert_eq!(expected_region, region);
    }

    #[test]
    fn union_rectangle_inserts_new_rectangle_in_band_of_3_rectangles_with_merging_with_side_rectangles() {
        let mut region = Region {
            extents: InclusiveRectangle {
                left: 2,
                top: 3,
                right: 15,
                bottom: 7,
            },
            rectangles: vec![
                InclusiveRectangle {
                    left: 2,
                    top: 3,
                    right: 7,
                    bottom: 7,
                },
                InclusiveRectangle {
                    left: 8,
                    top: 3,
                    right: 10,
                    bottom: 7,
                },
                InclusiveRectangle {
                    left: 13,
                    top: 3,
                    right: 15,
                    bottom: 7,
                },
            ],
        };

        let input_rectangle = InclusiveRectangle {
            left: 9,
            top: 3,
            right: 14,
            bottom: 7,
        };
        let expected_region = Region {
            extents: InclusiveRectangle {
                left: 2,
                top: 3,
                right: 15,
                bottom: 7,
            },
            rectangles: vec![
                InclusiveRectangle {
                    left: 2,
                    top: 3,
                    right: 7,
                    bottom: 7,
                },
                InclusiveRectangle {
                    left: 8,
                    top: 3,
                    right: 15,
                    bottom: 7,
                },
            ],
        };

        region.union_rectangle(input_rectangle);
        assert_eq!(expected_region, region);
    }

    #[test]
    fn union_rectangle_inserts_new_rectangle_in_band_of_3_rectangles_with_merging_with_side_rectangles_on_board() {
        let mut region = Region {
            extents: InclusiveRectangle {
                left: 2,
                top: 3,
                right: 15,
                bottom: 7,
            },
            rectangles: vec![
                InclusiveRectangle {
                    left: 2,
                    top: 3,
                    right: 7,
                    bottom: 7,
                },
                InclusiveRectangle {
                    left: 8,
                    top: 3,
                    right: 10,
                    bottom: 7,
                },
                InclusiveRectangle {
                    left: 13,
                    top: 3,
                    right: 15,
                    bottom: 7,
                },
            ],
        };

        let input_rectangle = InclusiveRectangle {
            left: 10,
            top: 3,
            right: 13,
            bottom: 7,
        };
        let expected_region = Region {
            extents: InclusiveRectangle {
                left: 2,
                top: 3,
                right: 15,
                bottom: 7,
            },
            rectangles: vec![
                InclusiveRectangle {
                    left: 2,
                    top: 3,
                    right: 7,
                    bottom: 7,
                },
                InclusiveRectangle {
                    left: 8,
                    top: 3,
                    right: 13,
                    bottom: 7,
                },
                InclusiveRectangle {
                    left: 13,
                    top: 3,
                    right: 15,
                    bottom: 7,
                },
            ],
        };

        region.union_rectangle(input_rectangle);
        assert_eq!(expected_region, region);
    }

    #[test]
    fn union_rectangle_inserts_new_rectangle_between_two_bands() {
        let mut region = Region {
            extents: InclusiveRectangle {
                left: 1,
                top: 3,
                right: 7,
                bottom: 10,
            },
            rectangles: vec![
                InclusiveRectangle {
                    left: 2,
                    top: 3,
                    right: 7,
                    bottom: 7,
                },
                InclusiveRectangle {
                    left: 1,
                    top: 8,
                    right: 4,
                    bottom: 10,
                },
            ],
        };

        let input_rectangle = InclusiveRectangle {
            left: 3,
            top: 4,
            right: 4,
            bottom: 9,
        };
        let expected_region = Region {
            extents: InclusiveRectangle {
                left: 1,
                top: 3,
                right: 7,
                bottom: 10,
            },
            rectangles: vec![
                InclusiveRectangle {
                    left: 2,
                    top: 3,
                    right: 7,
                    bottom: 7,
                },
                InclusiveRectangle {
                    left: 3,
                    top: 7,
                    right: 4,
                    bottom: 8,
                },
                InclusiveRectangle {
                    left: 1,
                    top: 8,
                    right: 4,
                    bottom: 10,
                },
            ],
        };

        region.union_rectangle(input_rectangle);
        assert_eq!(expected_region, region);
    }

    #[test]
    fn simplify_does_not_change_two_different_bands_with_multiple_rectangles() {
        let mut region = Region {
            extents: InclusiveRectangle {
                left: 1,
                top: 1,
                right: 7,
                bottom: 3,
            },
            rectangles: vec![
                InclusiveRectangle {
                    left: 1,
                    top: 1,
                    right: 2,
                    bottom: 2,
                },
                InclusiveRectangle {
                    left: 3,
                    top: 1,
                    right: 4,
                    bottom: 2,
                },
                InclusiveRectangle {
                    left: 5,
                    top: 1,
                    right: 6,
                    bottom: 2,
                },
                InclusiveRectangle {
                    left: 1,
                    top: 2,
                    right: 2,
                    bottom: 3,
                },
                InclusiveRectangle {
                    left: 3,
                    top: 2,
                    right: 4,
                    bottom: 3,
                },
                InclusiveRectangle {
                    left: 5,
                    top: 2,
                    right: 7,
                    bottom: 3,
                },
            ],
        };
        let expected_region = region.clone();

        region.simplify();
        assert_eq!(expected_region, region);
    }

    #[test]
    fn simplify_does_not_change_two_different_bands_with_one_rectangle() {
        let mut region = Region {
            extents: InclusiveRectangle {
                left: 2,
                top: 1,
                right: 7,
                bottom: 11,
            },
            rectangles: vec![
                InclusiveRectangle {
                    left: 3,
                    top: 1,
                    right: 5,
                    bottom: 3,
                },
                InclusiveRectangle {
                    left: 2,
                    top: 3,
                    right: 7,
                    bottom: 7,
                },
            ],
        };
        let expected_region = region.clone();

        region.simplify();
        assert_eq!(expected_region, region);
    }

    #[test]
    fn simplify_does_not_change_three_different_bands_with_one_rectangle() {
        let mut region = Region {
            extents: InclusiveRectangle {
                left: 2,
                top: 1,
                right: 7,
                bottom: 11,
            },
            rectangles: vec![
                InclusiveRectangle {
                    left: 3,
                    top: 1,
                    right: 5,
                    bottom: 3,
                },
                InclusiveRectangle {
                    left: 2,
                    top: 3,
                    right: 7,
                    bottom: 7,
                },
                InclusiveRectangle {
                    left: 3,
                    top: 7,
                    right: 5,
                    bottom: 11,
                },
            ],
        };
        let expected_region = region.clone();

        region.simplify();
        assert_eq!(expected_region, region);
    }

    #[test]
    fn simplify_merges_bands_with_identical_internal_rectangles() {
        let mut region = Region {
            extents: InclusiveRectangle {
                left: 1,
                top: 1,
                right: 7,
                bottom: 3,
            },
            rectangles: vec![
                InclusiveRectangle {
                    left: 1,
                    top: 1,
                    right: 2,
                    bottom: 2,
                },
                InclusiveRectangle {
                    left: 3,
                    top: 1,
                    right: 4,
                    bottom: 2,
                },
                InclusiveRectangle {
                    left: 5,
                    top: 1,
                    right: 6,
                    bottom: 2,
                },
                InclusiveRectangle {
                    left: 1,
                    top: 2,
                    right: 2,
                    bottom: 3,
                },
                InclusiveRectangle {
                    left: 3,
                    top: 2,
                    right: 4,
                    bottom: 3,
                },
                InclusiveRectangle {
                    left: 5,
                    top: 2,
                    right: 6,
                    bottom: 3,
                },
            ],
        };
        let expected_region = Region {
            extents: InclusiveRectangle {
                left: 1,
                top: 1,
                right: 7,
                bottom: 3,
            },
            rectangles: vec![
                InclusiveRectangle {
                    left: 1,
                    top: 1,
                    right: 2,
                    bottom: 3,
                },
                InclusiveRectangle {
                    left: 3,
                    top: 1,
                    right: 4,
                    bottom: 3,
                },
                InclusiveRectangle {
                    left: 5,
                    top: 1,
                    right: 6,
                    bottom: 3,
                },
            ],
        };

        region.simplify();
        assert_eq!(expected_region, region);
    }

    #[test]
    fn simplify_merges_three_bands_with_identical_internal_rectangles() {
        let mut region = Region {
            extents: InclusiveRectangle {
                left: 1,
                top: 1,
                right: 7,
                bottom: 3,
            },
            rectangles: vec![
                InclusiveRectangle {
                    left: 1,
                    top: 1,
                    right: 2,
                    bottom: 2,
                },
                InclusiveRectangle {
                    left: 3,
                    top: 1,
                    right: 4,
                    bottom: 2,
                },
                InclusiveRectangle {
                    left: 5,
                    top: 1,
                    right: 6,
                    bottom: 2,
                },
                InclusiveRectangle {
                    left: 1,
                    top: 2,
                    right: 2,
                    bottom: 3,
                },
                InclusiveRectangle {
                    left: 3,
                    top: 2,
                    right: 4,
                    bottom: 3,
                },
                InclusiveRectangle {
                    left: 5,
                    top: 2,
                    right: 6,
                    bottom: 3,
                },
                InclusiveRectangle {
                    left: 1,
                    top: 3,
                    right: 2,
                    bottom: 4,
                },
                InclusiveRectangle {
                    left: 3,
                    top: 3,
                    right: 4,
                    bottom: 4,
                },
                InclusiveRectangle {
                    left: 5,
                    top: 3,
                    right: 6,
                    bottom: 4,
                },
            ],
        };
        let expected_region = Region {
            extents: InclusiveRectangle {
                left: 1,
                top: 1,
                right: 7,
                bottom: 3,
            },
            rectangles: vec![
                InclusiveRectangle {
                    left: 1,
                    top: 1,
                    right: 2,
                    bottom: 4,
                },
                InclusiveRectangle {
                    left: 3,
                    top: 1,
                    right: 4,
                    bottom: 4,
                },
                InclusiveRectangle {
                    left: 5,
                    top: 1,
                    right: 6,
                    bottom: 4,
                },
            ],
        };

        region.simplify();
        assert_eq!(expected_region, region);
    }

    #[test]
    fn simplify_merges_two_pairs_of_bands_with_identical_internal_rectangles() {
        let mut region = Region {
            extents: InclusiveRectangle {
                left: 1,
                top: 1,
                right: 7,
                bottom: 5,
            },
            rectangles: vec![
                InclusiveRectangle {
                    left: 1,
                    top: 1,
                    right: 2,
                    bottom: 2,
                },
                InclusiveRectangle {
                    left: 3,
                    top: 1,
                    right: 4,
                    bottom: 2,
                },
                InclusiveRectangle {
                    left: 5,
                    top: 1,
                    right: 6,
                    bottom: 2,
                },
                InclusiveRectangle {
                    left: 1,
                    top: 2,
                    right: 2,
                    bottom: 3,
                },
                InclusiveRectangle {
                    left: 3,
                    top: 2,
                    right: 4,
                    bottom: 3,
                },
                InclusiveRectangle {
                    left: 5,
                    top: 2,
                    right: 6,
                    bottom: 3,
                },
                InclusiveRectangle {
                    left: 2,
                    top: 3,
                    right: 3,
                    bottom: 4,
                },
                InclusiveRectangle {
                    left: 4,
                    top: 3,
                    right: 5,
                    bottom: 4,
                },
                InclusiveRectangle {
                    left: 6,
                    top: 3,
                    right: 7,
                    bottom: 4,
                },
                InclusiveRectangle {
                    left: 2,
                    top: 4,
                    right: 3,
                    bottom: 5,
                },
                InclusiveRectangle {
                    left: 4,
                    top: 4,
                    right: 5,
                    bottom: 5,
                },
                InclusiveRectangle {
                    left: 6,
                    top: 4,
                    right: 7,
                    bottom: 5,
                },
            ],
        };
        let expected_region = Region {
            extents: InclusiveRectangle {
                left: 1,
                top: 1,
                right: 7,
                bottom: 5,
            },
            rectangles: vec![
                InclusiveRectangle {
                    left: 1,
                    top: 1,
                    right: 2,
                    bottom: 3,
                },
                InclusiveRectangle {
                    left: 3,
                    top: 1,
                    right: 4,
                    bottom: 3,
                },
                InclusiveRectangle {
                    left: 5,
                    top: 1,
                    right: 6,
                    bottom: 3,
                },
                InclusiveRectangle {
                    left: 2,
                    top: 3,
                    right: 3,
                    bottom: 5,
                },
                InclusiveRectangle {
                    left: 4,
                    top: 3,
                    right: 5,
                    bottom: 5,
                },
                InclusiveRectangle {
                    left: 6,
                    top: 3,
                    right: 7,
                    bottom: 5,
                },
            ],
        };

        region.simplify();
        assert_eq!(expected_region, region);
    }

    #[test]
    fn intersect_rectangle_returns_empty_region_for_not_intersecting_rectangle() {
        let region = &*REGION_FOR_RECTANGLES_INTERSECTION;
        let expected_region = Region {
            extents: InclusiveRectangle {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            },
            rectangles: Vec::new(),
        };
        let input_rectangle = InclusiveRectangle {
            left: 1,
            top: 4,
            right: 2,
            bottom: 5,
        };

        let actual_region = region.intersect_rectangle(&input_rectangle);
        assert_eq!(expected_region, actual_region);
    }

    #[test]
    fn intersect_rectangle_returns_empty_region_for_empty_intersection_region() {
        let expected_region: Region = Region {
            extents: InclusiveRectangle {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            },
            rectangles: Vec::new(),
        };
        let input_rectangle = InclusiveRectangle {
            left: 5,
            top: 2,
            right: 6,
            bottom: 3,
        };

        let actual_region = expected_region.intersect_rectangle(&input_rectangle);
        assert_eq!(expected_region, actual_region);
    }

    #[test]
    fn intersect_rectangle_returns_part_of_rectangle_that_overlaps_for_region_with_one_rectangle() {
        let region = Region {
            extents: InclusiveRectangle {
                left: 1,
                top: 1,
                right: 5,
                bottom: 3,
            },
            rectangles: vec![InclusiveRectangle {
                left: 1,
                top: 1,
                right: 5,
                bottom: 3,
            }],
        };
        let expected_region = Region {
            extents: InclusiveRectangle {
                left: 2,
                top: 2,
                right: 3,
                bottom: 3,
            },
            rectangles: vec![InclusiveRectangle {
                left: 2,
                top: 2,
                right: 3,
                bottom: 3,
            }],
        };
        let input_rectangle = InclusiveRectangle {
            left: 2,
            top: 2,
            right: 3,
            bottom: 3,
        };

        let actual_region = region.intersect_rectangle(&input_rectangle);
        assert_eq!(expected_region, actual_region);
    }

    #[test]
    fn intersect_rectangle_returns_region_with_parts_of_rectangles_that_intersect_input_rectangle() {
        let region = &*REGION_FOR_RECTANGLES_INTERSECTION;
        let expected_region = Region {
            extents: InclusiveRectangle {
                left: 3,
                top: 2,
                right: 8,
                bottom: 5,
            },
            rectangles: vec![
                InclusiveRectangle {
                    left: 3,
                    top: 2,
                    right: 5,
                    bottom: 3,
                },
                InclusiveRectangle {
                    left: 7,
                    top: 2,
                    right: 8,
                    bottom: 3,
                },
                InclusiveRectangle {
                    left: 7,
                    top: 3,
                    right: 8,
                    bottom: 4,
                },
                InclusiveRectangle {
                    left: 3,
                    top: 4,
                    right: 6,
                    bottom: 5,
                },
                InclusiveRectangle {
                    left: 7,
                    top: 4,
                    right: 8,
                    bottom: 5,
                },
            ],
        };
        let input_rectangle = InclusiveRectangle {
            left: 3,
            top: 2,
            right: 8,
            bottom: 5,
        };

        let actual_region = region.intersect_rectangle(&input_rectangle);
        assert_eq!(expected_region, actual_region);
    }

    #[test]
    fn intersect_rectangle_returns_region_with_exact_sizes_of_rectangle_that_overlaps_it() {
        let region = &*REGION_FOR_RECTANGLES_INTERSECTION;
        let expected_region = Region {
            extents: InclusiveRectangle {
                left: 2,
                top: 2,
                right: 4,
                bottom: 3,
            },
            rectangles: vec![InclusiveRectangle {
                left: 2,
                top: 2,
                right: 4,
                bottom: 3,
            }],
        };
        let input_rectangle: InclusiveRectangle = InclusiveRectangle {
            left: 2,
            top: 2,
            right: 4,
            bottom: 3,
        };

        let actual_region = region.intersect_rectangle(&input_rectangle);
        assert_eq!(expected_region, actual_region);
    }
}
