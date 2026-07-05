use embedded_graphics::prelude::Point;
use embedded_graphics::primitives::Circle;

const TICKS_PER_LOOP: f32 = 24.0;
const HORIZONTAL_AMPLITUDE: f32 = 44.0;
const MIN_DIAMETER: f32 = 6.0;
const MAX_DIAMETER: f32 = 10.0;

/// The ball as an [Circle] at `tick`, centered on `(cx, cy)`.
pub fn bouncy_ball(tick: u64, cx: i32, cy: i32) -> Circle {
    let phase = (std::f32::consts::TAU * (tick as f32) / TICKS_PER_LOOP).sin(); // -1..1
    let x = cx as f32 + HORIZONTAL_AMPLITUDE * phase;
    let diameter = MIN_DIAMETER + (MAX_DIAMETER - MIN_DIAMETER) * phase.abs();
    let radius = diameter / 2.0;
    Circle::new(
        Point::new((x - radius) as i32, (cy as f32 - radius) as i32),
        diameter as u32,
    )
}
