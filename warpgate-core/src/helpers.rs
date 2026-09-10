use std::time::Duration;

pub fn i64_seconds_to_duration(v: i64) -> Option<Duration> {
    Some(Duration::from_secs(u64::try_from(v).ok()?))
}
