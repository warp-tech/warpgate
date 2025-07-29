use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;

use tokio::sync::Mutex;
use uuid::Uuid;

use crate::rate_limiting::WarpgateRateLimiter;

pub struct RateLimiterRegistry {
    global_rate_limiter: Arc<Mutex<WarpgateRateLimiter>>,
    user_rate_limiters: HashMap<Uuid, Arc<Mutex<WarpgateRateLimiter>>>,
    target_rate_limiters: HashMap<Uuid, Arc<Mutex<WarpgateRateLimiter>>>,
}

impl RateLimiterRegistry {
    pub fn new() -> Self {
        Self {
            global_rate_limiter: Arc::new(Mutex::new(WarpgateRateLimiter::empty())),
            user_rate_limiters: HashMap::new(),
            target_rate_limiters: HashMap::new(),
        }
    }

}
