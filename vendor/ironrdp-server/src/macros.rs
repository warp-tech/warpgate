macro_rules! time_warn {
    ($context:expr, $threshold_ms:expr, $op:expr) => {{
        #[cold]
        fn warn_log(context: &str, duration: u128) {
            use ::core::sync::atomic::AtomicUsize;

            static COUNT: AtomicUsize = AtomicUsize::new(0);
            let current_count = COUNT.fetch_add(1, ::core::sync::atomic::Ordering::Relaxed);
            if current_count < 50 || current_count % 100 == 0 {
                ::tracing::warn!("{context} took {duration} ms! (count: {current_count})");
            }
        }

        let start = std::time::Instant::now();
        let result = $op;
        let duration = start.elapsed().as_millis();
        if duration > $threshold_ms {
            warn_log($context, duration);
        }
        result
    }};
}

pub(crate) use time_warn;
