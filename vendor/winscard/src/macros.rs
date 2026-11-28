/// Read the environment variable value in runtime.
///
/// Returns an [Error] otherwise.
#[doc(hidden)]
#[macro_export]
#[cfg(feature = "std")]
macro_rules! env {
    ($name:expr) => {{
        std::env::var($name).map_err(|_| {
            $crate::Error::new(
                $crate::ErrorKind::InvalidParameter,
                format!("env var '{}' missing or invalid", $name),
            )
        })
    }};
}
