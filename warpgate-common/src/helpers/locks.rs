use std::future::Future;

use tokio::sync::MutexGuard;

pub trait DebugLock<T> {
    fn lock2<'a>(&'a self) -> impl Future<Output = MutexGuard<'a, T>>
    where
        T: 'a;
}

impl<T> DebugLock<T> for tokio::sync::Mutex<T> {
    #[cfg(debug_assertions)]
    async fn lock2<'a>(&'a self) -> MutexGuard<'a, T>
    where
        T: 'a,
    {
        use std::time::Duration;

        tokio::select! {
            res = self.lock() => res,
            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                panic!("Mutex lock took too long");
            }
        }
    }

    #[cfg(not(debug_assertions))]
    async fn lock2<'a>(&'a self) -> MutexGuard<'a, T>
    where
        T: 'a,
    {
        self.lock().await
    }
}
