use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Mutex;

pub struct MutexGuard<'a, T> {
    inner: tokio::sync::MutexGuard<'a, T>,
    poisoned: &'a AtomicBool,
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        if self.poisoned.load(Ordering::Relaxed) {
            panic!("MutexGuard dropped while poisoned");
        }
    }
}

pub struct Mutex2<T> {
    inner: Mutex<T>,
    poisoned: AtomicBool,
}

impl<T> Mutex2<T> {
    pub fn new(data: T) -> Self {
        Self {
            inner: Mutex::new(data),
            poisoned: AtomicBool::new(false),
        }
    }

    pub async fn lock<'a>(&'a self) -> MutexGuard<'a, T> {
        self._lock().await
    }

    #[cfg(debug_assertions)]
    async fn _lock<'a>(&'a self) -> MutexGuard<'a, T> {
        use std::time::Duration;

        tokio::select! {
            res = self.inner.lock() => MutexGuard { inner: res, poisoned: &self.poisoned },
            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                self.poisoned.store(true, Ordering::Relaxed);
                panic!("Mutex lock took too long");
            }
        }
    }

    #[cfg(not(debug_assertions))]
    async fn _lock<'a>(&'a self) -> MutexGuard<'a, T> {
        self.inner.lock().await
    }
}

pub trait DebugLock<T> {
    fn lock2<'a>(&'a self) -> impl Future<Output = tokio::sync::MutexGuard<'a, T>>
    where
        T: 'a;
}

impl<T> DebugLock<T> for tokio::sync::Mutex<T> {
    #[cfg(debug_assertions)]
    async fn lock2<'a>(&'a self) -> tokio::sync::MutexGuard<'a, T>
    where
        T: 'a,
    {
        use std::time::Duration;

        tokio::select! {
            res = self.lock() => res,
            _ = tokio::time::sleep(Duration::from_secs(10)) => {
                panic!("Mutex lock took too long");
            }
        }
    }

    #[cfg(not(debug_assertions))]
    async fn lock2<'a>(&'a self) -> tokio::sync::MutexGuard<'a, T>
    where
        T: 'a,
    {
        self.lock().await
    }
}
