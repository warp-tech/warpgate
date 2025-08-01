use std::any::type_name;
use std::collections::HashMap;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};

use once_cell::sync::Lazy;
use tokio::sync::Mutex;
use tokio::task::Id;

static LOCK_IDENTITIES: Lazy<std::sync::Mutex<HashMap<Option<Id>, Vec<String>>>> =
    Lazy::new(|| std::sync::Mutex::new(HashMap::new()));

fn log_state() {
    eprintln!("Tokio task: {:?}", tokio::task::try_id());
    let ids = LOCK_IDENTITIES.lock().unwrap();
    let identities = ids.get(&tokio::task::try_id()).cloned().unwrap_or_default();
    if !identities.is_empty() {
        eprintln!("* Held locks: {:?}", identities);
    }
}

pub struct MutexGuard<'a, T> {
    inner: tokio::sync::MutexGuard<'a, T>,
    poisoned: &'a AtomicBool,
}

impl<'a, T> MutexGuard<'a, T> {
    pub fn new(inner: tokio::sync::MutexGuard<'a, T>, poisoned: &'a AtomicBool) -> Self {
        let this = Self { inner, poisoned };
        let mut ids = LOCK_IDENTITIES.lock().unwrap();
        let identities = ids.entry(tokio::task::try_id()).or_insert(vec![]);
        let id = this.identity();
        identities.push(id);
        // eprintln!("Locking {} @ {:?}", this.identity(), tokio::task::try_id());
        this
    }

    fn identity(&self) -> String {
        format!(
            "{:?}@{}",
            type_name::<T>(),
            tokio::task::try_id().map_or("unknown".to_string(), |id| id.to_string())
        )
    }
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

#[cfg(debug_assertions)]
impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        let self_id = self.identity();
        // eprintln!("Unlocking {} @ {:?}", self.identity(), tokio::task::try_id());

        if self.poisoned.load(Ordering::Relaxed) {
            eprintln!("[!!] MutexGuard dropped while poisoned");
            log_state();
            panic!();
        }

        let mut ids = LOCK_IDENTITIES.lock().unwrap();
        if let Some(identities) = ids.get_mut(&tokio::task::try_id()) {
            identities.retain(|id| id != &self_id);
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
            res = self.inner.lock() => MutexGuard::new(res, &self.poisoned),
            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                self.poisoned.store(true, Ordering::Relaxed);
                eprintln!("[!!] Mutex lock took too long");
                log_state();
                panic!();
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
