use std::path::PathBuf;

use anyhow::{Context, Result};
use notify::{RecursiveMode, Watcher, recommended_watcher};
use sea_orm::DatabaseConnection;
use tokio::sync::mpsc;
use tracing::{error, info};
use warpgate_core::static_targets::sync_static_targets_file;

/// Performs an initial sync of the static targets file at `path` into the
/// database, then watches it and re-syncs on every change. Read/parse
/// failures are logged rather than propagated, so a typo'd file doesn't take
/// the rest of the server down — the previously-synced rows stay as they
/// were until the file is fixed.
pub async fn watch_static_targets_file(path: PathBuf, db: DatabaseConnection) -> Result<()> {
    if let Err(error) = sync_static_targets_file(&db, &path).await {
        error!(?error, path = %path.display(), "Failed to sync static targets file");
    }

    let (tx, mut rx) = mpsc::channel(16);
    let mut watcher = recommended_watcher(move |res| {
        let _ = tx.blocking_send(res);
    })?;
    watcher
        .watch(path.as_ref(), RecursiveMode::NonRecursive)
        .with_context(|| format!("Failed to watch {}", path.display()))?;

    tokio::spawn(async move {
        let _watcher = watcher; // avoid dropping the watcher
        loop {
            // Block until a modify event, then debounce: editors and
            // atomic-replace tools emit several events per save, so wait for
            // 500ms of quiet before syncing once.
            match rx.recv().await {
                Some(Ok(event)) if event.kind.is_modify() => {}
                Some(Ok(_)) => continue,
                Some(Err(error)) => {
                    error!(?error, "Failed to watch static targets file");
                    continue;
                }
                None => {
                    error!("Static targets file watch failed");
                    break;
                }
            }
            while let Ok(pending) =
                tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await
            {
                match pending {
                    Some(Err(error)) => error!(?error, "Failed to watch static targets file"),
                    None => return,
                    Some(Ok(_)) => {} // more activity, keep debouncing
                }
            }

            match sync_static_targets_file(&db, &path).await {
                Ok(()) => info!(path = %path.display(), "Reloaded static targets file"),
                Err(error) => error!(?error, "Failed to reload static targets file"),
            }
        }
    });

    Ok(())
}
