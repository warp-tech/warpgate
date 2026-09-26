use std::future::Future;
use std::io::Result as IoResult;
use std::time::Duration;

use poem::http::uri::Scheme;
use poem::listener::Acceptor;
use poem::web::{LocalAddr, RemoteAddr};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::debug;

use crate::helpers::net::connection_setup_slots;

/// poem::Acceptor::accept return
pub type Accepted<Io> = (Io, LocalAddr, RemoteAddr, Scheme);

const CONNECTION_BACKLOG: usize = 1024;

/// A sleep prevents CPU loop for persistent errors (e.g. fd exhaustion)
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(100);

/// A poem Acceptor that runs connection setup (PROXY protocol header recv etc)
/// in a separate task instead of on the accept loop
///
/// This prevents a stalled peer from holding up the queue
///
/// Backpressure path is poem -> `connections` channel -> OS socket
pub struct ConcurrentAcceptor<Io> {
    local_addr: Vec<LocalAddr>,
    connections: mpsc::Receiver<IoResult<Accepted<Io>>>,
    accept_loop: JoinHandle<()>,
}

impl<Io> ConcurrentAcceptor<Io>
where
    Io: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    /// accept connections from `inner` and map them via `setup`
    pub fn new<A, F, Fut>(mut inner: A, setup: F) -> Self
    where
        A: Acceptor + 'static,
        F: FnMut(Accepted<A::Io>) -> Fut + Send + 'static,
        Fut: Future<Output = anyhow::Result<Accepted<Io>>> + Send + 'static,
    {
        let local_addr = inner.local_addr();
        let (tx, connections) = mpsc::channel(CONNECTION_BACKLOG);

        let mut setup = setup;
        let accept_loop = tokio::spawn(async move {
            let setups = connection_setup_slots();
            loop {
                // The semaphore is never closed, but bail rather than unwrap.
                let Ok(permit) = setups.clone().acquire_owned().await else {
                    return;
                };
                let accepted = match inner.accept().await {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        if tx.send(Err(error)).await.is_err() {
                            return;
                        }
                        tokio::time::sleep(ACCEPT_ERROR_PAUSE).await;
                        continue;
                    }
                };
                let prepared = setup(accepted);
                let tx = tx.clone();
                tokio::spawn(async move {
                    match prepared.await {
                        Ok(accepted) => {
                            let _ = tx.send(Ok(accepted)).await;
                        }
                        Err(error) => debug!("Dropping connection: {error:#}"),
                    }
                    drop(permit);
                });
            }
        });

        Self {
            local_addr,
            connections,
            accept_loop,
        }
    }
}

impl<Io> Drop for ConcurrentAcceptor<Io> {
    fn drop(&mut self) {
        self.accept_loop.abort();
    }
}

impl<Io> Acceptor for ConcurrentAcceptor<Io>
where
    Io: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Io = Io;

    fn local_addr(&self) -> Vec<LocalAddr> {
        self.local_addr.clone()
    }

    async fn accept(&mut self) -> IoResult<Accepted<Io>> {
        self.connections
            .recv()
            .await
            .unwrap_or_else(|| Err(std::io::Error::other("Listener stopped")))
    }
}
