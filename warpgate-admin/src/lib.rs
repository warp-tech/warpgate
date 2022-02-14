#![feature(async_stream)]
use futures::stream;
use futures::StreamExt;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use warp::Filter;
use warpgate_common::State;

pub struct AdminServer {
    state: Arc<Mutex<State>>,
}

use serde::Serialize;

#[derive(Serialize)]
struct SessionData {
    id: u64,
    username: Option<String>,
}

#[derive(Serialize)]
struct IndexResponse {
    sessions: Vec<SessionData>,
}

impl AdminServer {
    pub fn new(state: Arc<Mutex<State>>) -> Self {
        AdminServer { state }
    }

    pub async fn run(self, address: SocketAddr) {
        let state = self.state.clone();
        let with_state = warp::filters::any::any().map(move || state.clone());

        let hello = warp::filters::method::get()
            .and(warp::path::end())
            .and(with_state.clone())
            .and_then(|state: Arc<Mutex<State>>| async move {
                let state = state.lock().await;
                let sessions = stream::iter(state.sessions.iter()).then(|(id, s)| async move {
                    let session = s.lock().await;
                    SessionData {
                        id: *id,
                        username: session.username.clone(),
                    }
                });
                let sessions = sessions.collect::<Vec<_>>().await;
                Ok::<_, Infallible>(warp::reply::json(&IndexResponse { sessions }))
            });

        warp::serve(hello).run(address).await;
    }
}
