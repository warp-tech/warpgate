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
struct IndexResponse<'a> {
    session_count: &'a usize,
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
                Ok::<_, Infallible>(warp::reply::json(&IndexResponse {
                    session_count: &state.lock().await.sessions.len(),
                }))
            });

        warp::serve(hello).run(address).await;
    }
}
