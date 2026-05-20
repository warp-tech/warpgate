use std::future::Future;

use futures::{Sink, SinkExt, Stream, StreamExt};
use poem::web::websocket::Message;
use tokio_tungstenite::tungstenite::{self, Utf8Bytes};

pub trait TungsteniteCompatibleWebsocketMessage {
    fn to_tungstenite_message(self) -> tungstenite::Message;
    fn from_tungstenite_message(m: tungstenite::Message) -> Self;
}

impl TungsteniteCompatibleWebsocketMessage for Message {
    fn to_tungstenite_message(self) -> tungstenite::Message {
        match self {
            Self::Binary(data) => tungstenite::Message::Binary(data.into()),
            Self::Text(text) => tungstenite::Message::Text(text.into()),
            Self::Ping(data) => tungstenite::Message::Ping(data.into()),
            Self::Pong(data) => tungstenite::Message::Pong(data.into()),
            Self::Close(data) => {
                tungstenite::Message::Close(data.map(|data| tungstenite::protocol::CloseFrame {
                    code: u16::from(data.0).into(),
                    reason: Utf8Bytes::from(data.1),
                }))
            }
        }
    }

    fn from_tungstenite_message(msg: tungstenite::Message) -> Self {
        match msg {
            tungstenite::Message::Binary(data) => Self::Binary(data.to_vec()),
            tungstenite::Message::Text(text) => Self::Text(text.to_string()),
            tungstenite::Message::Ping(data) => Self::Ping(data.to_vec()),
            tungstenite::Message::Pong(data) => Self::Pong(data.to_vec()),
            tungstenite::Message::Close(data) => {
                Self::Close(data.map(|data| (u16::from(data.code).into(), data.reason.to_string())))
            }
            tungstenite::Message::Frame(_) => unreachable!(),
        }
    }
}

impl TungsteniteCompatibleWebsocketMessage for reqwest_websocket::Message {
    fn to_tungstenite_message(self) -> tungstenite::Message {
        match self {
            Self::Binary(data) => tungstenite::Message::Binary(data),
            Self::Text(text) => tungstenite::Message::Text(Utf8Bytes::from(text)),
            Self::Ping(data) => tungstenite::Message::Ping(data),
            Self::Pong(data) => tungstenite::Message::Pong(data),
            Self::Close { code, reason } => {
                tungstenite::Message::Close(Some(tungstenite::protocol::CloseFrame {
                    code: u16::from(code).into(),
                    reason: Utf8Bytes::from(reason),
                }))
            }
        }
    }

    fn from_tungstenite_message(msg: tungstenite::Message) -> Self {
        match msg {
            tungstenite::Message::Binary(data) => Self::Binary(data),
            tungstenite::Message::Text(text) => Self::Text(text.to_string()),
            tungstenite::Message::Ping(data) => Self::Ping(data),
            tungstenite::Message::Pong(data) => Self::Pong(data),
            tungstenite::Message::Close(data) => Self::Close {
                code: data
                    .as_ref()
                    .map_or(reqwest_websocket::CloseCode::Normal, |data| {
                        u16::from(data.code).into()
                    }),
                reason: data.map(|data| data.reason.to_string()).unwrap_or_default(),
            },
            tungstenite::Message::Frame(_) => unreachable!(),
        }
    }
}

impl TungsteniteCompatibleWebsocketMessage for tungstenite::Message {
    fn to_tungstenite_message(self) -> tungstenite::Message {
        self
    }

    fn from_tungstenite_message(msg: tungstenite::Message) -> Self {
        msg
    }
}

pub async fn pump_websocket<
    DM: TungsteniteCompatibleWebsocketMessage + Send,
    D: Sink<DM> + Send + Unpin,
    SM: TungsteniteCompatibleWebsocketMessage + Send,
    SE: Send,
    S: Stream<Item = Result<SM, SE>> + Send + Unpin,
    FE: Send,
    F: FnMut(tungstenite::Message) -> Fut,
    Fut: Future<Output = Result<tungstenite::Message, FE>> + Send,
>(
    mut source: S,
    mut sink: D,
    mut callback: F,
) -> anyhow::Result<()>
where
    anyhow::Error: From<D::Error> + From<SE> + From<FE>,
{
    while let Some(msg) = source.next().await {
        let msg = msg?.to_tungstenite_message();
        let msg = callback(msg).await?;
        sink.send(DM::from_tungstenite_message(msg)).await?;
    }
    Ok::<_, anyhow::Error>(())
}
