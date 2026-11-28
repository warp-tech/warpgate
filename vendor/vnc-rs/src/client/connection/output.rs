use crate::{VncError, VncEvent};
use tokio::sync::{mpsc::Sender, oneshot};

pub(super) async fn report_error(
    error: VncError,
    output: &Sender<VncEvent>,
    stop: &mut oneshot::Receiver<()>,
) {
    let message = match &error {
        // The network bridge closes with EOF on normal disconnection.
        VncError::IoError(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return,
        VncError::IoError(error) => error.to_string(),
        error => error.to_string(),
    };
    tracing::error!("Error occurs during the decoding {:?}", error);
    tokio::select! {
        biased;
        _ = stop => {},
        _ = output.send(VncEvent::Error(message)) => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::mpsc::channel;

    #[tokio::test]
    async fn error_waits_for_capacity_and_preserves_event_order() {
        let (output, mut events) = channel(2);
        output.try_send(VncEvent::Bell).unwrap();
        output.try_send(VncEvent::Text("queued".into())).unwrap();
        let (_stop, mut stopped) = oneshot::channel();
        let task = report_error(VncError::InvalidImageData, &output, &mut stopped);
        tokio::pin!(task);
        assert!(futures::poll!(task.as_mut()).is_pending());
        assert!(matches!(events.try_recv(), Ok(VncEvent::Bell)));
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap();
        assert!(matches!(events.try_recv(), Ok(VncEvent::Text(text)) if text == "queued"));
        assert!(
            matches!(events.try_recv(), Ok(VncEvent::Error(message)) if message == VncError::InvalidImageData.to_string())
        );
        assert!(events.try_recv().is_err());
    }

    #[tokio::test]
    async fn shutdown_cancels_error_delivery_even_when_capacity_returns() {
        for free_slot in [false, true] {
            let (output, mut events) = channel(1);
            output.try_send(VncEvent::Bell).unwrap();
            let (stop, mut stopped) = oneshot::channel();
            let task = report_error(VncError::InvalidImageData, &output, &mut stopped);
            tokio::pin!(task);
            assert!(futures::poll!(task.as_mut()).is_pending());
            stop.send(()).unwrap();
            if free_slot {
                events.try_recv().unwrap();
            }
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap();
            if !free_slot {
                assert!(matches!(events.try_recv(), Ok(VncEvent::Bell)));
            }
            assert!(events.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn dropped_consumer_releases_pending_error_delivery() {
        let (output, events) = channel(1);
        output.try_send(VncEvent::Bell).unwrap();
        let (_stop, mut stopped) = oneshot::channel();
        let task = report_error(VncError::InvalidImageData, &output, &mut stopped);
        tokio::pin!(task);
        assert!(futures::poll!(task.as_mut()).is_pending());
        drop(events);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn io_errors_are_delivered_but_normal_eof_is_not() {
        let (output, mut events) = channel(1);
        let (_stop, mut stopped) = oneshot::channel();
        for kind in [
            std::io::ErrorKind::UnexpectedEof,
            std::io::ErrorKind::InvalidData,
        ] {
            let error = std::io::Error::new(kind, "wire error");
            report_error(VncError::IoError(error), &output, &mut stopped).await;
            if kind == std::io::ErrorKind::UnexpectedEof {
                assert!(events.try_recv().is_err());
            } else {
                assert!(
                    matches!(events.try_recv(), Ok(VncEvent::Error(message)) if message == "wire error")
                );
            }
        }
    }
}
