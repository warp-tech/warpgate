use warpgate_core::SessionHandle;

pub struct KubernetesSessionHandle;

impl SessionHandle for KubernetesSessionHandle {
    fn close(&mut self) {
        // TODO hide on frontend
    }
}
