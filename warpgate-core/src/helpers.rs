use poem::Request;

use crate::Services;

/// Extract client IP, considering reverse proxy headers if trusted
pub async fn extract_client_ip(request: &Request, services: &Services) -> String {
    let trust_x_forwarded_headers = {
        let config = services.config.lock().await;
        config.store.http.trust_x_forwarded_headers
    };
    let remote_ip = request
        .remote_addr()
        .as_socket_addr()
        .map(|x| x.ip().to_string())
        .unwrap_or("<unknown>".into());
    if trust_x_forwarded_headers {
        request
            .header("x-forwarded-for")
            .map(|x| x.to_string())
            .unwrap_or(remote_ip)
    } else {
        remote_ip
    }
}
