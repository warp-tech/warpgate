use std::fmt::Debug;

use crate::consts::TICKET_SELECTOR_PREFIX;
use crate::Secret;

pub enum AuthSelector {
    User {
        username: String,
        target_name: String,
    },
    Ticket {
        secret: Secret<String>,
    },
}

impl From<&String> for AuthSelector {
    fn from(selector: &String) -> Self {
        if let Some(secret) = selector.strip_prefix(TICKET_SELECTOR_PREFIX) {
            let secret = Secret::new(secret.into());
            return AuthSelector::Ticket { secret };
        }

        let separator = if selector.contains('#') { '#' } else { ':' };

        let mut parts = selector.splitn(2, separator);
        let username = parts.next().unwrap_or("").to_string();
        let target_name = parts.next().unwrap_or("").to_string();
        AuthSelector::User {
            username,
            target_name,
        }
    }
}

impl Debug for AuthSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthSelector::User {
                username,
                target_name,
            } => write!(f, "<{} for {}>", username, target_name),
            AuthSelector::Ticket { .. } => write!(f, "<ticket>"),
        }
    }
}
