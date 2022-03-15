use std::fmt::Debug;

use secrecy::Secret;

use crate::consts::TICKET_SELECTOR_PREFIX;

pub enum AuthSelector {
    User {
        username: String,
        target_name: String,
    },
    Ticket {
        secret: Secret<String>,
    },
}

// Consume string so the ticket secret can't be accidentally leaked from it
impl From<String> for AuthSelector {
    fn from(selector: String) -> Self {
        if selector.starts_with(TICKET_SELECTOR_PREFIX) {
            let secret = Secret::new(selector[TICKET_SELECTOR_PREFIX.len()..].into());
            return AuthSelector::Ticket { secret };
        }

        let mut parts = selector.splitn(2, ':');
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
