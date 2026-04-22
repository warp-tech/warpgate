use poem_openapi::{Enum, Object};
use serde::{Deserialize, Serialize};

/// Rules that a password must satisfy.
#[derive(Debug, Clone, Default, Serialize, Deserialize, Object, PartialEq, Eq)]
pub struct PasswordPolicy {
    /// Minimum number of characters (0 = no requirement).
    pub min_length: u32,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digits: bool,
    pub require_special: bool,
}

impl PasswordPolicy {
    pub fn is_empty(&self) -> bool {
        self.min_length == 0
            && !self.require_uppercase
            && !self.require_lowercase
            && !self.require_digits
            && !self.require_special
    }
}

/// A single rule that was violated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Enum)]
pub enum PasswordPolicyViolation {
    TooShort,
    MissingUppercase,
    MissingLowercase,
    MissingDigit,
    MissingSpecial,
}

/// Returns a list of violated rules.  Empty list means the password is accepted.
pub fn validate_password(password: &str, policy: &PasswordPolicy) -> Vec<PasswordPolicyViolation> {
    let mut violations = Vec::new();

    if policy.min_length > 0 && (password.chars().count() as u32) < policy.min_length {
        violations.push(PasswordPolicyViolation::TooShort);
    }
    if policy.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
        violations.push(PasswordPolicyViolation::MissingUppercase);
    }
    if policy.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
        violations.push(PasswordPolicyViolation::MissingLowercase);
    }
    if policy.require_digits && !password.chars().any(|c| c.is_ascii_digit()) {
        violations.push(PasswordPolicyViolation::MissingDigit);
    }
    if policy.require_special
        && !password
            .chars()
            .any(|c| !c.is_alphanumeric() && c.is_ascii())
    {
        violations.push(PasswordPolicyViolation::MissingSpecial);
    }

    violations
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> PasswordPolicy {
        PasswordPolicy {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_digits: true,
            require_special: true,
        }
    }

    #[test]
    fn accepts_strong_password() {
        assert!(validate_password("Str0ng!Pass", &policy()).is_empty());
    }

    #[test]
    fn rejects_too_short() {
        let v = validate_password("Ab1!", &policy());
        assert!(v.contains(&PasswordPolicyViolation::TooShort));
    }

    #[test]
    fn rejects_missing_uppercase() {
        let v = validate_password("str0ng!pass", &policy());
        assert!(v.contains(&PasswordPolicyViolation::MissingUppercase));
    }

    #[test]
    fn rejects_missing_lowercase() {
        let v = validate_password("STR0NG!PASS", &policy());
        assert!(v.contains(&PasswordPolicyViolation::MissingLowercase));
    }

    #[test]
    fn rejects_missing_digit() {
        let v = validate_password("Strong!Pass", &policy());
        assert!(v.contains(&PasswordPolicyViolation::MissingDigit));
    }

    #[test]
    fn rejects_missing_special() {
        let v = validate_password("Str0ngPass", &policy());
        assert!(v.contains(&PasswordPolicyViolation::MissingSpecial));
    }

    #[test]
    fn empty_policy_accepts_anything() {
        let p = PasswordPolicy::default();
        assert!(validate_password("a", &p).is_empty());
        assert!(validate_password("", &p).is_empty());
    }
}
