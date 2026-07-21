use std::cell::RefCell;
use std::ops::DerefMut;

use crate::{Error, ErrorKind, Result, Secret, SecurityBuffer};

pub struct ChangePassword<'a> {
    pub domain_name: String,
    pub account_name: String,
    pub old_password: Secret<String>,
    pub new_password: Secret<String>,
    pub impersonating: bool,
    pub output: &'a mut [SecurityBuffer],
}

#[derive(Default)]
struct ChangePasswordBuilderInner<'a> {
    domain_name: Option<String>,
    account_name: Option<String>,
    old_password: Option<Secret<String>>,
    new_password: Option<Secret<String>>,
    impersonating: bool,
    output: Option<&'a mut [SecurityBuffer]>,
}

pub struct ChangePasswordBuilder<'a> {
    inner: RefCell<ChangePasswordBuilderInner<'a>>,
}

impl<'a> ChangePasswordBuilder<'a> {
    pub fn new() -> Self {
        Self {
            inner: RefCell::new(ChangePasswordBuilderInner::default()),
        }
    }

    /// Required
    pub fn with_domain_name(&self, domain_name: impl Into<String>) -> &Self {
        self.inner.borrow_mut().domain_name = Some(domain_name.into());
        self
    }

    /// Required
    pub fn with_account_name(&self, account_name: impl Into<String>) -> &Self {
        self.inner.borrow_mut().account_name = Some(account_name.into());
        self
    }

    /// Required
    pub fn with_old_password(&self, old_password: impl Into<String>) -> &Self {
        self.inner.borrow_mut().old_password = Some(old_password.into().into());
        self
    }

    /// Required
    pub fn with_new_password(&self, new_password: impl Into<String>) -> &Self {
        self.inner.borrow_mut().new_password = Some(new_password.into().into());
        self
    }

    /// Optional(default to false if not set)
    pub fn with_impersonating(&self, impersonating: bool) -> &Self {
        self.inner.borrow_mut().impersonating = impersonating;
        self
    }

    /// Required
    pub fn with_output(&self, output: &'a mut [SecurityBuffer]) -> &Self {
        self.inner.borrow_mut().output = Some(output);
        self
    }

    pub fn build(&self) -> Result<ChangePassword<'a>> {
        let mut inner = self.inner.borrow_mut();

        let ChangePasswordBuilderInner {
            domain_name,
            account_name,
            old_password,
            new_password,
            impersonating,
            output,
        } = inner.deref_mut();

        Ok(ChangePassword {
            domain_name: domain_name
                .take()
                .ok_or_else(|| Error::new(ErrorKind::InvalidParameter, "Missing domain_name parameter"))?,
            account_name: account_name
                .take()
                .ok_or_else(|| Error::new(ErrorKind::InvalidParameter, "Missing account_name parameter"))?,
            old_password: old_password
                .take()
                .ok_or_else(|| Error::new(ErrorKind::InvalidParameter, "Missing old_password parameter"))?,
            new_password: new_password
                .take()
                .ok_or_else(|| Error::new(ErrorKind::InvalidParameter, "Missing new_password parameter"))?,
            impersonating: *impersonating,
            output: output
                .take()
                .ok_or_else(|| Error::new(ErrorKind::InvalidParameter, "Missing output parameter"))?,
        })
    }
}

impl Default for ChangePasswordBuilder<'_> {
    fn default() -> Self {
        Self::new()
    }
}
