// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

use cryptovec::CryptoVec;
use std::sync::Arc;
use thrussh_keys::encoding;
use thrussh_keys::key;
use tokio::io::{AsyncRead, AsyncWrite};

bitflags! {
    /// Set of methods, represented by bit flags.
    pub struct MethodSet: u32 {
        /// The SSH `none` method (no authentication).
        const NONE = 1;
        /// The SSH `password` method (plaintext passwords).
        const PASSWORD = 2;
        /// The SSH `publickey` method (sign a challenge sent by the
        /// server).
        const PUBLICKEY = 4;
        /// The SSH `hostbased` method (certain hostnames are allowed
        /// by the server).
        const HOSTBASED = 8;
        /// The SSH `keyboard-interactive` method (answer to a
        /// challenge, where the "challenge" can be a password prompt,
        /// a bytestring to sign with a smartcard, or something else).
        const KEYBOARD_INTERACTIVE = 16;
    }
}

macro_rules! iter {
    ( $y:expr, $x:expr ) => {{
        if $y.contains($x) {
            $y.remove($x);
            return Some($x);
        }
    }};
}

impl Iterator for MethodSet {
    type Item = MethodSet;
    fn next(&mut self) -> Option<MethodSet> {
        iter!(self, MethodSet::NONE);
        iter!(self, MethodSet::PASSWORD);
        iter!(self, MethodSet::PUBLICKEY);
        iter!(self, MethodSet::HOSTBASED);
        iter!(self, MethodSet::KEYBOARD_INTERACTIVE);
        None
    }
}

pub trait Signer: Sized {
    type Error: From<crate::SendError>;
    type Future: futures::Future<Output = (Self, Result<CryptoVec, Self::Error>)> + Send;

    fn auth_publickey_sign(self, key: &key::PublicKey, to_sign: CryptoVec) -> Self::Future;
}

#[derive(Debug, Error)]
pub enum AgentAuthError {
    #[error(transparent)]
    Send(#[from] crate::SendError),
    #[error(transparent)]
    Key(#[from] thrussh_keys::Error),
}

impl<R: AsyncRead + AsyncWrite + Unpin + Send + 'static> Signer
    for thrussh_keys::agent::client::AgentClient<R>
{
    type Error = AgentAuthError;
    type Future = std::pin::Pin<
        Box<dyn futures::Future<Output = (Self, Result<CryptoVec, Self::Error>)> + Send>,
    >;
    fn auth_publickey_sign(self, key: &key::PublicKey, to_sign: CryptoVec) -> Self::Future {
        let fut = self.sign_request(key, to_sign);
        futures::FutureExt::boxed(async move {
            let (a, b) = fut.await;
            (a, b.map_err(AgentAuthError::Key))
        })
    }
}

#[derive(Debug)]
pub enum Method {
    // None,
    Password { password: String },
    PublicKey { key: Arc<key::KeyPair> },
    FuturePublicKey { key: key::PublicKey },
    // Hostbased,
}

impl encoding::Bytes for MethodSet {
    fn bytes(&self) -> &'static [u8] {
        match *self {
            MethodSet::NONE => b"none",
            MethodSet::PASSWORD => b"password",
            MethodSet::PUBLICKEY => b"publickey",
            MethodSet::HOSTBASED => b"hostbased",
            MethodSet::KEYBOARD_INTERACTIVE => b"keyboard-interactive",
            _ => b"",
        }
    }
}

impl MethodSet {
    pub(crate) fn from_bytes(b: &[u8]) -> Option<MethodSet> {
        match b {
            b"none" => Some(MethodSet::NONE),
            b"password" => Some(MethodSet::PASSWORD),
            b"publickey" => Some(MethodSet::PUBLICKEY),
            b"hostbased" => Some(MethodSet::HOSTBASED),
            b"keyboard-interactive" => Some(MethodSet::KEYBOARD_INTERACTIVE),
            _ => None,
        }
    }
}

#[doc(hidden)]
#[derive(Debug)]
pub struct AuthRequest {
    pub methods: MethodSet,
    pub partial_success: bool,
    pub current: Option<CurrentRequest>,
    pub rejection_count: usize,
}

#[doc(hidden)]
#[derive(Debug)]
pub enum CurrentRequest {
    PublicKey {
        key: CryptoVec,
        algo: CryptoVec,
        sent_pk_ok: bool,
    },
    KeyboardInteractive {
        submethods: String,
    },
}
