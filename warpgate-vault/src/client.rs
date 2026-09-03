use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use data_encoding::BASE64;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{debug, warn};
use warpgate_common::{MAX_CERTIFICATE_LIFETIME, VaultAuth, VaultConfig};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Result, VaultError};
use crate::metadata;

/// Re-login this long before the lease actually runs out, so a certificate
/// request issued just after the check cannot race the expiry.
const TOKEN_EXPIRY_MARGIN: Duration = Duration::from_secs(30);

/// How much of a failed response is kept for the error message. Anything
/// answering on the configured address can send an arbitrarily large body, so
/// this bounds what a bad endpoint can make Warpgate allocate.
const MAX_ERROR_BODY: usize = 256;

/// The largest response body accepted from a successful call. A signed
/// certificate is a couple of kilobytes and an auth response smaller still, so
/// the bound is far above anything Vault sends — but without one, an endpoint
/// answering on the configured address can make every session in flight buffer
/// a body of its choosing.
const MAX_RESPONSE_BODY: usize = 256 * 1024;

static NEXT_TOKEN_ID: AtomicU64 = AtomicU64::new(1);

/// Whether this configuration leaves the AWS login request replayable, and why.
///
/// `server_id` is bound into the SigV4 signature as
/// `X-Vault-AWS-IAM-Server-ID`, and Vault checks it against its own
/// `iam_server_id_header_value`. Without it the signed request proves only
/// "this principal", so anyone who obtains one can present it to any other
/// Vault that trusts the same principal — which is exactly what the README says
/// this field prevents, while the field defaulted to unset and said nothing.
///
/// A warning rather than a refusal, matching what this constructor already does
/// for a plain-HTTP loopback address: Vault ignores the header entirely unless
/// `iam_server_id_header_value` is configured, so requiring a value here would
/// force operators to invent one for a server that will not look at it.
fn aws_binding_advice(auth: &VaultAuth) -> Option<&'static str> {
    match auth {
        VaultAuth::Aws {
            server_id: None, ..
        } => Some(
            "vault.auth.server_id is unset, so the signed AWS login request is not bound to \
             this Vault and can be replayed against any other that trusts the same principal. \
             Set it here and as iam_server_id_header_value on the Vault AWS auth mount.",
        ),
        _ => None,
    }
}

/// The address to talk to, or a refusal — the two are not separable.
///
/// Returns the parsed URL rather than `()` so that the only way to obtain
/// something this client will send a request to is to have come through here.
/// Left as a check, with `config.address` still the string every request is
/// built from, the guarantee would be a property of call order — and that is
/// the kind of invariant a later refactor drops silently.
fn validate_address(address: &str) -> Result<url::Url> {
    let parsed = url::Url::parse(address).map_err(|e| VaultError::InvalidAddress(e.to_string()))?;
    // No exception for loopback. Every login sends a credential — a projected
    // service account token, an AppRole secret ID, a signed cloud identity — so
    // an address this client will talk to is one it can talk to in confidence,
    // or it is refused. An exception for a development Vault without a
    // certificate would buy that convenience with a real path along which a
    // secret crosses the wire in the clear.
    if parsed.scheme() != "https" {
        return Err(VaultError::InsecureAddress);
    }
    // A trailing slash so `Url::join` extends the address instead of replacing
    // its last segment: an address behind a reverse proxy at /vault must keep
    // that prefix, and without the slash `join` would drop it.
    let mut parsed = parsed;
    let path = format!("{}/", parsed.path().trim_end_matches('/'));
    parsed.set_path(&path);
    Ok(parsed)
}

fn validate_segment(name: &str) -> Result<()> {
    // The rule itself lives in `warpgate-common`, so the admin API can refuse a
    // name at save time by the same test the signing path applies at connect
    // time. Two copies of a rule are two rules eventually.
    if !warpgate_common::vault_name_is_well_formed(name) {
        return Err(VaultError::InvalidRole(name.to_string()));
    }
    Ok(())
}

/// Vault reads `valid_principals` as a comma-separated list, so a comma in the
/// target's username would silently widen the certificate to accounts the
/// operator never named.
fn validate_principal(principal: &str) -> Result<()> {
    if principal.is_empty() || principal.contains(',') || principal.chars().any(char::is_control) {
        return Err(VaultError::InvalidPrincipal(principal.to_owned()));
    }
    Ok(())
}

/// Enough for `warpgate:<username>:<uuid>` with a username nobody would call
/// unreasonable, and far below anything that would matter in a log line.
const MAX_KEY_ID: usize = 256;

/// The key ID is echoed verbatim into the target's own sshd log — which is the
/// point, since that is what makes a proxied session attributable to a person.
///
/// Both halves matter, and the second was missing. A control character would
/// let a Warpgate username forge log lines there; an unbounded length lets it
/// bury them. A 4 KB username produced a 4 KB key ID, which Vault signed and
/// the target wrote out on every connection — and the check on the *returned*
/// key ID could not see it, because it compares against what was asked for.
fn validate_key_id(key_id: &str) -> Result<()> {
    if key_id.chars().any(char::is_control) || key_id.len() > MAX_KEY_ID {
        return Err(VaultError::InvalidKeyId);
    }
    Ok(())
}

/// Keeps the error message bounded and always a valid string: `from_utf8_lossy`
/// replaces a multi-byte character cut in half by the byte limit instead of
/// panicking the way slicing a `String` at a non-boundary would.
fn render_error_body(bytes: &[u8], truncated: bool) -> String {
    let mut text = String::from_utf8_lossy(bytes).into_owned();
    if truncated {
        text.push_str("... (truncated)");
    }
    text
}

struct CachedToken {
    id: u64,
    value: Zeroizing<String>,
    /// `None` for a token Vault says has no lease.
    ///
    /// Nothing here revokes anything. What a `403` on signing does is drop this
    /// entry so the next call authenticates again — cache invalidation, not
    /// revocation, and the earlier wording said the second. Warpgate never
    /// calls `auth/token/revoke-self`, and the reason it does not is that the
    /// one moment it would want to is exactly when the token has just been
    /// refused: a token Vault rejects for signing would as likely be rejected
    /// for revoking, so the call would fail and the token is already useless.
    /// Vault expires it at the end of its lease either way.
    expires_at: Option<Instant>,
}

/// A secret ID that was delivered response-wrapped, kept alongside the exact
/// file content it came from.
///
/// A wrapping token can be redeemed once, while the secret ID inside it stays
/// usable until its own `secret_id_num_uses` or `secret_id_ttl` runs out — so
/// unwrapping per login would fail every login after the first. Keying on the
/// file content means a freshly provisioned token is still picked up: the file
/// is read on every login, only the redemption is skipped.
struct UnwrappedSecretId {
    source: Zeroizing<String>,
    secret_id: Zeroizing<String>,
}

/// Room reserved for a login payload before anything is written into it. A
/// service account token or a signed AWS header set is a few kilobytes; this is
/// far above that, and the reason it matters is below.
const LOGIN_PAYLOAD_CAPACITY: usize = 32 * 1024;

/// The largest credential file that will be read. A service account token or a
/// wrapped secret ID is a few kilobytes; beyond this the file is not a
/// credential, and reading it would outgrow the payload buffer reserved above
/// and reintroduce the grow-and-copy leak that reservation exists to prevent.
const MAX_CREDENTIAL_FILE: u64 = 16 * 1024;

/// Serializes a login payload into a buffer that is zeroized on drop.
///
/// Public so that `tests/zeroization.rs` can exercise *this* function rather
/// than reimplementing the safe pattern beside it: a test that rebuilds the
/// pattern inline stays green when the real one is reverted, which is exactly
/// what it exists to prevent.
///
/// Written into a buffer reserved up front rather than through
/// `serde_json::to_string`, because a `String` that grows while being written
/// frees each smaller buffer without wiping it — leaving a prefix of the
/// credential-bearing JSON in freed memory on every single login. `Zeroizing`
/// only ever wipes the buffer that survives to the end. Measured, with the
/// mechanism narrowed down, in `tests/zeroization.rs`.
pub fn login_payload<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>> {
    let mut buffer = Zeroizing::new(Vec::with_capacity(LOGIN_PAYLOAD_CAPACITY));
    serde_json::to_writer(&mut *buffer, value)?;
    Ok(buffer)
}

/// Wipes the signed AWS headers on every path out of the function that holds
/// them.
///
/// They carry the SigV4 signature and, on an instance role, the session token.
/// A wipe at the end of the function is skipped by the one path where
/// something has already gone wrong. `Drop` is not.
///
/// Not covered by a test, and cannot be: once `Drop` has run there is nothing
/// left to assert against, and a test that wipes a map itself proves only that
/// `zeroize` works.
struct WipedHeaders(warpgate_aws::StsIdentityRequest);

impl Drop for WipedHeaders {
    fn drop(&mut self) {
        for value in self.0.headers.values_mut() {
            value.zeroize();
        }
    }
}

#[derive(Serialize)]
struct JwtLogin<'a> {
    role: &'a str,
    jwt: &'a str,
}

#[derive(Serialize)]
struct AppRoleLogin<'a> {
    role_id: &'a str,
    secret_id: &'a str,
}

#[derive(Serialize)]
struct AzureLogin<'a> {
    role: &'a str,
    jwt: &'a str,
    subscription_id: &'a str,
    resource_group_name: &'a str,
    vm_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    vmss_name: Option<&'a str>,
}

#[derive(Serialize)]
struct AwsLogin<'a> {
    role: Option<&'a str>,
    iam_http_request_method: &'a str,
    iam_request_url: &'a str,
    iam_request_body: &'a str,
    iam_request_headers: &'a str,
}

#[derive(Serialize)]
struct SignRequest<'a> {
    public_key: &'a str,
    valid_principals: &'a str,
    cert_type: &'a str,
    key_id: &'a str,
    /// Omitted rather than sent as zero when unset: Vault reads a zero TTL as
    /// "use the role's default", but only if the field is absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<String>,
}

#[derive(Deserialize)]
struct AuthResponse {
    auth: AuthData,
}

#[derive(Deserialize)]
struct AuthData {
    client_token: String,
    lease_duration: u64,
}

#[derive(Deserialize)]
struct SignResponse {
    data: SignData,
}

#[derive(Deserialize)]
struct SignData {
    signed_key: String,
}

#[derive(Deserialize)]
struct UnwrapResponse {
    data: Option<UnwrapData>,
}

#[derive(Deserialize)]
struct UnwrapData {
    secret_id: Option<String>,
}

/// Reads a response into a bounded, zeroized buffer.
///
/// At module level and `pub(crate)` because the metadata calls answer to the
/// same argument as the Vault ones: an endpoint named in the configuration is
/// not a trusted party, and what it returns is a credential.
/// Makes room for `incoming` more bytes without leaving the old buffer behind.
///
/// `Vec` grows by allocating, copying and freeing, and it frees the old block
/// itself — `Zeroizing` only ever wipes the one that survives to be dropped. So
/// a buffer reserved at 32 KiB and grown past it leaves a credential-bearing
/// copy in freed memory, which reserving up front was supposed to prevent and
/// only made less likely.
///
/// `zeroization.rs` finds the canary in the freed block.
///
/// Moving to a new buffer by hand keeps the old one ours until it is dropped,
/// so its own `Zeroizing` wipes it before the allocator takes it back.
///
/// Public so the test exercises this function rather than a copy of its shape
/// written beside it, which is also why `login_payload` is public.
#[must_use]
pub fn grown_without_leaving_a_copy(
    buf: Zeroizing<Vec<u8>>,
    incoming: usize,
) -> Zeroizing<Vec<u8>> {
    if buf.len() + incoming <= buf.capacity() {
        return buf;
    }
    let wanted = (buf.capacity() * 2).max(buf.len() + incoming);
    let mut grown: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(wanted));
    grown.extend_from_slice(&buf);
    grown
}

pub(crate) async fn read_bounded(mut response: reqwest::Response) -> Result<Zeroizing<Vec<u8>>> {
    // Reserved up front, for the reason spelled out on `login_payload`: a buffer
    // that grows frees every size it outgrew without wiping it, and `Zeroizing`
    // only clears the one that survives. Every caller of this function carries a
    // credential — the Vault token, an AppRole secret ID, a cloud identity JWT —
    // so the response path needed the same treatment as the request path and did
    // not get it. A GCE `format=full` identity token is around 2 KiB and
    // arrives in more than one chunk, which is exactly the case that reallocs.
    //
    // Not `MAX_RESPONSE_BODY`: that is the refusal threshold, not an
    // expectation. Anything past this reserve is far larger than a credential.
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(LOGIN_PAYLOAD_CAPACITY));
    while let Some(chunk) = response.chunk().await? {
        if buf.len() + chunk.len() > MAX_RESPONSE_BODY {
            return Err(VaultError::OversizedResponse);
        }
        // Grown by hand, because `Vec` frees the old allocation itself and
        // `Zeroizing` only ever sees the one that survives. Reserving up front
        // was supposed to make growth impossible; it only made it unlikely, and
        // a response between the reserve and the refusal threshold reallocated
        // with a credential in it. Measured, after being argued about twice and
        // dismissed both times: `zeroization.rs` finds the canary in a freed
        // block for a 64 KiB body.
        //
        // Moving to a new buffer explicitly means the old one is dropped while
        // it is still ours, so its own `Zeroizing` wipes it before the allocator
        // gets it back.
        buf = grown_without_leaving_a_copy(buf, chunk.len());
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

pub(crate) async fn read_bounded_json<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T> {
    let buf = read_bounded(response).await?;
    Ok(serde_json::from_slice(&buf)?)
}

pub struct VaultClient {
    config: VaultConfig,
    /// The validated address every request is built from. Not read back out of
    /// `config`, which holds the unvalidated string the operator wrote.
    base: url::Url,
    http: reqwest::Client,
    metadata_http: reqwest::Client,
    token: Mutex<Option<CachedToken>>,
    unwrapped_secret_id: Mutex<Option<UnwrappedSecretId>>,
}

impl VaultClient {
    pub fn new(config: VaultConfig) -> Result<Self> {
        let base = validate_address(&config.address)?;
        validate_segment(&config.mount)?;
        validate_segment(&config.default_role)?;

        // Both ends of the range, caught here rather than at connect time.
        //
        // A sub-second TTL truncates to "0s", which both Vault and OpenBao
        // refuse. One above the ceiling is refused on arrival by the certificate
        // check instead. Either way the mistake would otherwise surface as a
        // failed session for every target at once, with nothing pointing at the
        // config line that caused it — and that argument, written here for the
        // lower bound, applies identically to the upper one, which is the half
        // it was not applied to.
        if let Some(ttl) = config.certificate_ttl
            && (ttl.as_secs() == 0 || ttl > MAX_CERTIFICATE_LIFETIME)
        {
            return Err(VaultError::InvalidCertificateTtl(ttl));
        }

        if let Some(advice) = aws_binding_advice(&config.auth) {
            warn!("{advice}");
        }

        // Redirects are refused rather than followed: reqwest strips
        // `Authorization` on a cross-origin hop but knows nothing about
        // `X-Vault-Token`, so a 307 from a hostile or misconfigured endpoint
        // would replay the token to another host, or downgrade the request to
        // plain HTTP.
        // A Vault behind a private CA. Added to the host's trust store rather
        // than replacing it, and read here so an unreadable or malformed bundle
        // is a startup error naming the file, not a signing failure on every
        // target at once with nothing pointing at the config line.
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(config.timeout);
        if let Some(path) = config.ca_bundle.as_ref() {
            let pem = std::fs::read(path).map_err(|source| VaultError::CaBundle {
                path: path.clone(),
                reason: source.to_string(),
            })?;
            for certificate in reqwest::Certificate::from_pem_bundle(&pem).map_err(|source| {
                VaultError::CaBundle {
                    path: path.clone(),
                    reason: source.to_string(),
                }
            })? {
                builder = builder.add_root_certificate(certificate);
            }
        }
        let http = builder.build()?;

        // The metadata services are link-local and plain HTTP by definition, and
        // reqwest honours HTTP_PROXY/HTTPS_PROXY by default — a proxy in the
        // environment would carry the instance identity token off the host.
        // GCE's default address is a hostname, so the usual IP-based NO_PROXY
        // list does not cover it. Vault's own address keeps ambient proxy
        // support, since reaching it through one is a legitimate deployment.
        let metadata_http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(config.timeout)
            .build()?;

        Ok(Self {
            config,
            base,
            http,
            metadata_http,
            token: Mutex::new(None),
            unwrapped_secret_id: Mutex::new(None),
        })
    }

    pub fn default_role(&self) -> &str {
        &self.config.default_role
    }

    /// How long any single call to Vault may take.
    ///
    /// Exposed because the connection path has to budget for several of them.
    pub const fn timeout(&self) -> Duration {
        self.config.timeout
    }

    /// The lifetime asked for when signing, if the operator set one.
    ///
    /// Exposed because asking is not getting: what comes back is checked
    /// against it.
    pub const fn certificate_ttl(&self) -> Option<Duration> {
        self.config.certificate_ttl
    }

    /// The signing CA the operator pinned, if any.
    ///
    /// Exposed for the same reason as the TTL, one step further: the crate
    /// speaks Vault and returns an OpenSSH string, so the party that parses
    /// certificates is the one that compares them.
    pub fn pinned_ca_public_key(&self) -> Option<&str> {
        self.config.ca_public_key.as_deref()
    }

    /// Reads the on-disk half of the configured credential, without logging in.
    ///
    /// `warpgate check` exists to find a broken config before a session depends
    /// on it, the way it already does for the listeners' TLS material.
    /// Constructing this client validates the address, mount and role names,
    /// but the Kubernetes token and the AppRole secret ID are read per login
    /// rather than at construction — so a typo in either path passed the check
    /// and then failed every certificate session. The cloud methods have no
    /// file to read here: their credential comes from an SDK chain or a
    /// metadata service, reachable only at login.
    ///
    /// A read and not `login_body()`, deliberately: a response-wrapped secret
    /// ID is redeemed once, and spending that redemption here would make the
    /// first real login fail.
    pub async fn check_credential(&self) -> Result<()> {
        match &self.config.auth {
            VaultAuth::Kubernetes { token_path, .. } => {
                Self::read_credential(token_path).await?;
            }
            VaultAuth::AppRole { secret_id_path, .. } => {
                Self::read_credential(secret_id_path).await?;
            }
            VaultAuth::Aws { .. } | VaultAuth::Azure { .. } | VaultAuth::Gcp { .. } => {}
        }
        Ok(())
    }

    /// Signs `public_key` into a short-lived OpenSSH user certificate, returned
    /// in OpenSSH wire format.
    ///
    /// `principals` are usernames on the target, not Warpgate usernames. `key_id`
    /// is echoed into the target's own sshd log, which is what makes a session
    /// attributable to a person rather than to the gateway.
    pub async fn sign_ssh_key(
        &self,
        role: &str,
        public_key: &str,
        principals: &str,
        key_id: &str,
    ) -> Result<String> {
        validate_segment(role)?;
        validate_principal(principals)?;
        validate_key_id(key_id)?;

        let (token_id, result) = self.sign_once(role, public_key, principals, key_id).await;

        match result {
            // A cached token can stop being accepted long before its lease runs
            // out — it may have been revoked, or Vault resealed or restarted.
            // Forcing one re-login tells that apart from a real policy denial.
            // Only invalidate if the token in cache is still the token that failed.
            Err(VaultError::Api { status, .. }) if status == StatusCode::FORBIDDEN => {
                let mut guard = self.token.lock().await;
                if guard.as_ref().map(|t| t.id) == Some(token_id) {
                    *guard = None;
                }
                drop(guard);
                let (_, second_try) = self.sign_once(role, public_key, principals, key_id).await;
                second_try
            }
            res => res,
        }
    }

    async fn sign_once(
        &self,
        role: &str,
        public_key: &str,
        principals: &str,
        key_id: &str,
    ) -> (u64, Result<String>) {
        let (token_id, token) = match self.token().await {
            Ok(t) => t,
            Err(err) => return (0, Err(err)),
        };
        // The token id rides along so the caller can tell a stale token from a
        // refused one, which is why this returns a tuple and cannot use `?`.
        let endpoint = match self.url(&format!("{}/sign/{role}", self.config.mount)) {
            Ok(url) => url,
            Err(err) => return (token_id, Err(err)),
        };

        let response = self
            .http
            .post(endpoint)
            .header("X-Vault-Token", token.as_str())
            .json(&SignRequest {
                public_key,
                valid_principals: principals,
                cert_type: "user",
                key_id,
                ttl: self
                    .config
                    .certificate_ttl
                    .map(|ttl| format!("{}s", ttl.as_secs())),
            })
            .send()
            .await;

        let res = match response {
            Ok(resp) => match Self::check(resp).await {
                Ok(resp) => match Self::read_json::<SignResponse>(resp).await {
                    Ok(parsed) => {
                        debug!(role, principals, key_id, "Issued an SSH certificate");
                        Ok(parsed.data.signed_key)
                    }
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
            },
            Err(e) => Err(VaultError::Request(e)),
        };

        (token_id, res)
    }

    /// The cached client token, logging in again once it nears expiry. Plain
    /// re-login is used instead of Vault's renew API because it behaves the same
    /// whether or not the token has hit its `max_ttl`.
    ///
    /// The lock is deliberately held across the login: one expiring token would
    /// otherwise send every session in flight to Vault at once, and for the
    /// cloud methods each of those first fetches an identity token of its own.
    /// The cost of that choice is that a slow login delays every other session
    /// by up to `timeout`.
    async fn token(&self) -> Result<(u64, Zeroizing<String>)> {
        let mut cached = self.token.lock().await;

        if let Some(token) = cached.as_ref()
            && token.expires_at.is_none_or(|at| Instant::now() < at)
        {
            return Ok((token.id, token.value.clone()));
        }

        // Bounded here rather than inside `login()`, because the bound has to
        // cover assembling the request as well as sending it. `reqwest` times
        // out the POST; `login_body()` reads a credential — a file for the
        // Kubernetes and AppRole methods, the whole SDK credential chain for
        // AWS — and nothing bounded that. Since this lock is held across the
        // login on purpose, an unbounded read here is not one stalled session
        // but all of them.
        let token = tokio::time::timeout(self.config.timeout, self.login())
            .await
            .map_err(|_| VaultError::LoginTimeout)??;
        let id = token.id;
        let value = token.value.clone();
        *cached = Some(token);
        Ok((id, value))
    }

    async fn login(&self) -> Result<CachedToken> {
        let (path, body) = self.login_body().await?;

        let response = self
            .http
            .post(self.url(path)?)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_vec())
            .send()
            .await?;
        let auth = Self::read_json::<AuthResponse>(Self::check(response).await?)
            .await?
            .auth;

        debug!(method = self.config.auth.kind(), "Authenticated to Vault");

        let token_id = NEXT_TOKEN_ID.fetch_add(1, Ordering::Relaxed);
        Ok(CachedToken {
            id: token_id,
            value: Zeroizing::new(auth.client_token),
            // Vault reports a lease of zero for a token that does not expire.
            // Reading that as "expired half a minute ago" would turn every
            // certificate request into a fresh login.
            //
            // The lease is an unbounded number out of a network response, and
            // `Instant + Duration` panics on overflow, so an absurd one is
            // rejected as a bad response rather than taken at its word.
            expires_at: match auth.lease_duration {
                0 => None,
                seconds => Some(
                    Instant::now()
                        .checked_add(
                            Duration::from_secs(seconds).saturating_sub(TOKEN_EXPIRY_MARGIN),
                        )
                        .ok_or(VaultError::InvalidLease(seconds))?,
                ),
            },
        })
    }

    /// The endpoint and JSON payload for the configured authentication method.
    ///
    /// The payload is built through `serde` straight into a `Zeroizing` buffer
    /// rather than through a `serde_json::Value`: every intermediate copy of a
    /// service account token, secret ID or identity token is one more place the
    /// credential outlives the request in freed memory. The buffer reqwest takes
    /// to put the body on the wire is the one copy Warpgate cannot reach.
    async fn login_body(&self) -> Result<(&'static str, Zeroizing<Vec<u8>>)> {
        Ok(match &self.config.auth {
            VaultAuth::Kubernetes { role, token_path } => {
                let jwt = Self::read_credential(token_path).await?;
                (
                    "auth/kubernetes/login",
                    login_payload(&JwtLogin { role, jwt: &jwt })?,
                )
            }
            VaultAuth::AppRole {
                role_id,
                secret_id_path,
            } => {
                let cred = Self::read_credential(secret_id_path).await?;
                let secret_id = if cred.starts_with("unwrap:") {
                    self.unwrapped_secret_id(secret_id_path, &cred).await?
                } else {
                    cred
                };
                (
                    "auth/approle/login",
                    login_payload(&AppRoleLogin {
                        role_id: role_id.expose_secret(),
                        secret_id: &secret_id,
                    })?,
                )
            }
            VaultAuth::Aws {
                role,
                server_id,
                region,
            } => (
                "auth/aws/login",
                self.aws_login_body(role.as_deref(), server_id.as_deref(), region.as_deref())
                    .await?,
            ),
            VaultAuth::Azure {
                role,
                resource,
                metadata_address,
            } => {
                let (jwt, instance) =
                    metadata::azure_login_material(&self.metadata_http, metadata_address, resource)
                        .await?;
                (
                    "auth/azure/login",
                    login_payload(&AzureLogin {
                        role,
                        jwt: &jwt,
                        subscription_id: &instance.subscription_id,
                        resource_group_name: &instance.resource_group_name,
                        vm_name: &instance.name,
                        vmss_name: (!instance.vm_scale_set_name.is_empty())
                            .then_some(instance.vm_scale_set_name.as_str()),
                    })?,
                )
            }
            VaultAuth::Gcp {
                role,
                metadata_address,
            } => {
                let audience = format!("vault/{role}");
                let jwt =
                    metadata::gcp_identity_token(&self.metadata_http, metadata_address, &audience)
                        .await?;
                (
                    "auth/gcp/login",
                    login_payload(&JwtLogin { role, jwt: &jwt })?,
                )
            }
        })
    }

    /// The secret ID behind a `unwrap:<token>` file, redeeming the wrapping
    /// token the first time and on every later change to the file.
    async fn unwrapped_secret_id(
        &self,
        path: &Path,
        cred: &Zeroizing<String>,
    ) -> Result<Zeroizing<String>> {
        let mut cached = self.unwrapped_secret_id.lock().await;

        if let Some(entry) = cached.as_ref()
            && entry.source.as_str() == cred.as_str()
        {
            return Ok(entry.secret_id.clone());
        }

        let wrapping_token = Zeroizing::new(cred.trim_start_matches("unwrap:").trim().to_owned());
        let secret_id = self.unwrap_secret_id(&wrapping_token).await.map_err(|e| {
            VaultError::SecretIdUnwrap {
                path: path.to_owned(),
                source: Box::new(e),
            }
        })?;

        *cached = Some(UnwrappedSecretId {
            source: cred.clone(),
            secret_id: secret_id.clone(),
        });
        Ok(secret_id)
    }

    async fn unwrap_secret_id(&self, wrapping_token: &str) -> Result<Zeroizing<String>> {
        let response = self
            .http
            .post(self.url("sys/wrapping/unwrap")?)
            .header("X-Vault-Token", wrapping_token)
            .send()
            .await?;

        let unwrap_resp = Self::read_json::<UnwrapResponse>(Self::check(response).await?).await?;

        // Moved rather than copied out of the response, so the only allocation
        // holding the secret ID is the one that gets zeroized on drop.
        unwrap_resp
            .data
            .and_then(|data| data.secret_id)
            .map_or_else(
                || {
                    Err(VaultError::Api {
                        status: StatusCode::BAD_REQUEST,
                        body: "failed to unwrap secret_id from Vault response".to_owned(),
                    })
                },
                |secret_id| Ok(Zeroizing::new(secret_id)),
            )
    }

    async fn aws_login_body(
        &self,
        role: Option<&str>,
        server_id: Option<&str>,
        region: Option<&str>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let request =
            WipedHeaders(warpgate_aws::sign_sts_identity_request(region, server_id).await?);

        // The headers carry the SigV4 signature and, on an instance role, the
        // session token — the one part of this request worth protecting. The URL
        // and body are the same public constants on every call. Every buffer
        // they pass through is zeroized, to match what the other methods do with
        // their credentials.
        // Through the same sized buffer `login_payload` uses, and for the same
        // reason: `serde_json::to_string` grows its `String` as it writes and
        // frees each smaller one unwiped. These headers carry the SigV4
        // signature and, on an instance role, the session token — so this was
        // the one call site still doing what the comment on `login_payload`
        // forbids, one function away from it.
        let mut headers = Zeroizing::new(Vec::with_capacity(LOGIN_PAYLOAD_CAPACITY));
        serde_json::to_writer(&mut *headers, &request.0.headers)?;
        let encoded_headers = Zeroizing::new(BASE64.encode(&headers));

        login_payload(&AwsLogin {
            role,
            iam_http_request_method: request.0.method,
            iam_request_url: &BASE64.encode(request.0.url.as_bytes()),
            iam_request_body: &BASE64.encode(request.0.body.as_bytes()),
            iam_request_headers: &encoded_headers,
        })
    }

    /// `read_to_string` sizes its buffer from the file's own length, so it does
    /// not grow while reading and leaves nothing behind — measured, rather than
    /// assumed, in `tests/zeroization.rs`. That holds only while the file is
    /// small enough to fit the reserved payload buffer, hence the cap.
    async fn read_credential(path: &Path) -> Result<Zeroizing<String>> {
        let describe = |source| VaultError::CredentialFile {
            path: path.to_owned(),
            source,
        };

        // One handle, opened once, and a bound on the stream rather than on
        // what a separate `stat` claimed.
        //
        // Opening the path twice — `metadata` then `read_to_string` — lets the
        // file be replaced between the two, and a FIFO reports a length of zero
        // and then delivers as much as it likes. The token mutex is held across
        // login, so blocking here stalls every session at once rather than one.
        let file = tokio::fs::File::open(path).await.map_err(describe)?;
        let size = file.metadata().await.map_err(describe)?.len();
        if size > MAX_CREDENTIAL_FILE {
            return Err(VaultError::CredentialTooLarge {
                path: path.to_owned(),
                size,
            });
        }

        // Reserved at the cap rather than at the reported size: a buffer that
        // grows frees every smaller size unwiped, and the reported size is the
        // number this function no longer trusts.
        let mut raw = Zeroizing::new(String::with_capacity(MAX_CREDENTIAL_FILE as usize + 1));
        use tokio::io::AsyncReadExt as _;
        let read = file
            .take(MAX_CREDENTIAL_FILE + 1)
            .read_to_string(&mut raw)
            .await
            .map_err(describe)? as u64;
        if read > MAX_CREDENTIAL_FILE {
            return Err(VaultError::CredentialTooLarge {
                path: path.to_owned(),
                size: read,
            });
        }
        Ok(Zeroizing::new(raw.trim().to_owned()))
    }

    /// Joins onto the parsed base rather than formatting a string, so the URL
    /// that reaches the HTTP client still carries the scheme `validate_address`
    /// insisted on. Built by `format!` it is only text, and nothing downstream —
    /// a reader, or an analyser — can tell it was ever checked.
    fn url(&self, path: &str) -> Result<url::Url> {
        self.base
            .join(&format!("v1/{path}"))
            .map_err(|e| VaultError::InvalidAddress(e.to_string()))
    }

    /// Parses a successful response, refusing one larger than any Vault answer
    /// could be. `json()` would buffer whatever arrives before anything got to
    /// look at its size, so a single endpoint could hold as much of Warpgate's
    /// memory as it cared to send, once per session in flight.
    async fn read_json<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<T> {
        read_bounded_json(response).await
    }

    async fn check(response: reqwest::Response) -> Result<reqwest::Response> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        Err(VaultError::Api {
            status,
            body: Self::error_body(response).await,
        })
    }

    /// The first `MAX_ERROR_BODY` bytes of a failed response. Read chunk by
    /// chunk rather than with `text()`, which would buffer the whole body before
    /// there was anything to truncate — an endpoint answering on the configured
    /// address could then make an error message cost arbitrary memory.
    async fn error_body(mut response: reqwest::Response) -> String {
        // Wiped and reserved up front, like the credential path beside it.
        // Vault's error bodies are its own words rather than a secret, but they
        // are read off the same connection as the token and this is the last
        // buffer on that path without the treatment. The reserve is what makes
        // the wipe complete: a `Vec` that grows frees every size it outgrew
        // without wiping it, and `Zeroizing` only ever sees the one that lives.
        let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(MAX_ERROR_BODY));
        let mut truncated = false;

        while buf.len() < MAX_ERROR_BODY {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    let room = MAX_ERROR_BODY.saturating_sub(buf.len());
                    let taken = chunk.get(..room).unwrap_or(&chunk);
                    truncated |= taken.len() < chunk.len();
                    buf.extend_from_slice(taken);
                }
                Ok(None) | Err(_) => break,
            }
        }

        // The loop can fill the buffer exactly while the body continues; one
        // more poll is what tells a 256-byte body from a truncated one.
        if !truncated && buf.len() == MAX_ERROR_BODY {
            truncated = matches!(response.chunk().await, Ok(Some(chunk)) if !chunk.is_empty());
        }

        render_error_body(&buf, truncated)
    }
}

#[cfg(test)]
mod tests {
    /// `Url::join` replaces the last path segment unless the base ends in a
    /// slash, so a Vault reached through a reverse proxy at /vault would have
    /// had that prefix silently dropped from every request.
    #[test]
    fn a_path_prefix_on_the_address_survives_into_every_request() {
        let base = super::validate_address("https://vault.example:8200/vault").unwrap();
        assert_eq!(
            base.join("v1/ssh/sign/role").unwrap().as_str(),
            "https://vault.example:8200/vault/v1/ssh/sign/role"
        );

        let bare = super::validate_address("https://vault.example:8200").unwrap();
        assert_eq!(
            bare.join("v1/ssh/sign/role").unwrap().as_str(),
            "https://vault.example:8200/v1/ssh/sign/role"
        );
    }

    use std::path::PathBuf;
    use std::sync::{Arc, Mutex as StdMutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// A directory that goes away when the test does.
    ///
    /// A fixed name under the system temp directory would be shared by every
    /// run of the test, and several of these hold real credential material: two
    /// runs at once clobber each other, a crashed run leaves the file behind,
    /// and on a shared machine the name is guessable by anyone who read this
    /// file.
    fn scratch() -> tempfile::TempDir {
        tempfile::tempdir().expect("could not create a temporary directory")
    }

    /// A one-shot HTTP server that records the raw request it was sent.
    ///
    /// `login` answers the authentication endpoint, `other` everything else, so
    /// a test can let the client reach the point where it holds a token.
    /// One self-signed certificate for every stand-in Vault in this module.
    ///
    /// These tests talk over TLS because the client refuses anything else,
    /// loopback included. Shared rather than per-server so adding a test needs
    /// no ceremony, and so the bundle path is a constant `approle_config` can
    /// reach without threading it through nine call sites.
    fn test_tls() -> &'static (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        Vec<u8>,
        PathBuf,
    ) {
        static TLS: std::sync::OnceLock<(
            Vec<rustls::pki_types::CertificateDer<'static>>,
            Vec<u8>,
            PathBuf,
        )> = std::sync::OnceLock::new();
        TLS.get_or_init(|| {
            // Here rather than in individual tests. Three of them installed the
            // provider and the rest relied on one of those three having run
            // first — true when the tests run in order, false when cargo runs
            // them in parallel, and then whichever TLS test started first hung
            // until its timeout. Every TLS test reaches this helper, and
            // `get_or_init` makes the install happen exactly once.
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
            let dir = std::env::temp_dir().join("warpgate-vault-test-tls");
            std::fs::create_dir_all(&dir).unwrap();
            let bundle = dir.join("ca.pem");
            std::fs::write(&bundle, cert.cert.pem()).unwrap();
            (
                vec![cert.cert.der().clone()],
                cert.signing_key.serialize_der(),
                bundle,
            )
        })
    }

    fn test_ca_bundle() -> PathBuf {
        test_tls().2.clone()
    }

    fn test_tls_acceptor() -> tokio_rustls::TlsAcceptor {
        let (chain, key_der, _) = test_tls();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.clone().into());
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain.clone(), key)
            .unwrap();
        tokio_rustls::TlsAcceptor::from(Arc::new(config))
    }

    async fn spawn_server(
        login: String,
        other: String,
        log: Arc<StdMutex<Vec<String>>>,
    ) -> Result<String> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("https://{}", listener.local_addr().unwrap());
        let acceptor = test_tls_acceptor();

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let Ok(mut socket) = acceptor.accept(stream).await else {
                    continue;
                };
                let mut buf = vec![0u8; 8192];
                let read = socket.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..read]).into_owned();
                let response = if request.contains("/login") {
                    login.clone()
                } else {
                    other.clone()
                };
                log.lock().unwrap().push(request);
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });

        Ok(address)
    }

    /// Answers the login endpoint normally and then streams an error body that
    /// never ends — the shape of a hostile or broken endpoint.
    async fn spawn_endless_error_server(login: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("https://{}", listener.local_addr().unwrap());
        let acceptor = test_tls_acceptor();

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let Ok(mut socket) = acceptor.accept(stream).await else {
                    continue;
                };
                let mut buf = vec![0u8; 8192];
                let read = socket.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..read]).into_owned();

                if request.contains("/login") {
                    let _ = socket.write_all(login.as_bytes()).await;
                    let _ = socket.shutdown().await;
                    continue;
                }

                let _ = socket
                    .write_all(
                        b"HTTP/1.1 500 Internal Server Error\r\nTransfer-Encoding: chunked\r\n\r\n",
                    )
                    .await;
                // Paced, so a reader that waits for the end cannot finish
                // before the request timeout no matter how fast the loopback is.
                let chunk = format!("1000\r\n{}\r\n", "a".repeat(4096));
                for _ in 0..1000 {
                    if socket.write_all(chunk.as_bytes()).await.is_err() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
        });

        address
    }

    fn json_response(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    /// Both ends of the range are refused where the operator can see it.
    ///
    /// The lower bound was checked here and the upper one was not, though the
    /// comment beside it argues for both: a bad value surfacing as every target
    /// failing at once, with nothing naming the config line.
    #[tokio::test]
    async fn a_certificate_ttl_outside_the_allowed_range_is_refused_at_construction() {
        for (ttl, why) in [
            (Duration::from_millis(500), "sub-second, truncates to 0s"),
            (
                MAX_CERTIFICATE_LIFETIME + Duration::from_secs(1),
                "over the ceiling",
            ),
            (
                Duration::from_secs(90 * 24 * 60 * 60),
                "far over the ceiling",
            ),
        ] {
            let mut config = approle_config(
                "https://vault.invalid".to_owned(),
                PathBuf::from("/dev/null"),
            );
            config.certificate_ttl = Some(ttl);
            let error = VaultClient::new(config).err();
            assert!(
                matches!(error, Some(VaultError::InvalidCertificateTtl(_))),
                "{why}: expected InvalidCertificateTtl, got {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_certificate_ttl_inside_the_range_is_accepted() {
        // Unlike the refusals above, this one builds a real client.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        for ttl in [
            Duration::from_secs(1),
            Duration::from_secs(180),
            MAX_CERTIFICATE_LIFETIME,
        ] {
            let mut config = approle_config(
                "https://vault.invalid".to_owned(),
                PathBuf::from("/dev/null"),
            );
            config.certificate_ttl = Some(ttl);
            assert!(
                VaultClient::new(config).is_ok(),
                "{ttl:?} should be accepted"
            );
        }
    }

    /// A FIFO reports a length of zero and then delivers whatever it likes.
    ///
    /// The token mutex is held across login, so a credential path that never
    /// ends stalls every session rather than one.
    ///
    /// A FIFO and not an oversized regular file: that is refused by the `stat`
    /// early-out and by the stream bound alike, and a test both guards answer
    /// cannot say which one is working. A FIFO separates them — `stat` reports
    /// zero, so only the bound on what actually arrives can refuse it.
    #[tokio::test]
    async fn only_the_stream_bound_can_refuse_a_source_that_lies_about_its_size() {
        let tmp = scratch();
        let dir = tmp.path();
        let path = dir.join("lying");
        // The `mkfifo` command rather than the libc call: std has no API for
        // this file type, and shelling out costs a process where the
        // alternative costs a dependency and an `unsafe` block in a crate that
        // denies both.
        let made = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("mkfifo is not available");
        assert!(made.success(), "could not create the FIFO");

        // `stat` on a FIFO reports zero regardless of what is coming, which is
        // the lie. Written from another thread because opening a FIFO for
        // writing blocks until a reader arrives.
        let writer_path = path.clone();
        let writer = std::thread::spawn(move || {
            use std::io::Write as _;
            if let Ok(mut fifo) = std::fs::OpenOptions::new().write(true).open(&writer_path) {
                // More than the cap, in chunks, ignoring the broken pipe that
                // arrives when the reader gives up — which is the pass case.
                let chunk = "z".repeat(4096);
                for _ in 0..((MAX_CREDENTIAL_FILE / 4096) + 4) {
                    if fifo.write_all(chunk.as_bytes()).is_err() {
                        break;
                    }
                }
            }
        });

        let reported = std::fs::metadata(&path).unwrap().len();
        assert_eq!(
            reported, 0,
            "a FIFO that reports a size is not the case here"
        );

        let outcome = VaultClient::read_credential(&path).await;
        assert!(
            matches!(outcome, Err(VaultError::CredentialTooLarge { .. })),
            "a source that under-reports its size was accepted: {outcome:?}"
        );

        let _ = writer.join();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The `stat` early-out, on the only input that reaches it first.
    #[tokio::test]
    async fn an_oversized_regular_file_is_refused() {
        let tmp = scratch();
        let dir = tmp.path();
        let path = dir.join("oversized");
        std::fs::write(&path, "x".repeat((MAX_CREDENTIAL_FILE + 1024) as usize)).unwrap();
        assert!(
            matches!(
                VaultClient::read_credential(&path).await,
                Err(VaultError::CredentialTooLarge { .. })
            ),
            "an oversized credential file was accepted"
        );

        // And one at the cap is still read.
        std::fs::write(&path, "y".repeat(64)).unwrap();
        let read = VaultClient::read_credential(&path)
            .await
            .expect("a normal credential");
        assert_eq!(read.len(), 64);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The field the README calls the replay defence, defaulting to unset and
    /// saying nothing about it.
    #[test]
    fn an_unbound_aws_login_is_called_out() {
        let unbound = VaultAuth::Aws {
            role: None,
            server_id: None,
            region: None,
        };
        let advice = aws_binding_advice(&unbound).expect("an unbound AWS login");
        assert!(advice.contains("replayed"), "{advice}");

        let bound = VaultAuth::Aws {
            role: None,
            server_id: Some("vault.internal".to_owned()),
            region: None,
        };
        assert!(aws_binding_advice(&bound).is_none());

        // Nothing to say about the methods that carry no such binding.
        assert!(
            aws_binding_advice(&VaultAuth::AppRole {
                role_id: "r".to_owned().into(),
                secret_id_path: PathBuf::from("/dev/null"),
            })
            .is_none()
        );
    }

    /// The same, with no `ca_bundle`, for the one test whose subject is what
    /// happens when a certificate is *not* trusted. Handing that test the shared
    /// bundle would have it verify against a root store instead of the platform
    /// verifier — a different mechanism from the one it means to exercise.
    fn approle_config_without_bundle(address: String, secret_id_path: PathBuf) -> VaultConfig {
        VaultConfig {
            ca_bundle: None,
            ..approle_config(address, secret_id_path)
        }
    }

    fn approle_config(address: String, secret_id_path: PathBuf) -> VaultConfig {
        VaultConfig {
            address,
            mount: "ssh-client-signer".to_owned(),
            default_role: "warpgate".to_owned(),
            ca_public_key: None,
            auth: VaultAuth::AppRole {
                role_id: "role-1".to_owned().into(),
                secret_id_path,
            },
            certificate_ttl: None,
            // Not a latency assertion: the tests that care about the timeout set
            // their own, and for the rest this only decides how slow a machine
            // has to be before a login over TLS is reported as the behaviour
            // under test failing.
            timeout: Duration::from_secs(30),
            ca_bundle: Some(test_ca_bundle()),
        }
    }

    /// reqwest strips `Authorization` on a cross-origin redirect but has no idea
    /// `X-Vault-Token` is a credential, so following one would hand the token to
    /// whichever host the redirect names.
    #[tokio::test]
    async fn test_a_redirect_never_carries_the_token_to_another_host() {
        // The binary does this in `main`; a unit test has to do it itself before
        // reqwest will build a client at all.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let attacker_log = Arc::new(StdMutex::new(vec![]));
        let attacker = spawn_server(
            json_response("{}"),
            json_response("{}"),
            attacker_log.clone(),
        )
        .await
        .unwrap();

        let vault_log = Arc::new(StdMutex::new(vec![]));
        let vault = spawn_server(
            json_response(r#"{"auth":{"client_token":"s.stub-token","lease_duration":3600}}"#),
            format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: {attacker}/v1/steal\r\nContent-Length: 0\r\n\r\n"),
            vault_log.clone(),
        )
        .await
        .unwrap();

        let tmp = scratch();
        let secret_id_path = tmp.path().join("secret-id");
        std::fs::write(&secret_id_path, "secret-id").unwrap();

        let client = VaultClient::new(approle_config(vault, secret_id_path)).unwrap();
        let error = client
            .sign_ssh_key("warpgate", "ssh-ed25519 AAAA", "root", "warpgate:alice")
            .await
            .unwrap_err();

        assert!(
            matches!(error, VaultError::Api { status, .. } if status == StatusCode::TEMPORARY_REDIRECT),
            "the redirect should surface as an error, got {error:?}"
        );
        assert!(
            attacker_log.lock().unwrap().is_empty(),
            "the redirect target was contacted at all"
        );
        // Without this the test would also pass if the signing request had never
        // been made, which is the failure mode it exists to rule out.
        assert!(
            vault_log
                .lock()
                .unwrap()
                .iter()
                .any(|request| request.to_lowercase().contains("x-vault-token")),
            "no token-bearing request was made, so nothing was under test"
        );
    }

    /// `text()` would buffer the whole body before there was anything to
    /// truncate, so an endpoint that never stops sending holds the session open
    /// until the request timeout and allocates everything it sent meanwhile.
    #[tokio::test]
    async fn test_an_endless_error_body_is_not_buffered() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let vault = spawn_endless_error_server(json_response(
            r#"{"auth":{"client_token":"s.stub-token","lease_duration":3600}}"#,
        ))
        .await;

        let tmp = scratch();
        let secret_id_path = tmp.path().join("secret-id");
        std::fs::write(&secret_id_path, "secret-id").unwrap();

        let mut config = approle_config(vault, secret_id_path);
        // The two outcomes this separates are "stopped at the cap" and "waited
        // out the whole stream", so what matters is the distance between them,
        // not either number. A minute against the twenty seconds below leaves
        // room for a machine three times slower than the one that measured
        // 7.6 seconds for the early stop.
        config.timeout = Duration::from_secs(60);
        let client = VaultClient::new(config).unwrap();

        let started = Instant::now();
        let error = client
            .sign_ssh_key("warpgate", "ssh-ed25519 AAAA", "root", "warpgate:alice")
            .await
            .unwrap_err();
        let elapsed = started.elapsed();

        match error {
            VaultError::Api { status, body } => {
                assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
                assert!(body.len() <= MAX_ERROR_BODY + "... (truncated)".len());
                // Both halves, deliberately: an upper bound alone is satisfied
                // by a reader that returns nothing at all.
                assert_eq!(body.len(), MAX_ERROR_BODY + "... (truncated)".len());
                assert!(body.starts_with("aaaa"), "the body was not read: {body:?}");
                assert!(body.ends_with("... (truncated)"), "no truncation marker");
            }
            other => panic!("expected a bounded API error, got {other:?}"),
        }
        assert!(
            elapsed < Duration::from_secs(20),
            "reading the error body waited on the whole stream ({elapsed:?})"
        );
    }

    /// A body is a body whatever the status code on it says, and this one is
    /// parsed for every session that asks for a certificate.
    #[tokio::test]
    async fn test_an_oversized_success_body_is_refused_rather_than_buffered() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let oversized = format!(
            r#"{{"data":{{"signed_key":"{}"}}}}"#,
            "A".repeat(MAX_RESPONSE_BODY + 1)
        );
        let log = Arc::new(StdMutex::new(vec![]));
        let vault = spawn_server(
            json_response(r#"{"auth":{"client_token":"s.stub-token","lease_duration":3600}}"#),
            json_response(&oversized),
            log.clone(),
        )
        .await
        .unwrap();

        let tmp = scratch();
        let secret_id_path = tmp.path().join("secret-id");
        std::fs::write(&secret_id_path, "secret-id").unwrap();

        let client = VaultClient::new(approle_config(vault, secret_id_path)).unwrap();
        let error = client
            .sign_ssh_key("warpgate", "ssh-ed25519 AAAA", "root", "warpgate:alice")
            .await
            .unwrap_err();

        assert!(
            matches!(error, VaultError::OversizedResponse),
            "expected the body to be refused on size, got {error:?}"
        );
        // Otherwise this passes just as well when the request was never sent.
        assert!(
            log.lock().unwrap().iter().any(|r| r.contains("/sign/")),
            "no signing request was made, so nothing was under test"
        );
    }

    /// Vault reports `lease_duration: 0` for a token with no lease at all — a
    /// root or otherwise non-expiring token. Treating that as an expiry in the
    /// past makes every certificate request log in again, which is a login storm
    /// against Vault sourced from ordinary traffic.
    #[tokio::test]
    async fn test_a_token_with_no_lease_is_not_re_fetched_for_every_request() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let log = Arc::new(StdMutex::new(vec![]));
        let vault = spawn_server(
            json_response(r#"{"auth":{"client_token":"s.stub-token","lease_duration":0}}"#),
            json_response(r#"{"data":{"signed_key":"ssh-ed25519-cert-v01@openssh.com AAAA"}}"#),
            log.clone(),
        )
        .await
        .unwrap();

        let tmp = scratch();
        let secret_id_path = tmp.path().join("secret-id");
        std::fs::write(&secret_id_path, "secret-id").unwrap();

        let client = VaultClient::new(approle_config(vault, secret_id_path)).unwrap();
        for _ in 0..3 {
            client
                .sign_ssh_key("warpgate", "ssh-ed25519 AAAA", "root", "warpgate:alice")
                .await
                .unwrap();
        }

        let logins = log
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.contains("/login"))
            .count();
        assert_eq!(
            logins, 1,
            "the cached token was thrown away between requests"
        );
    }

    /// A `200` is not a certificate. Vault answering with a body that parses but
    /// carries no key must be an error, not an empty certificate handed to the
    /// SSH layer to make sense of.
    #[tokio::test]
    async fn test_a_success_without_a_signed_key_is_an_error() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let log = Arc::new(StdMutex::new(vec![]));
        let vault = spawn_server(
            json_response(r#"{"auth":{"client_token":"s.stub-token","lease_duration":3600}}"#),
            json_response(r#"{"data":{}}"#),
            log.clone(),
        )
        .await
        .unwrap();

        let tmp = scratch();
        let secret_id_path = tmp.path().join("secret-id");
        std::fs::write(&secret_id_path, "secret-id").unwrap();

        let client = VaultClient::new(approle_config(vault, secret_id_path)).unwrap();
        let error = client
            .sign_ssh_key("warpgate", "ssh-ed25519 AAAA", "root", "warpgate:alice")
            .await
            .unwrap_err();

        assert!(
            matches!(error, VaultError::Json(_)),
            "expected the response to be rejected, got {error:?}"
        );
        assert!(
            log.lock().unwrap().iter().any(|r| r.contains("/sign/")),
            "no signing request was made, so nothing was under test"
        );
    }

    /// Nothing else in the crate would notice if certificate verification were
    /// turned off: every other test here trusts the stand-in server through
    /// `ca_bundle`, and Warpgate does disable verification deliberately
    /// elsewhere (`warpgate-protocol-http`'s client cache). The token crosses
    /// this connection, so it must not happen here. Configured without a bundle
    /// on purpose — the subject is the default trust decision, not a root store
    /// the test itself supplied.
    #[tokio::test]
    async fn test_an_untrusted_vault_certificate_is_refused() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let certificate = rustls_pki_types::CertificateDer::from(issued.cert.der().to_vec());
        let key =
            rustls_pki_types::PrivateKeyDer::try_from(issued.signing_key.serialize_der()).unwrap();

        let server_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![certificate], key)
                .unwrap(),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            while let Ok((socket, _)) = listener.accept().await {
                // The handshake is expected to fail; accepting is enough to
                // prove the client got as far as looking at the certificate.
                let _ = acceptor.accept(socket).await;
            }
        });

        let tmp = scratch();
        let secret_id_path = tmp.path().join("secret-id");
        std::fs::write(&secret_id_path, "secret-id").unwrap();

        let client = VaultClient::new(approle_config_without_bundle(
            format!("https://localhost:{port}"),
            secret_id_path,
        ))
        .unwrap();
        let error = client
            .sign_ssh_key("warpgate", "ssh-ed25519 AAAA", "root", "warpgate:alice")
            .await
            .unwrap_err();

        match error {
            VaultError::Request(e) => {
                let reported = format!("{e:?}");
                assert!(
                    reported.contains("certificate") || reported.contains("UnknownIssuer"),
                    "expected a certificate error, got {reported}"
                );
            }
            other => panic!("expected the handshake to be refused, got {other:?}"),
        }
    }

    /// `lease_duration` is an unbounded number out of a network response, and
    /// `Instant + Duration` panics on overflow — so a Vault returning a nonsense
    /// lease would take the process down on the login path.
    #[tokio::test]
    async fn test_an_absurd_lease_is_refused_rather_than_panicking() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let log = Arc::new(StdMutex::new(vec![]));
        let vault = spawn_server(
            json_response(&format!(
                r#"{{"auth":{{"client_token":"s.stub","lease_duration":{}}}}}"#,
                u64::MAX
            )),
            json_response("{}"),
            log,
        )
        .await
        .unwrap();

        let tmp = scratch();
        let secret_id_path = tmp.path().join("secret-id");
        std::fs::write(&secret_id_path, "secret-id").unwrap();

        let client = VaultClient::new(approle_config(vault, secret_id_path)).unwrap();
        let error = client
            .sign_ssh_key("warpgate", "ssh-ed25519 AAAA", "root", "warpgate:alice")
            .await
            .unwrap_err();

        assert!(
            matches!(error, VaultError::InvalidLease(_)),
            "expected the lease to be refused, got {error:?}"
        );
    }

    /// The truncation marker has to mean something.
    ///
    /// Upper bounds alone are satisfied by an empty answer, so inverting the
    /// "is there more?" poll, the `truncated` accumulation or the loop
    /// condition changes nothing they can see. These pin both sides.
    #[tokio::test]
    async fn test_a_body_is_marked_truncated_exactly_when_it_is() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        for (size, expect_marker) in [
            (MAX_ERROR_BODY - 1, false),
            (MAX_ERROR_BODY, false),
            (MAX_ERROR_BODY + 1, true),
        ] {
            let payload = "z".repeat(size);
            let log = Arc::new(StdMutex::new(vec![]));
            let vault = spawn_server(
                json_response(r#"{"auth":{"client_token":"s.stub","lease_duration":3600}}"#),
                format!(
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\r\n{payload}",
                    payload.len()
                ),
                log,
            )
            .await
            .unwrap();

            let tmp = scratch();
            let secret_id_path = tmp.path().join("secret-id");
            std::fs::write(&secret_id_path, "secret-id").unwrap();

            let client = VaultClient::new(approle_config(vault, secret_id_path)).unwrap();
            let error = client
                .sign_ssh_key("warpgate", "ssh-ed25519 AAAA", "root", "warpgate:alice")
                .await
                .unwrap_err();

            let VaultError::Api { body, .. } = error else {
                panic!("expected an API error for a {size}-byte body");
            };
            assert_eq!(
                body.ends_with("... (truncated)"),
                expect_marker,
                "a {size}-byte body was marked wrongly: {body:.40}"
            );
            let kept = body.trim_end_matches("... (truncated)");
            assert_eq!(kept.len(), size.min(MAX_ERROR_BODY), "wrong amount kept");
        }
    }

    #[test]
    fn test_error_body_truncation_survives_a_split_character() {
        // 255 ASCII bytes then a two-byte character: cutting at byte 256 lands
        // inside it, which slicing a `String` would panic on.
        let mut body = "a".repeat(255).into_bytes();
        body.extend_from_slice("é".as_bytes());

        let rendered = render_error_body(&body[..MAX_ERROR_BODY], true);
        assert!(rendered.starts_with(&"a".repeat(255)));
        assert!(rendered.ends_with("... (truncated)"));
    }

    #[test]
    fn test_error_body_is_left_alone_when_it_fits() {
        assert_eq!(
            render_error_body(br#"{"errors":["permission denied"]}"#, false),
            r#"{"errors":["permission denied"]}"#
        );
    }

    #[test]

    fn test_address_validation() {
        assert!(validate_address("https://vault.internal:8200").is_ok());
        for plaintext in [
            "http://vault.internal:8200",
            // Loopback included: a local Vault is still a Vault the client
            // sends a credential to.
            "http://localhost:8200",
            "http://127.0.0.1:8200",
            "http://[::1]:8200",
        ] {
            assert!(
                matches!(
                    validate_address(plaintext),
                    Err(VaultError::InsecureAddress)
                ),
                "{plaintext} was accepted"
            );
        }
    }

    /// `test_segment_validation` proves the rule; this proves someone applies
    /// it before the socket is opened.
    ///
    /// It cannot be proved end to end: the admin API refuses to save a target
    /// with such a role, so the connect path cannot be reached with one. Reading
    /// the code and seeing `validate_segment` at the top of `sign_ssh_key` is
    /// not the same as watching nothing leave the process, so this watches.
    #[tokio::test]
    async fn a_role_that_climbs_out_of_the_mount_sends_nothing() {
        let log = Arc::new(StdMutex::new(vec![]));
        let vault = spawn_server(
            json_response(r#"{"auth":{"client_token":"s.stub-token","lease_duration":3600}}"#),
            json_response(r#"{"data":{"signed_key":"ssh-ed25519-cert-v01@openssh.com AAAA"}}"#),
            log.clone(),
        )
        .await
        .unwrap();

        let tmp = scratch();
        let secret_id_path = tmp.path().join("secret-id");
        std::fs::write(&secret_id_path, "secret-id").unwrap();

        let client = VaultClient::new(approle_config(vault, secret_id_path)).unwrap();
        let error = client
            .sign_ssh_key(
                "../../auth/token/create",
                "ssh-ed25519 AAAA",
                "root",
                "warpgate:alice",
            )
            .await
            .unwrap_err();

        assert!(matches!(error, VaultError::InvalidRole(_)), "{error:?}");
        assert!(
            log.lock().unwrap().is_empty(),
            "a request left the process carrying the gateway's own token: {:?}",
            log.lock().unwrap()
        );
    }

    #[test]
    fn test_segment_validation() {
        assert!(validate_segment("valid-role_123").is_ok());
        assert!(matches!(
            validate_segment("../path-traversal"),
            Err(VaultError::InvalidRole(_))
        ));
        assert!(matches!(
            validate_segment("role/with/slashes"),
            Err(VaultError::InvalidRole(_))
        ));
    }

    #[test]
    fn test_principal_validation() {
        assert!(validate_principal("root").is_ok());
        // Vault splits `valid_principals` on commas, so this would issue a
        // certificate valid for root as well.
        assert!(matches!(
            validate_principal("deploy,root"),
            Err(VaultError::InvalidPrincipal(_))
        ));
        assert!(matches!(
            validate_principal(""),
            Err(VaultError::InvalidPrincipal(_))
        ));
        assert!(matches!(
            validate_principal("deploy\nroot"),
            Err(VaultError::InvalidPrincipal(_))
        ));
    }

    #[test]
    fn test_key_id_validation() {
        assert!(validate_key_id("warpgate:alice:6f1a").is_ok());
        // The target's sshd logs the key ID verbatim.
        assert!(matches!(
            validate_key_id("warpgate:alice\nAccepted publickey for root"),
            Err(VaultError::InvalidKeyId)
        ));
        // The length half of the same check. It had no case at all, so a
        // mutation dropping only the bound was caught by nothing — the two
        // halves are separate guards in the matrix and needed separate
        // evidence.
        assert!(validate_key_id(&"a".repeat(MAX_KEY_ID)).is_ok());
        assert!(matches!(
            validate_key_id(&"a".repeat(MAX_KEY_ID + 1)),
            Err(VaultError::InvalidKeyId)
        ));
    }

    // `test_token_zeroizing` was here. It built a `Zeroizing<String>` and
    // asserted that `as_str()` returned what was put in — the `zeroize` crate's
    // own `Deref`, with no Warpgate code in it, under a name that read as
    // coverage of the token cache. Deleted rather than repaired: the property
    // it claimed is measured for real in `tests/zeroization.rs`, against the
    // paths that actually hold a credential.
}

/// The validators and the error renderer take input straight off the network or
/// out of an operator's config. Example-based tests only ever prove that the
/// four cases somebody thought of are handled; these say what must hold for
/// every input, which is the shape of the two defects that got through — a byte
/// index landing inside a character, and an address form nobody had in mind.
#[cfg(test)]
mod properties {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// The whole purpose of the check: nothing accepted is plaintext.
        /// Stated over arbitrary input rather than over the handful of
        /// addresses anyone thought to write down, because the version of this
        /// rule that compared strings passed every example and still admitted
        /// `http://[::1]:8200`.
        #[test]
        fn an_accepted_address_is_https(address in "\\PC{0,64}") {
            if let Ok(parsed) = validate_address(&address) {
                prop_assert_eq!(parsed.scheme(), "https");
            }
        }

        /// Vault splits `valid_principals` on commas, so an accepted principal
        /// has to be exactly one entry — and carry nothing that could forge a
        /// line in the target's sshd log.
        #[test]
        //
        // The generator is `(?s).` and not `\PC`: `\PC` is the *negation* of
        // Unicode category C, so it produced only strings with no control
        // characters — and the third assertion below then held for every input
        // whether or not `validate_principal` looked at all. A property that
        // cannot fail is not evidence, and this one carried a matrix entry.
        fn an_accepted_principal_is_a_single_harmless_entry(principal in "(?s).{0,64}") {
            if validate_principal(&principal).is_ok() {
                prop_assert_eq!(principal.split(',').count(), 1);
                prop_assert!(!principal.is_empty());
                prop_assert!(!principal.chars().any(char::is_control));
            }
        }

        /// An accepted mount or role must stay one path segment. `../` and an
        /// embedded slash both address a different Vault API entirely.
        #[test]
        fn an_accepted_segment_cannot_leave_its_path(segment in "\\PC{0,64}") {
            if validate_segment(&segment).is_ok() {
                let url = url::Url::parse(&format!("https://vault.invalid/v1/ssh/sign/{segment}"))
                    .unwrap();
                let segments: Vec<_> = url.path_segments().unwrap().collect();
                prop_assert_eq!(segments, vec!["v1", "ssh", "sign", segment.as_str()]);
            }
        }

        /// Rendering an error must not panic and must stay bounded, whatever
        /// arrived — including bytes that are not UTF-8 at all, and a limit that
        /// lands in the middle of a character.
        #[test]
        fn rendering_an_error_body_is_bounded_and_total(
            bytes in proptest::collection::vec(any::<u8>(), 0..2048),
            truncated in any::<bool>(),
        ) {
            let kept = bytes.get(..MAX_ERROR_BODY).unwrap_or(&bytes);
            let rendered = render_error_body(kept, truncated);
            // Lossy decoding can grow the byte length — one invalid byte becomes
            // a three-byte replacement character — so the bound that matters is
            // on characters, not bytes.
            prop_assert!(rendered.chars().count() <= MAX_ERROR_BODY + "... (truncated)".len());
        }

        /// `key_id` is echoed verbatim into the target's sshd log.
        #[test]
        // Same generator defect as above, and here it made the property vacuous
        // outright: every assertion in it is about a control character.
        fn an_accepted_key_id_cannot_forge_a_log_line(key_id in "(?s).{0,128}") {
            if validate_key_id(&key_id).is_ok() {
                prop_assert!(!key_id.contains('\n'));
                prop_assert!(!key_id.contains('\r'));
                prop_assert!(!key_id.contains('\0'));
            }
        }
    }
}
