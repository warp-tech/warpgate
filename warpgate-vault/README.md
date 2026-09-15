# SSH certificate authentication for targets

Warpgate can authenticate to an SSH target with a short-lived OpenSSH certificate
issued on demand by HashiCorp Vault, instead of a private key it stores.

## What changes

| | Stored key (`publickey`) | Vault certificate (`certificate`) |
|---|---|---|
| On the Warpgate host | a private key every target trusts, indefinitely | nothing a target would accept |
| On each target | an `authorized_keys` entry per gateway key | one `TrustedUserCAKeys` line, set once |
| Revoking access | edit `authorized_keys` on every host | stop issuing at Vault |
| Target's own audit log | one shared gateway identity | the Warpgate username and session |
| Adding a target | provision the key first | nothing |

Warpgate generates an ed25519 keypair per connection, has Vault sign the public
half for the target's username, authenticates, and drops both. The private half
never reaches disk, the database, or a log.

```
  ssh user:target@warpgate
        │
        ▼
   ┌──────────┐  1. workload identity   ┌───────┐
   │ Warpgate │ ──────────────────────► │ Vault │
   │          │ ◄────────────────────── │  CA   │
   └──────────┘  2. certificate (2 min) └───────┘
        │                                    ▲
        │ 3. ephemeral key + certificate     │ trusts
        ▼                                    │
   ┌──────────┐  TrustedUserCAKeys ──────────┘
   │  target  │  (no authorized_keys)
   └──────────┘
```

Vault is on the critical path of every session — see *Operational notes* below.

## 1. Vault: the SSH CA

```bash
vault secrets enable -path=ssh-client-signer ssh
vault write ssh-client-signer/config/ca generate_signing_key=true key_type=ed25519

vault write ssh-client-signer/roles/warpgate - <<'EOF'
{
  "key_type": "ca",
  "allow_user_certificates": true,
  "allow_user_key_ids": true,
  "allowed_users": "deploy,app",
  "default_user": "deploy",
  "ttl": "2m",
  "max_ttl": "5m",
  "default_extensions": { "permit-pty": "" }
}
EOF

vault policy write warpgate - <<'EOF'
path "ssh-client-signer/sign/warpgate" {
  capabilities = ["update"]
}
EOF
```

Two settings deserve attention:

- **`allowed_users`** is the real access boundary. Never `*`. Targets of differing
  privilege belong to differing roles, selected per target in Warpgate.
- **`allow_user_key_ids`** must be `true`. Without it Vault rejects the request
  outright, and every session would be attributed to the Warpgate service
  identity instead of to a person.
- **A target with no username** asks for a certificate naming the *connecting
  Warpgate user* instead — the same substitution every other SSH auth method
  makes. That is not a bypass, since `allowed_users` still bounds what Vault will
  issue, but it means the role must list every Warpgate username that may reach
  the target. Setting the username explicitly is almost always what you want.

`default_extensions` grants the minimum. Add `permit-port-forwarding` or
`permit-agent-forwarding` only if your users need them — and only together with
the matching change on the target. A target's `allowed_extensions` defaults to
`permit-pty` alone and refuses any certificate carrying an extension not on that
list, so granting one here without updating the target does not add a
capability: it fails every session to that target.

## 2. Warpgate's identity to Vault

This decides whether the feature delivers what it promises. Every method reads
its credential from a file or a metadata service, never from `warpgate.yaml`.

| Deployment | `kind` | What is on disk |
|---|---|---|
| Kubernetes | `kubernetes` | nothing durable — the kubelet mounts and rotates the token |
| EC2 | `aws` | nothing — the instance role's credentials are short-lived |
| GCE | `gcp` | nothing — the token comes from the metadata server |
| Azure VM | `azure` | nothing — the token comes from IMDS |
| Anything else | `app_role` | a short-lived secret ID, ideally response-wrapped |

Common part of the config:

```yaml
vault:
  address: https://vault.internal:8200
  mount: ssh-client-signer     # default
  default_role: warpgate
  timeout: 10s                 # default
  certificate_ttl: 3m          # optional; the role's TTL decides when unset
  auth:
    ...
```

`certificate_ttl` is a request, not a grant: Vault clamps it to the role's
`max_ttl`, so it can shorten the window but never widen it. It is there so the
lifetime can be tightened from Warpgate's side without an edit to Vault. Under a
second is refused at startup — both issuers reject it, and failing at config
load names the line instead of failing every session later.

Whatever the role grants, Warpgate checks the certificate it gets back and
refuses to use it if the window is wrong. Four cases, because a role's `max_ttl`
is not something Warpgate can see:

| Returned certificate | What happens |
|---|---|
| Valid for more than **24 hours** | Refused. Generous — a role would have to be badly misconfigured to exceed it — but this feature exists to hand the target a credential that is worthless minutes later |
| Valid for longer than the `certificate_ttl` that was asked for | Refused. Vault may shorten a request and never widen one, so a longer window back means the role is not the one intended. A few seconds of slack is allowed for the round trip |
| Marked never-expiring (`ssh-keygen -V always:forever`, or a role with no TTL) | Refused |
| Already expired | Refused, with a message naming the clock — the usual cause is skew on this host or the target, not a bad credential |

Set `certificate_ttl` well below the 24-hour ceiling; it is a backstop against a
misconfigured role, not a target to aim at.

Warpgate refuses a plain-HTTP `address`, loopback included. Vault's
certificate is verified against the host's trust store, plus `ca_bundle` if set:

```yaml
vault:
  ca_bundle: /etc/warpgate/vault-ca.pem   # optional
```

The bundle is *added* to the host's roots rather than replacing them, and an
unreadable or malformed file fails at startup naming the path. Leave it unset and
install the CA on the host or in the container image instead
(`/usr/local/share/ca-certificates` + `update-ca-certificates` on Debian-based
images) — either works.

There is deliberately no setting to skip verification. The HTTP and Kubernetes
target paths offer `verify: false` for devices whose certificates cannot be
fixed; there is no equivalent case for Vault, and the Vault token crosses this
connection in a header.

Pin the CA itself with `ca_public_key`, the same key section 3 below writes to
the target's `TrustedUserCAKeys`:

```yaml
vault:
  ca_public_key: "ssh-ed25519 AAAA..."   # optional
```

Every other check on Vault's response asks whether the certificate matches what
was requested - the principal, the lifetime, the options. This is the only one
that asks who signed it, and it catches a role rebound to a different CA.
Without it a certificate from the wrong CA is still refused, but only by the
target's `TrustedUserCAKeys`, after Warpgate has already offered it, and the
rejection that comes back names the target rather than the CA that mis-signed.
Left unset, nothing is checked here.

### Kubernetes

```yaml
  auth:
    kind: kubernetes
    role: warpgate
    # token_path defaults to the projected service account token
```
```bash
vault auth enable kubernetes
vault write auth/kubernetes/config kubernetes_host="https://$KUBERNETES_PORT_443_TCP_ADDR:443"
vault write auth/kubernetes/role/warpgate \
    bound_service_account_names=warpgate \
    bound_service_account_namespaces=warpgate \
    token_policies=warpgate ttl=1h
```

### AWS

```yaml
  auth:
    kind: aws
    role: warpgate
    server_id: vault.internal   # must match iam_server_id_header_value
```
```bash
vault auth enable aws
vault write auth/aws/config/client iam_server_id_header_value=vault.internal
vault write auth/aws/role/warpgate auth_type=iam \
    bound_iam_principal_arn="arn:aws:iam::<ACCOUNT>:role/<INSTANCE_ROLE>" \
    token_policies=warpgate ttl=1h
```

Warpgate signs an `sts:GetCallerIdentity` request; Vault replays it against STS
to learn who signed it. No credential is disclosed.

**`server_id` is optional and leaving it out is the insecure choice.** It is
bound into the signature as `X-Vault-AWS-IAM-Server-ID`, and Vault compares it
against its own `iam_server_id_header_value`. Without it the signed request
proves only *this principal signed something* — so anyone who obtains one can
present it to any other Vault that trusts the same principal. Warpgate logs a
warning at startup when it is unset rather than refusing: Vault ignores the
header entirely unless `iam_server_id_header_value` is configured, so demanding
a value here would mean inventing one for a server that will not look at it.
Set both, or accept the warning knowingly.

Leave `region` unset. Vault replays against the global endpoint, which rejects a
signature scoped to any other region. Set it only if Vault has a matching
`sts_endpoint`.

### GCE

```yaml
  auth:
    kind: gcp
    role: warpgate
```
```bash
gcloud services enable iam.googleapis.com     # required, see Troubleshooting
vault auth enable gcp
vault write auth/gcp/config
vault write auth/gcp/role/warpgate type=gce \
    bound_projects=<PROJECT> bound_zones=<ZONE> \
    token_policies=warpgate ttl=1h
```

### Azure

```yaml
  auth:
    kind: azure
    role: warpgate
```
```bash
vault auth enable azure
vault write auth/azure/config \
    tenant_id=<TENANT> resource=https://management.azure.com/ \
    client_id=<SP_APP_ID> client_secret=<SP_SECRET>
vault write auth/azure/role/warpgate \
    bound_subscription_ids=<SUB> \
    bound_resource_groups=<RG> \
    bound_service_principal_ids=<VM_MANAGED_IDENTITY_OBJECT_ID> \
    token_policies=warpgate ttl=1h
```

The VM needs a system-assigned managed identity. Vault needs its own service
principal with `Reader` on the resource group to verify the VM through ARM.

### AppRole

```yaml
  auth:
    kind: app_role
    role_id: <not a secret>
    secret_id_path: /run/secrets/vault-secret-id
```

The secret ID is read fresh on every login, so it can be rotated underneath a
running Warpgate.

## 3. Targets

Add the CA public key and remove nothing else yet:

```bash
vault read -field=public_key ssh-client-signer/config/ca | sudo tee /etc/ssh/trusted-ca.pub
sudo chmod 600 /etc/ssh/trusted-ca.pub
echo 'TrustedUserCAKeys /etc/ssh/trusted-ca.pub' | sudo tee -a /etc/ssh/sshd_config
sudo sshd -t && sudo systemctl reload sshd
```

The target now accepts certificates from this CA *in addition* to whatever it
accepted before. Once certificate auth is confirmed working, remove the gateway's
entry from `authorized_keys`.

For a second boundary on the target side, `AuthorizedPrincipalsFile` restricts
which principals may log in as which local user.

## 4. Warpgate target configuration

In the admin UI, an SSH target's **Authenticate using** now offers *Certificate
issued by Vault*, with an optional signing role. The option appears only when
`vault:` is configured. Leave the role empty to use `default_role`.

Through the API:

```json
{
  "name": "prod-db",
  "options": {
    "kind": "Ssh", "host": "db.internal", "port": 22, "username": "deploy",
    "auth": { "kind": "Certificate", "role": "warpgate-prod" }
  }
}
```

## Verification

```bash
# Warpgate: one login, one certificate per session. Both lines log at debug
# level, and the default filter is warpgate=info, so run with -d (or
# RUST_LOG=warpgate=debug) to see them.
grep -E 'Authenticated to Vault|Issued an SSH certificate' <warpgate log>

# The target names the person, not the gateway
grep 'Accepted certificate ID' /var/log/auth.log

# Nothing was persisted: only the bootstrap keys, whatever you do
# (admin UI → Config → SSH, or GET /@warpgate/admin/api/ssh/own-keys)
```

Expected in the target's log:

```
Accepted certificate ID "warpgate:alice:8fae5e3d-..." (serial ...) signed by ED25519 CA ...
```

## Troubleshooting

**`SignatureDoesNotMatch: Credential should be scoped to a valid region`** (AWS) —
`region` is set in the config but Vault replays against the global STS endpoint.
Remove it, or set Vault's `sts_endpoint` to match.

**`SERVICE_DISABLED ... Identity and Access Management (IAM) API`** (GCP) — Vault
resolves the service account named in the identity token through the IAM API.
`gcloud services enable iam.googleapis.com`, then wait a minute.

**`expected specific bound_group_ids or bound_service_principal_ids`** (Azure) —
the Vault role binds only a subscription and resource group. Add
`bound_service_principal_ids`, the object ID of the VM's managed identity (the
`oid` claim of the IMDS token).

**A policy change appears to have no effect** — narrower than it looks, because
Warpgate already recovers from most of it. Vault evaluates a policy's rules at
request time, so editing what a policy *allows* takes effect immediately for a
token already issued. And when signing comes back `403`, Warpgate drops the
cached token, logs in once more and retries within the same request — so a
revoked token, a resealed or restarted Vault, and a token whose lease Vault
stopped honouring all resolve on their own, and a denial that survives the retry
is a real one.

What is left: changing which policies the *auth role* attaches applies only to
tokens issued after the change, and Warpgate keeps its token until shortly
before the lease runs out. If you have granted new permissions that way and
signing is not failing outright, restart Warpgate or wait out `token_ttl`.

**`Vault issued a certificate valid for N hours, far longer than a session
credential should be`** — Warpgate refuses anything over 24 hours, whatever the
role's `max_ttl` allows, and the certificate was never offered to the target.
Shorten the role's `max_ttl`, or set `certificate_ttl` to hold the window down
from Warpgate's side. The companion messages are `never expires`, for a role with
no TTL at all, and `already expired`, which is almost always clock skew rather
than a bad credential.

**`Certificate authentication was rejected by the SSH target`** — the certificate
was issued but the target refused it. Check `sshd -T | grep trustedusercakeys`,
that the principal matches the target username, and the clock skew between
Warpgate and the target.

**`No Vault server is configured`** — the target uses certificate auth but
`vault:` is absent from the config.

## OpenBao Compatibility

Warpgate's Vault integration is fully compatible with **OpenBao**. The SSH secrets engine API and `/sign/<role>` endpoints are identical.

This is asserted rather than assumed: `tests/test_vault_contract.py` runs the
same suite against `hashicorp/vault` and `openbao/openbao`, and every claim the
test stub makes about server behaviour is pinned against both.

Note for OpenBao deployments:
- AWS, Azure, and GCP auth engines are not bundled in OpenBao's core binary; they are separate plugins (`openbao/openbao-plugins`) that must be registered and mounted before those cloud login paths can be used.
- Kubernetes and AppRole auth engines are built-in to OpenBao out of the box.
- For AppRole authentication, Warpgate supports both static Secret IDs and Vault Response Wrapping tokens (specify `unwrap:<wrapping_token>` in the credential file).
- **Audit devices cannot be enabled over the API** — OpenBao answers `cannot
  enable audit device via API; use declarative, config-based audit device
  management instead`. Declare one in the server config, where `type` and `path`
  are both required and the device's own settings belong under `options`; a
  `file_path` written at the top level is accepted with only a warning and then
  ignored, which looks exactly like a working audit device that never writes
  anything. Worth knowing, because the issuance record on the Vault side is half
  the point of this feature.

## Operational notes

**Vault is on the critical path of every session.** An outage locks every target
using certificate auth — including the one you would use to reach Vault. Keep a
break-glass path: one target on stored-key auth, or console access.

**Clock skew.** Certificates live minutes. A target whose clock lags rejects them
as not yet valid, with an error that does not say so. Require NTP on targets.

**Certificate TTL vs. session length.** The TTL bounds how long the certificate
may be *presented*, not how long the session lasts. An established session
survives expiry.

**Revocation.** Stopping issuance at Vault takes effect for new sessions only. An
already-issued certificate stays valid for its TTL — which is why the TTL is
minutes.

**Warpgate does not rate-limit issuance.** One session is one signing call, and
nothing on the Warpgate side caps how many a user can start. Put the ceiling in
Vault — a rate limit quota on the mount (`vault write sys/quotas/rate-limit/ssh
path=ssh-client-signer rate=...`) bounds it without depending on Warpgate
behaving.

**A slow Vault delays every session, not just one.** Warpgate holds one client
token and logs in once for everybody; the login is serialised so an expiring
token cannot send every session in flight to Vault at once. The cost is that a
login which hangs blocks the others for up to `timeout`. Keep `timeout` at a
value you are willing to make every concurrent session wait.

**Critical options are refused unless the target names them.** If a Vault role
sets `default_critical_options`, a `force-command` there replaces whatever the
user typed — the target runs Vault's command, under the user's own principal and
key ID, and the recording shows its output. Planting one needs write access to a
role, which is a lower bar than the right to sign with it or a route to the
target, so Warpgate is the only place this can be caught.

A target therefore refuses any critical option it was not told to expect. Where a
role sets one deliberately, name it on the target — and pin the value, since for
`force-command` the value is the command:

```json
"auth": {
  "kind": "Certificate",
  "role": "warpgate-backup",
  "allowed_critical_options": [
    { "name": "force-command", "value": "/usr/local/bin/backup" }
  ]
}
```

**Pinning a `value` also makes the option mandatory.** A certificate that omits
`force-command` above is refused, not accepted as unrestricted — otherwise the
role-write attack works just as well in reverse: remove the option instead of
adding one, and a target locked to a single command hands out a shell.

Leaving `value` unset only permits: the option may appear with any value, and a
certificate without it is fine. That is how you express a role that *sometimes*
sets an option — `source-address`, say. If every entry were mandatory there
would be no way to say it: list the option and certificates without it fail,
omit it and certificates with it fail.

The refusal reaches the connecting user, not only the log.

**A pinned `force-command` alone does not confine a session.** It decides what
the *shell or exec* channel runs. It does not touch the other channel types, and
OpenSSH gates those purely on what the certificate carries:
`permit-port-forwarding` opens `direct-tcpip`, `permit-agent-forwarding` reaches
the connecting user's own SSH agent. A role whose `default_extensions` grants
either — set deliberately, or written by someone with role-write and nothing
else — would otherwise hand out a session that forwards and pivots from a target
the certificate was supposed to lock to one command.

Extensions are checked for that reason. A target's `allowed_extensions` is an
allow-list, and a certificate carrying anything not on it is refused before it
is offered to the target. It defaults to `permit-pty` alone, which is enough for
an interactive session and nothing more:

```json
"auth": {
  "kind": "Certificate",
  "role": "warpgate-prod",
  "allowed_extensions": ["permit-pty", "permit-port-forwarding"]
}
```

Widen it only for a target whose sessions need to forward, and only together
with the matching `default_extensions` on the role, as section 1 says: either
one without the other fails every session to that target rather than granting
anything. Check the target's own `sshd_config` too — `AllowTcpForwarding no` and
`AllowAgentForwarding no` hold regardless of what a certificate permits.

**`address` and `metadata_address` are fetched as given.** Both come from
`warpgate.yaml`, so anyone who can edit that file can point Warpgate's outbound
requests — including the ones carrying its Vault token and its cloud identity
token — at a host of their choosing. That is no more access than editing the
config already grants, but it means the config file deserves the same protection
as a credential: root-owned, not world-readable, and under change review.
Warpgate refuses plain HTTP for `address` and never follows a
redirect, so neither address can be downgraded or re-pointed after the fact by
whatever answers it.
