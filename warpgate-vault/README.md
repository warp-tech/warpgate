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

`default_extensions` grants the minimum. Add `permit-port-forwarding` or
`permit-agent-forwarding` only if your users need them.

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
lifetime can be tightened from Warpgate's side without an edit to Vault.

Warpgate refuses a plain-HTTP `address` unless it is loopback, and verifies
Vault's certificate against the **host's trust store** — there is no CA-bundle
setting. A Vault behind a private CA therefore needs that CA installed on the
Warpgate host or in its container image (`/usr/local/share/ca-certificates` +
`update-ca-certificates` on Debian-based images), which is the same thing every
other outbound connection in Warpgate expects.

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
to learn who signed it. No credential is disclosed. `server_id` is bound into the
signature so a captured request cannot be replayed against a different Vault.

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
# Warpgate: one login, one certificate per session
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

**A policy change appears to have no effect** — Warpgate caches the Vault token
until shortly before its lease expires. A role or policy change does not
invalidate a token already issued. Restart Warpgate, or wait out `token_ttl`.

**`Certificate authentication was rejected by the SSH target`** — the certificate
was issued but the target refused it. Check `sshd -T | grep trustedusercakeys`,
that the principal matches the target username, and the clock skew between
Warpgate and the target.

**`No Vault server is configured`** — the target uses certificate auth but
`vault:` is absent from the config.

## OpenBao Compatibility

Warpgate's Vault integration is fully compatible with **OpenBao**. The SSH secrets engine API and `/sign/<role>` endpoints are identical.

Note for OpenBao deployments:
- AWS, Azure, and GCP auth engines are not bundled in OpenBao's core binary; they are separate plugins (`openbao/openbao-plugins`) that must be registered and mounted before those cloud login paths can be used.
- Kubernetes and AppRole auth engines are built-in to OpenBao out of the box.
- For AppRole authentication, Warpgate supports both static Secret IDs and Vault Response Wrapping tokens (specify `unwrap:<wrapping_token>` in the credential file).

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

**A certificate can come back carrying critical options.** If a Vault role sets
`default_critical_options`, a `force-command` there replaces whatever the user
typed — the target runs Vault's command and the session recording shows its
output. Warpgate does not refuse such a certificate, because a restricted role
may set one deliberately, but it logs every arrival:

```
WARN Vault issued a certificate carrying critical options options=["force-command"]
```

Alert on that line if your roles are not supposed to set any.

**`address` and `metadata_address` are fetched as given.** Both come from
`warpgate.yaml`, so anyone who can edit that file can point Warpgate's outbound
requests — including the ones carrying its Vault token and its cloud identity
token — at a host of their choosing. That is no more access than editing the
config already grants, but it means the config file deserves the same protection
as a credential: root-owned, not world-readable, and under change review.
Warpgate refuses plain HTTP for `address` outside localhost and never follows a
redirect, so neither address can be downgraded or re-pointed after the fact by
whatever answers it.
