import { TargetKind } from 'gateway/lib/api'

// Admin-facing per-protocol reference shown at the top of the target editor.
// Authored as Markdown, rendered with snarkdown in ProtocolInfo.svelte.
// Facts reflect the proxy implementations; keep in sync when protocol behaviour changes.

export const protocolInfo: Partial<Record<TargetKind, string>> = {
    [TargetKind.Ssh]: `
## Warpgate ↔ target

* Authenticates with a stored password, Warpgate's managed public key, or an IAM role (EC2 Instance Connect).
* Keyboard-interactive prompts from the target are auto-answered empty.

## Warpgate ↔ client

* Client authenticates with a public key, password or keyboard-interactive (for OTP, SSO and web approval).

## SSH protocol

* Only secure kex and encryption is allowed by default.
* Per-target \`Allow insecure algorithms\` re-enables legacy DH-group1/14, 3DES, HMAC-SHA1 and RSA-SHA1 for older targets.
* Minimum target: any SSH2 server; pre-OpenSSH 6.5 (2014) may require \`Allow insecure algorithms\`.

## Supported Warpgate credentials

* Password
* Public key
* OTP
* SSO (browser approval)
* Ticket
`,

    [TargetKind.Http]: `
## Warpgate ↔ target

* No credential injection.
* Basic credentials embedded in the target URL are forwarded as-is.
* Warpgate adds \`X-Warpgate-Username\`, \`X-Warpgate-Authentication-Type\` and \`X-Forwarded-*\`.
* TLS at target is optional.

## Warpgate ↔ client

* Warpgate requires TLS from the client and sets HSTS.
* Target selection: through the menu, \`?warpgate-target=<name>\` or a subdomain bound in the target options.

## HTTP protocol

* HTTP/1.1 and HTTP/2
* HTTP/3 is not supported.

## Supported Warpgate credentials

* Password
* OTP
* SSO
* Ticket
* API token
`,

    [TargetKind.MySql]: `
## Warpgate ↔ target

* Warpgate authenticates against the target using \`caching_sha2_password\`, \`sha256_password\` or \`mysql_native_password\`.
* TLS at target is optional.

## Warpgate ↔ client

* Warpgate requires TLS from the client.
* Client authenticates using cleartext password (must be explicitly enabled) over mandatory TLS.
* The client must support the \`mysql_clear_password\` plugin (for \`caching_sha2_password\` auth).

## MySQL protocol

* Warpgate advertises itself as \`8.0.3-Warpgate\` (configurable).
* Minimum target: MySQL 5.x+ or MariaDB 10.x+.

## Supported Warpgate credentials

* Password
* Ticket
`,

    [TargetKind.Postgres]: `
## Warpgate ↔ target

* Authenticates with a stored password or an IAM role (RDS auth token).
* Auth methods: cleartext, MD5 or SCRAM (SASL).
* TLS at target is optional.

## Warpgate ↔ client

* Warpgate requires TLS from the client.
* Client authenticates using cleartext password over the mandatory TLS.

## PostgreSQL protocol

* Wire protocol 3.0 and 3.2 (configurable).
* Minimum target: PostgreSQL 7.4+

## Supported Warpgate credentials

* Password
* Ticket
* Web approval (browser link prompt)
`,

    [TargetKind.Kubernetes]: `
## Warpgate ↔ target

* Authenticates to the cluster with a client certificate (mTLS), a bearer token, or an IAM role (EKS token).
* TLS at target is optional.

## Warpgate ↔ client

* Client authenticates with a Warpgate-issued client certificate, a Warpgate API token, or an SSO/OIDC id-token (via kubelogin).

## Kubernetes protocol

* WebSocket/SPDY \`exec\`/\`attach\`/\`port-forward\` streams are supported.
* Protobuf streams are not supported.

## Supported Warpgate credentials

* Client certificate
* Warpgate API token as bearer token
* SSO
* Web approval
`,

    [TargetKind.Vnc]: `
## Warpgate ↔ target

* Authentication with or without a password.
* No TLS support.

## Warpgate ↔ client

* Mandatory TLS via VeNCrypt (X509Plain) unless Apple-DH authentication is enabled.
* Authentication always starts with a password, other credentials (OTP / web approval) are then collected over a visual UI.
* Optional Apple-DH (ARD) auth does not support TLS and must be enabled in the config file.

## VNC protocol

* RFB 003.008 to the viewer.
* Plain \`None\` and legacy \`VncAuth\` schemes are not supported.
* macOS built-in Screen Sharing client is not supported.
* Minimum target: RFB 3.3+ (e.g. TigerVNC, RealVNC, TightVNC, x11vnc).

## Supported Warpgate credentials

* Password
* OTP
* Web approval
* Ticket
`,
}
