# Warpgate technical design

## Actors

* `Client`: the end-user wishing to connect to the `Target`.
* `Client Admin`: the administrator at `Client`'s organization who decides on security policies.
* `Target`: the on-premise server or service that the `Client` wishes to connect to.
* `Target Admin`: the administrator at `Target`'s organization who decides on security policies.
* `Ingress`: the service sitting between the on-premise servers and the Internet.
* `Central`: the SaaS service providing user authorization and access control.
* `Auth provider` (optional): the customer's own authentication provider (Active Directory / AuthZ / Okta / generic SAML / OAuth providers / etc).
* Note: `Client` and `Target` may be within the same organization in which case `Client Admin` and `Target Admin` are the same user/person.

## Where secrets live

* Credentials to access `Target`s are stored in the `Ingress` server (or optionally in a dedicated secret store, see below).
* `Ingress` has its own access token which links it to `Central`.
* `Client` has a user account on `Central` (either a username + password or an enterprise account imported through an identity provider).

## Trust relationships

* `Target` has ultimate trust in `Ingress` since `Ingress` has the access credentials for `Target`.
* `Ingress` trusts `Central` to verify `Client`'s identity.
* (optional) `Central` trusts the `Auth provider` to verify `Client`'s identity.
* `Client` knows `Ingress`'s identity as verified by `Central` (which knows its host key).

## How connections work (from the `Client`'s perspective)

### First-time setup

* The `Client` logs into `Central` and is provided with a list of allowed `Target`s.
  * They are provided with a unique `token` which serves as the 1st authentication factor for any `Target`, which they note or save in their favourite SSH client.

### Connecting to a target (Option A: interactive)

Use case: day-to-day work.

* The user connects to the `Target` via SSH as follows (this can be saved as a profile in their SSH client, or when using Tabby, it will pull up the complete profile automatically):
  * Host: the `Ingress` address
  * Port: the `Ingress` public port
  * Username: the name of the `Target`
  * Password: the `token` provided by `Central`
* Their SSH client connects to `Ingress` and (optionally) prompts them for more authentication factors according to the configurable security policy, e.g.:
  * One-time password
  * Oauth
  * Browser-based SAML login (via a link)
* Their connection is forwarded by `Ingress` directly to the `Target` and they can carry on with their work.

*(this is an example for SSH, other protocols can be unwrapped in a similar manner)*

### Connecting to a target (Option B: unattended)

Use case: connecting services across locations.

* The user generates a new, app-specific `Token` in the `Central`'s web interface and uses this token instead of their personal `Token` as the password when connecting.
* These app-specific `Tokens` bypass multi-factor authentication to allow using them with non-interactive clients, e.g. connecting a web service to a database across networks.
* Both `Client Admin` and `Target Admin` can forbid or enforce expiration rules for these tokens.

NB: `Token` could be a private key instead of a text password.

## How connections work (technical)

An example for SSH, other protocols can be unwrapped in a similar manner.

1. `Ingress`, acting as an SSH server, accepts an SSH connection from `Client`.
1. `Ingress` uses the "password" (which is actually `Client`'s `Token`) to verify the `Client`'s identity at `Central`.
1. If the security policy configured at `Central` indicates that additional authentication factors are required, `Ingress` conducts additional security verification through either an interactive "shell" session, or keyboard-interactive authentication, passing the results over to `Central`.
1. Once `Central` indicates that the security requirements have been satisfied, Ingress connects to the `Target` using the credentials stored locally, and starts forwarding and recording data from `Client` to `Target` and back, so that it appears to the `Client` that they're now directly connected to `Target`.
1. At this point, `Ingress` can improse further security restrictions onto the session, such as forbidding port forwarding.

## How connections for other protocols could work (technical)

* For connections that use username and password based authentication can follow the exact same steps, with the exception of interactive authentication (when not supported by the protocol) - an unattended access `Token` will be required.
* HTTP/s services can be exposed directly, passing the `Token` as a URL parameter and presenting interactive authentication prompts to the user.

## How management works

### For the `Client Admin`

The `Client Admin` uses Warpgate `Central`:

* to set up authentication providers and import user accounts.
* to access session recordings and audit logs.

### For the `Target Admin`

The `Target Admin` uses Warpgate `Central`:

* to register their local `Ingress` instances.
* to add `Target`s
* to assign `Client`s to `Target`s.
* to set up security policies (e.g. requiring 2FA).
* to access session recordings and audit logs.

### In the single-organization case

The admin does all that with their single user account.

## Further tighetning down security

### On-premise-only credentials

If `Target Admin` doesn't trust `Central` with deploying `Target` credentials to `Ingress`, they can deploy the credentials themselves, or disable the `Central`-initiated configuration changes altogether and use the on-premise `Ingress` web interface instead.

### Secret stores

`Ingress` can integrate with secret stores (e.g. Hashicorp Vault) to tighten security around credentials even further.

### Zero trust configuration

Credentials stored in `Ingress` can be further encrypted with a passphrase, which is then split between `Central` and `Clients`, thus requiring both a `Client` and the `Central` to cooperate to decrypt them.

## How the MVP will differ from the final product

* The MVP includes the `Ingress` service only.
* Only SSH and possibly HTTP will be supported.
* In absence of Central, only username/password authentication and basic access assignments will be supported.
* No secret store support.
* No zero trust configuration support.
* Some of the later features will make it into the opensource edition, e.g. support for more protocols.

# Warpgate vs a classic OpenSSH bastion comparison

## Granting a new employee access to `SSH` targets

### Bastion

* Obtain the user's public SSH key.
* Add the user's key to the bastion's authorized_keys.
* Log in to each target and add the user's key to authorized_keys.

### Warpgate

* Assign the user to the targets in the `Central`'s web interface.

## Granting a new employee access to `database` targets

### Bastion

* Obtain the user's public SSH key.
* Add the user's key to the bastion's authorized_keys.
* Log in to the database server and create a new account for the user, grant it access to necessary schemas.
* Send the user their new database user credentials.

### Warpgate

* Assign the user to the targets in the `Central`'s web interface.

## Revoking a user's access

### Bastion

* Find the user's public SSH key.
* Remove the user's key to the bastion's authorized_keys.
* Log in to each target and remove the user's key to authorized_keys.

### Warpgate

* Remove the user's access to the targets in the `Central`'s web interface.

## Auditing user activity

### Bastion

* OpenSSH keeps logs of login attempts, successful logins and logouts.
* Unless forwarded to an external log store, a user logged in as root can easily modify these logs.

### Warpgate

* Connection and login logs are stored on the `Ingress` server and forwarded to the `Central` along with playable session recordings.

## Rotating server keys

### Bastion

* Generate new key pairs for each user
* Manually log in to each server and replace the authorized_keys entries for each user on each server.
* Send the new keys to the users.

### Warpgate

* Server keys: `Ingress` can automatically regenerate and reauthorize keys for each `Target`.
* Client tokens: `Ingress` can notify the users that their token is about to expire, or, when using `Tabby` as a client, automatically update them.

## Host key verification

### Bastion

* For each user and each host, on first connection the user has to manually verify that the target machine's host key is correct to prevent MitM attacks.

### Warpgate

* `Ingress` "knows" all `Target`s and verifies the host keys during connection setup.
* `Central` knows the `Ingress`, so the client can automatically verify its host key.

## Using client applications that do not support SSH jump hosts natively

### Bastion

* Only possible by opening an SSH connection to the bastion first, locally forwarding a port and then connecting to that port.

### Warpgate

* Just works, as all connections are "direct" from the application's point of view.

## Allowing login for specific time only

### Bastion

* For limited per-user accounts, pam_time module allows it.
* For the root user, one would have to script scheduled removal and re-addition of the SSH key to authorized_hosts.

### Warpgate

* Just works.

## Restricting port forwarding, X11 forwarding, etc.

### Bastion

* Possible for limited accounts, but a root user can simply revert these restrictions.

### Warpgate

* Just works, `Ingress` can block features on the protocol level.
