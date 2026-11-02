# SCIM 2.0 provisioning — design

## Goal

Let an identity provider (Okta, Entra ID, OneLogin, JumpCloud, Keycloak, …) create, update,
deactivate and delete Warpgate users and manage their access-role memberships over
SCIM 2.0 (RFC 7643 schema, RFC 7644 protocol), so joiners/leavers and group changes land in
Warpgate without an admin touching the UI. Unit-tested at the protocol layer, integration-tested
end to end against a running Warpgate (and the OIDC mock for the "provisioned user can log in"
path).

## Relevant current state (from the review)

- `users`: id, username (unique, matched case-insensitively), credential_policy, description,
  rate limit, LDAP link, allowed_ip_ranges. **No disabled flag, no external id, no timestamps.**
- `roles` (name unique, case-sensitive index) and `user_roles` with granted/expires/revoked
  history; `UserRoleAssignment::idempotent_grant` re-activates revoked rows.
- Identity sources today: LDAP (import + SSH-key sync, link by object UUID) and OIDC
  (`auto_create_users`, group→role mapping applied at login via `apply_sso_role_mappings`).
- Machine auth is only `X-Warpgate-Token` (admin token from env, or a user API token stored as
  SHA-256 via `hash_secret`). There is no `Authorization: Bearer` scheme anywhere.
- Login chokepoints: interactive logins resolve the user in
  `AuthStateStore::resolve_user_and_policy`; non-interactive credentials (tickets, API tokens,
  Kubernetes) go through `vet_credential_bearer`; OIDC goes through `resolve_and_map_sso_user`.
- Audit events live in `warpgate-common/src/audit.rs`; admin-token actions already emit
  `actor_user_id = Uuid::nil()`.
- Tests: Rust unit tests use `sqlite::memory:` + `migrate_database`; Python e2e under `tests/`
  (`processes.start_wg`, `admin_client`, OIDC mock, llvm-cov). `tests/test_api.py` fails if any
  admin OpenAPI operation lacks a permission test case.
- `warpgate recover-access` resets a password; it is the documented way back in when admins are
  locked out.

## Approach

A new crate `warpgate-scim` exposing a plain-`poem` app mounted by `warpgate-protocol-http` at
`/@warpgate/scim/v2` (the `/_warpgate` alias comes for free). Three layers:

1. **protocol** (no DB, pure): resource JSON builders, filter parser + evaluator, PATCH engine,
   error envelope, discovery documents. Exhaustively unit-tested.
2. **store** (DB): maps SCIM User ↔ `users` and Group ↔ `roles` + `user_roles`; one transaction
   per mutating request; emits audit events; closes sessions where access was lost.
3. **http**: Bearer gate against `scim_tokens`, routing, content negotiation, request span.

Why plain `poem` and not `poem-openapi`: SCIM mandates `application/scim+json`, its own error
envelope (`urn:ietf:params:scim:api:messages:2.0:Error`), `schemas` arrays and tolerance for IdP
quirks; poem-openapi's payload validation and the admin OpenAPI schema (plus its oasdiff
compatibility gate in CI) do not fit, and the SCIM surface must not leak into the admin SDKs.

Why a separate crate and not a module in `warpgate-admin`: a large, independently testable
protocol implementation, in the same spirit as `warpgate-ldap` / `warpgate-sso`.

## Decisions

**D1 — Authentication.** `Authorization: Bearer <token>` checked against a new `scim_tokens`
table (`id, label, secret_hash, sso_provider NULL, created, expiry NULL, last_used NULL`).
Secret = `generate_ticket_secret()` (32 random bytes, hex), stored with `hash_secret()`,
shown once at creation. The login-protection IP block is checked *before* the lookup (as
`user_for_api_token` does) so a blocked caller gets no token-existence oracle. The admin cookie
and `X-Warpgate-Token` are **not** accepted on SCIM routes: IdPs cannot send them, and keeping
SCIM off the cookie path keeps it out of the browser/CSRF surface. Failed Bearer attempts are not
recorded against a username (there is none); 256-bit random tokens make brute force moot.
Rejected: reusing user API tokens — IdPs only speak Bearer/Basic/OAuth, and the SCIM actor is a
machine, not a user.

**D2 — Base URL** `https://<host>/@warpgate/scim/v2`, shown in the admin UI next to the token.

**D3 — User mapping.** `id` = `users.id`; `userName` = `username` (409 `uniqueness` on a
case-insensitive clash, via `username_eq_ci`); `externalId` = new `users.scim_external_id`;
`active` = new `users.enabled`; `groups` (readOnly) = active `user_roles`. Every other attribute
the IdP writes (`name`, `displayName`, `emails`, `title`, the enterprise extension, …) is kept
verbatim in a new `users.scim_attributes` JSON column so that `GET` round-trips exactly what was
`PUT`/`PATCH`ed — Entra and Okta compare what they read back. `description` stays admin-owned.
New users get the instance default credential policy and the default roles (same as the admin
API / LDAP import, via `on_user_created`). Rejected: `displayName → description` — two writers.

**D4 — Account disabling (`active=false`).** `users.enabled = false` denies every login path:
interactive (`resolve_user_and_policy` returns `UserNotFound` after recording the attempt, same
shape as an unknown user), non-interactive (`vet_credential_bearer` returns `false`), OIDC
(`resolve_and_map_sso_user` returns `None`), and admin standing (`admin_permission_set` returns
`none()`). Disabling closes the user's sessions with `close_sessions(SessionsFilter::User)`, which
also ends their HTTP sessions. Admins are *not* exempt: offboarding an admin is the point.
`warpgate recover-access` additionally re-enables the account so an IdP that disables every
admin is recoverable. The admin API/UI get the same switch so the flag is not SCIM-only magic.
Rejected: a permanent `UserLockout` row — lockouts are disabled by `login_protection_enabled`
and exempt admins.

**D5 — Group mapping.** `id` = `roles.id`; `displayName` = `roles.name`; `externalId` = new
`roles.scim_external_id`; `members` = active `user_roles` (`value` = user id, `display` =
username, `$ref`). `GET /Groups` lists **all** roles so an admin can pre-create a role with its
target grants and let the IdP link to it by name (IdPs `GET /Groups?filter=displayName eq …`
before creating). Group create checks the name case-insensitively and returns 409 even though the
DB index is case-sensitive, so a filter (case-insensitive per spec) never matches two roles.
Member add → `idempotent_grant` (no expiry); member remove → `revoked_at = now` then
`close_sessions_without_role_access()`. `DELETE /Groups/{id}` deletes the role **including its
target assignments** (`resources::roles::delete`) — spec-compliant (`GET` must 404 afterwards)
and IdPs only send it on explicit unassignment; the UI warns about it. Rejected: unlink-only
delete — breaks DELETE/GET semantics and conformance suites. `is_default` is never changed.

**D6 — SSO linking.** When the token has `sso_provider` set, the user's primary (else first)
`emails[].value` is reconciled into exactly one SSO credential (`provider = that name`,
`email = that`); other SSO credentials of that provider on the user are replaced, and an empty
`emails` removes it. Without `sso_provider` SSO credentials are untouched. This is what lets a
freshly provisioned user log in with the same IdP's OIDC without `auto_create_users`.

**D7 — Filters.** Full RFC 7644 §3.4.2.2 grammar: `eq ne co sw ew pr gt ge lt le`, `and`/`or`/
`not`, parentheses, value paths such as `emails[type eq "work"].value`, schema-URI-prefixed
attribute names. String comparison is case-insensitive (`caseExact=false` is the schema default
for every attribute we expose). Evaluation runs in memory over fully built resources after
loading users, roles and assignments in three queries. A SQL fast path handles the sole-clause
`userName eq`, `externalId eq` and `displayName eq` filters, which is all IdPs send during sync;
a unit test asserts both paths agree. Invalid filter → 400 `invalidFilter`. Rejected: translating
the full grammar to SQL — most attributes live in a JSON text column.

**D8 — Pagination and sorting.** `startIndex` (1-based, <1 → 1) and `count` (capped at 200,
advertised as `filter.maxResults`); `sortBy` on `userName`/`displayName`/`externalId`/`id`,
`meta.created`/`meta.lastModified`, `sortOrder` ascending/descending; `totalResults` is the
filtered total. `POST /Users/.search` and
`/Groups/.search` accept the same parameters as a body.

**D9 — PATCH.** RFC 7644 §3.5.2 engine operating on the resource JSON, then persisted by diff.
Tolerated IdP quirks: capitalised ops (`"Replace"`), `value` object without `path`
(multi-attribute replace, Okta), `active` as the strings `"True"`/`"False"` (Entra), `members`
filter paths (`members[value eq "…"]`, Entra remove), `remove` with only a `path`, and
`replace` of `members` meaning "set exactly these members". Read-only attributes (`id`,
`groups`, `meta`) → 400 `mutability`; unknown path → 400 `invalidPath`; a no-op PATCH is 200.

**D10 — Errors and content types.** RFC 7644 §3.12 envelope (`status`, `scimType`, `detail`),
`application/scim+json; charset=utf-8` on every response; request bodies are accepted as either
`application/scim+json` or `application/json` (Okta sends the latter), and a missing content type
on a body-less request is fine (Entra `DELETE`). 401 carries
`WWW-Authenticate: Bearer realm="warpgate"`. Internal errors go through the existing
`render_errors` correlation-id path.

**D11 — Explicitly unsupported** (and declared so in `ServiceProviderConfig`): bulk (`/Bulk` →
501), ETag/`version`/`If-Match`, `changePassword`, `/Me` (501). `meta` carries `resourceType`,
`location`, `created` and `lastModified` (see D18).

**D12 — Audit.** Existing `UserCreated`/`UserDeleted`/`AccessRoleGranted`/`AccessRoleRevoked`
are reused with `actor_user_id = Uuid::nil()` (exactly as admin-token requests do); new
`UserDisabled`/`UserEnabled` events cover D4 for both SCIM and the admin API. Every SCIM request
runs inside a tracing span carrying `scim_token = <label>` so the log and audit rows name the
token that acted.

**D13 — Admin API** (poem-openapi, in `warpgate-admin`): `GET /scim-tokens`, `POST /scim-tokens`
(returns the secret once), `DELETE /scim-tokens/:id`. Permissions: list/delete require
`ConfigEdit`; create requires `ConfigEdit` **and** `UsersDelete` **and** `AccessRolesDelete`,
because the token can delete users and roles and a config-only admin must not mint a credential
more powerful than themselves. `PUT /users/:id` gains an optional `enabled` (absent = unchanged,
like `RoleDataRequest.is_default`); the `User` object gains `enabled`, `scim_external_id`,
`created_at` and `updated_at`; the `Role` object gains `created_at` and `updated_at`.
All additive, so the oasdiff gate passes; SDKs are regenerated.

**D14 — Admin UI.** Config → "SCIM provisioning": token list, create modal (label, optional
expiry, optional SSO provider from the gateway's `/api/sso/providers`, one-time secret display),
delete, the tenant URL (`location.origin` + the SCIM path, computed client-side) and the D5
warning. Users list gets "SCIM" and "Disabled" badges; the user page gets an
"Account enabled" switch and a read-only "Provisioned via SCIM (externalId …)" line.

**D15 — Username guardrail.** `userName` must be non-empty and must not contain `:` or `#`
(SSH and database selectors split on them, so such a user could never connect) → 400
`invalidValue`. Email-shaped names (Entra UPNs) are fine.

**D18 — Timestamps.** New `users.created_at`/`users.updated_at` and
`roles.created_at`/`roles.updated_at` (UTC). The migration adds them nullable and backfills every
existing row with the migration time (SQLite cannot add a NOT NULL column with a non-constant
default), so the model type is `Option<OffsetDateTime>` and the SCIM layer omits a `meta` field
only if a row somehow has none. `ActiveModelBehavior::before_save` on both entities stamps
`created_at` on insert and `updated_at` on every save, so no writer (admin API, SSO mapping,
LDAP link, SCIM) can forget it. `meta.lastModified` is **derived**: the maximum of the row's
`updated_at` and the `granted_at`/`revoked_at` of the user's (or group's) role assignments, so a
membership change moves both the user's and the group's `lastModified` without extra bookkeeping.
Both timestamps are exposed on the admin `User`/`Role` objects and shown on the user page, and
`sortBy meta.created` / `meta.lastModified` is supported. Rejected: NOT NULL with a literal
default — three backends, three literal syntaxes, no gain.

**D16 — Cluster.** All state is in the DB; `close_sessions` already fans out to peers; nothing
node-local is introduced.

## Files

New
- `warpgate-scim/` (`Cargo.toml`, `src/lib.rs`, `src/protocol/{mod,resource,filter,patch,
  query,error,discovery}.rs`, `src/store/{mod,common,users,groups,sso_link,tests}.rs`,
  `src/http/{mod,auth,resources,discovery,tests}.rs`) — workspace member, added to the
  justfile `projects` list.
- `warpgate-db-entities/src/ScimToken.rs`; `warpgate-db-migrations/src/m00096_scim.rs`.
- `warpgate-admin/src/api/scim_tokens.rs`.
- `warpgate-web/src/admin/config/scim/{ScimTokens,CreateScimTokenModal}.svelte`.
- `tests/test_scim.py`.

Changed
- `warpgate-db-entities/src/{User,Role,UserRoleAssignment,lib}.rs` (new columns, `Related`
  impls for assignment joins, entity registration).
- Every `User::ActiveModel { … }` literal: `warpgate-admin/src/api/{users,ldap_servers}.rs`,
  `warpgate-core/src/config_providers/{db,mod}.rs`, `warpgate-core/src/approvals/tests.rs`,
  `warpgate/src/commands/{create_user,recover_access}.rs`.
- `warpgate-common/src/{audit,config/mod}.rs` (events; `User.enabled`, `scim_external_id`,
  timestamps; `Role` timestamps).
- `warpgate-core/src/auth_state_store.rs`, `config_providers/sso_user.rs` (D4 enforcement);
  `warpgate-admin/src/api/common.rs` (`admin_permission_set`).
- `warpgate-protocol-http/src/lib.rs` (mount), `Cargo.toml`.
- `warpgate-admin/src/api/{mod,users}.rs`, `warpgate/src/commands/{copy_database,recover_access}.rs`.
- `warpgate-web/src/admin/config/{Config,users/Users,users/User}.svelte`, generated API clients
  and `openapi-schema.json`, `tests/api_sdk`.
- `tests/test_api.py` (cases for the three new operations; the harness gains `also_requires`
  so an operation can demand several permissions), `README.md` (feature bullet), `Cargo.toml`,
  `justfile`.

## Deploy / blast radius

- One additive, reversible migration (`scim_tokens` table; `users.enabled` default true,
  `users.scim_external_id`, `users.scim_attributes`, `users.created_at`, `users.updated_at`,
  `roles.scim_external_id`, `roles.created_at`, `roles.updated_at`, timestamps backfilled to the
  migration time; indexes on the two external ids). Runs at startup on SQLite, Postgres and MySQL
  as every migration does.
- No config-file/schema change. Nothing changes for an install until a SCIM token is created.
- Admin OpenAPI changes are additive; `just openapi-all` + `npm run openapi:tests-sdk` regenerate
  the clients and the Python test SDK.
- Residual risk: an IdP deactivating every admin → `warpgate recover-access` (re-enables + resets
  password). A group deleted at the IdP deletes the role's target grants (D5, warned in UI).
- Local toolchain: the pinned nightly is installed under `~/.rustup/toolchains` but `cargo`,
  `just` and `poetry` are not on `PATH`; use the toolchain `bin` directly or
  `nix-shell -p rustup just poetry`. Docker is present for the e2e images.

## Verification

1. `cargo fmt --check`, `cargo cranky --workspace --all-features` clean (deny lints: no
   unwrap/expect/panic/indexing outside tests).
2. `cargo test -p warpgate-scim`: filter tokenizer/parser (valid + invalid), evaluator on
   fixtures (case-insensitivity, value paths, precedence), PATCH engine incl. every D9 quirk,
   store CRUD on in-memory SQLite (uniqueness, external ids, round-trip of `scim_attributes`,
   membership grant/revoke/re-grant, SSO credential reconciliation, group delete cascade), auth
   gate (missing/invalid/expired token, cookie and `X-Warpgate-Token` rejected), pagination
   bounds, error envelope, derived `lastModified` moving on membership changes.
3. `cargo test` for `warpgate-db-migrations` (up/down), `warpgate-core` (D4 enforcement at all
   three chokepoints), `warpgate-admin`, `warpgate-protocol-http`.
4. `tests/test_scim.py` (e2e, own Warpgate instance): discovery docs; user create/get/list/
   filter/paginate/put/patch/delete; `active=false` ends an open SSH session and blocks a new
   SSH login, HTTP login and API-token call; re-activation restores access; group create/link by
   name/add member → SSH to the role's target works/remove member → session ends and access
   denied/replace members/delete → 404 and target grant gone; Entra-style and Okta-style PATCH
   bodies; 401 for no/bad/expired token and for the admin cookie; 409 on duplicate userName and
   displayName; 400 on bad filter/path/userName; provisioned user with `sso_provider` logs in
   through the OIDC mock and reaches the target; audit lines name the token.
5. `tests/test_api.py` operation-coverage assertion passes with the three new admin operations;
   permission matrix passes.
6. `just npm run check`, `just lint`; manual click-through of the SCIM page and the user switch.
7. `tests/test_db_migrations.py` still passes (fresh DB and upgrade path).
