# SCIM — todo (see scim_design.md for detail)

## Phase 0 — plan
- [x] Design reviewed and validated

## Phase 1 — schema and account state
- [x] Migration m00096: scim_tokens table, users.enabled/scim_external_id/scim_attributes, roles.scim_external_id, created_at/updated_at on both, indexes
- [x] ScimToken entity, register in with_every_entity and copy_database
- [x] User and Role entity columns and before_save timestamp hook; update every User::ActiveModel literal
- [x] warpgate_common::User gains enabled, scim_external_id and timestamps; Role gains timestamps
- [x] UserDisabled/UserEnabled audit events
- [x] Enforce enabled in resolve_user_and_policy, vet_credential_bearer, resolve_and_map_sso_user, admin_permission_set
- [x] recover-access re-enables the account
- [x] Unit tests for the enforcement points and the migration up/down

## Phase 2 — warpgate-scim protocol layer
- [x] Crate skeleton, workspace member, justfile projects entry
- [x] Error envelope type and scimType set
- [x] Resource types and JSON builders for User, Group, ListResponse
- [x] Filter tokenizer and parser
- [x] Filter evaluator with case-insensitive string semantics and value paths
- [x] PATCH engine with IdP quirk handling
- [x] Discovery documents: ServiceProviderConfig, ResourceTypes, Schemas
- [x] Pagination and sort parameter parsing incl. meta.created/lastModified
- [x] Unit tests for every item above

## Phase 3 — store layer
- [x] User load/list with batched roles and assignments and derived lastModified
- [x] User create/replace/patch/delete with uniqueness, guardrail, audit, session close
- [x] Group load/list with members and derived lastModified
- [x] Group create/replace/patch/delete with membership grant/revoke and session close
- [x] SSO credential reconciliation from emails when sso_provider is set
- [x] SQL fast path for sole-clause eq filters, with agreement test
- [x] Store unit tests on in-memory SQLite

## Phase 4 — HTTP layer and mounting
- [x] Bearer auth gate against scim_tokens with IP block check and last_used update
- [x] Routes for Users, Groups, .search, discovery, Bulk/Me 501
- [x] Content-type handling and WWW-Authenticate on 401
- [x] Request span with scim_token label
- [x] Mount at /@warpgate/scim/v2 in warpgate-protocol-http
- [x] Unit tests for the gate and routing

## Phase 5 — admin API and UI
- [x] scim_tokens admin endpoints with permission gates
- [x] users PUT accepts enabled; User/Role responses expose enabled, scim_external_id and timestamps
- [x] Regenerate OpenAPI schemas, clients and the Python test SDK
- [x] SCIM provisioning page and create-token modal
- [x] Users list badges, user page enabled switch and timestamps
- [x] Config nav entry and routes
- [x] svelte-check and lint clean

## Phase 6 — e2e tests
- [x] test_api.py cases for the three new operations
- [x] test_scim.py: discovery and auth
- [x] test_scim.py: user lifecycle, filters, pagination, PATCH quirks
- [x] test_scim.py: deactivation ends sessions and blocks every login path
- [x] test_scim.py: group lifecycle and membership gating of SSH access
- [x] test_scim.py: provisioned user logs in via OIDC mock
- [x] test_scim.py: audit lines name the token

## Phase 7 — finish
- [x] README feature bullet
- [x] fmt, cranky, full cargo test, full e2e run
- [x] Final review against the design and PR description
