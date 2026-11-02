# e2e harness — design

## Goal

Make the e2e suite under `tests/` run the same way on a developer machine as in CI, and remove
the timing and environment assumptions that made local runs fail for reasons unrelated to the
code under test.

## What went wrong (observed while landing SCIM, 2026-11-02)

- `wait_mysql_port` probed MySQL/MariaDB containers with a `mysql` client on the host. The host
  had none; with a current MariaDB client its `--ssl` flag means "require TLS", so the probe
  never succeeded against the plain-TCP container and the test timed out before Warpgate started.
  Postgres already probes inside the container with `pg_isready` and had no such problem.
- Tools the harness shells out to (`just`, `poetry`, Java for the OpenAPI generators, `kubectl`,
  FreeRDP, `xvfb-run`, `expect`, the MySQL client) are installed ad hoc by CI with `apt`,
  `pip` and `cargo install`; locally nothing guarantees them or their versions.
- `alloc_port` keeps a per-xdist-worker counter starting at the same base in every pytest
  process, so two pytest processes on one machine walk the same range.
- Tests prove "the session started" by waiting a fixed 8 seconds for the client not to exit;
  that is both slow and timing-sensitive on a loaded machine.

## Decisions

**D1 — Database readiness is probed inside the container.** `wait_mysql_port(port)` runs
`mysql --protocol=tcp … --execute='show schemas;'` with `docker exec` in the container
published on `port`, which `start_mysql_server`/`start_mariadb_server` now name and register
(as `start_ssh_server` does). The temporary server the image's entrypoint runs during
initialisation has networking disabled, so a TCP probe only succeeds once the real server is
up. The host client is still used, deliberately, by the tests that speak the MySQL protocol
*through Warpgate*; the `GITHUB_ACTION` client-flag switch stays for those. Rejected: pinning
a host client version — the probe has no reason to leave the container.

**D2 — One pinned tool set.** `tests/shell.nix` lists every host tool the harness and the
generators need, at versions that match CI's behaviour (notably a MariaDB 10.x client, whose
`--ssl` is opportunistic). `tests/README.md` documents the local run. CI keeps its `apt` steps
for now: moving CI onto the nix shell is a separate decision for the maintainers, and the
shell makes that move a one-line change when wanted.

**D3 — Ports scatter per process.** `alloc_port` starts each process at a point derived from
its PID (and still offsets xdist workers), keeping the monotonic counter that stops a process
racing itself and `_port_is_free` as the last line of defence. Rejected: OS-assigned ephemeral
ports — a port free at probe time is not free at bind time, and Docker publishes to the same
space, which the existing comment already explains.

**D4 — Poll for state, don't sleep for it.** `util.wait_until(condition, msg, timeout)` polls a
predicate to a deadline. `conftest.wait_for_open_session(wg, username)` uses the admin sessions
API (`active_only`, `username`) to prove a session is open, replacing the fixed negative waits
in `test_role_access_ends_sessions.py` and `test_scim.py`. Negative assertions that are the
point of a test (a session must *not* end before its role expires) keep their bounded wait.

## Out of scope (next, with their own design)

- Running pytest itself in a container: the harness spawns Docker containers (targets, OIDC
  mock, Vault, k3s) and addresses them on `localhost`, so the runner needs the Docker socket,
  a networking model for published ports, and a shared volume for llvm-cov `.profraw` files.
- An OpenLDAP container so the `WARPGATE_UNDER_TEST` short-circuits in LDAP discovery and
  import can go and those paths get e2e coverage.
- Session-scoped shared fixtures (`shared_wg`, the k3s container) that let one failing test
  poison the rest of a worker.

## Files

- `tests/util.py` (`alloc_port`, `wait_until`, `wait_mysql_port`, `mysql_containers`),
  `tests/conftest.py` (container names, `wait_for_open_session`),
  `tests/test_role_access_ends_sessions.py`, `tests/test_scim.py`,
  `tests/shell.nix`, `tests/README.md`.

## Verification

1. `test_db_migrations.py` passes on Postgres, MySQL and MariaDB from the nix shell with no
   host `mysql` client on `PATH` outside it.
2. `test_mysql_user_auth_password.py`, `test_logo.py` and `test_admin_approval_protocols.py`
   (the other `wait_mysql_port` callers) pass.
3. `test_role_access_ends_sessions.py` and `test_scim.py` pass and run faster than before.
4. Two pytest processes started concurrently do not collide on ports (checked by starting
   `test_ssh_user_auth_password.py` twice in parallel).
