# e2e harness — todo (see harness_design.md for detail)

## Phase 1 — probes and ports
- [x] Name and register MySQL/MariaDB containers; probe readiness with docker exec
- [x] Per-process port scatter in alloc_port
- [x] wait_until helper and wait_for_open_session
- [x] Replace fixed session-start waits in the role and SCIM tests

## Phase 2 — toolset
- [x] tests/shell.nix with the pinned host tools
- [x] tests/README.md with the local run

## Phase 3 — verify
- [x] Migration tests on all three databases from the nix shell
- [x] Other wait_mysql_port callers pass
- [x] Role and SCIM tests pass
- [x] Two concurrent pytest processes do not collide on ports
