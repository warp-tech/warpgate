# End-to-end tests

The suite starts Warpgate from `target/debug/warpgate` and, per test, the services it needs as
Docker containers (SSH, MySQL, MariaDB, Postgres, VNC and RDP targets, an OIDC mock, Vault,
k3s). It also shells out to a few host tools; `shell.nix` pins them all.

```sh
# once: the target images and the web assets the binary embeds
make all
( cd ../warpgate-web && npm ci && npm run build )
cargo build --all-features            # from the repository root

# the Python SDK the tests drive the admin API with (regenerate after API changes)
( cd ../warpgate-web && npm run openapi:schema:admin && npm run openapi:tests-sdk )

nix-shell                             # or install the tools shell.nix lists
poetry install
poetry run pytest test_scim.py        # one suite
TIMEOUT=120 ./run.sh                  # everything, with coverage, like CI
```

`TIMEOUT` (seconds) scales every wait in the harness; raise it on a slow machine.
Each pytest process picks its own port range, so two runs can overlap.
