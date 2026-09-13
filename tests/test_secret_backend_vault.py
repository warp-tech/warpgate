"""
Integration tests for the Vault/OpenBao secret-backend feature: targets (and Warpgate's
own SSH host/client keys) can hold a `vault://backend/path#field` reference instead of an
inline value, resolved at connect-time against a real Vault server.
"""
import asyncio
import json
import os
import subprocess
import time
from uuid import uuid4

import aiohttp
import pytest

from .api_client import admin_client, sdk
from .conftest import VNC_BACKEND_SIZE, ProcessManager, VaultInstance, WarpgateProcess
from .util import (
    _wait_timeout,
    alloc_port,
    mysql_client_opts,
    mysql_client_ssl_opt,
    wait_mysql_port,
    wait_port,
)
from .vnc_client import VncClient, VncError

# xrdp does a full NLA/CredSSP handshake before it'll relay anything, so the web-desktop
# RDP test needs more headroom than a VNC/Postgres/SSH connect -- matches test_rdp_web.py.
FRAME_TIMEOUT = 40


def _vault_backend(
    name: str,
    address: str,
    token: str = None,
    backend_type: str = "vault",
    **auth,
) -> sdk.SecretBackendRequest:
    return sdk.SecretBackendRequest(
        name=name,
        backend_type=backend_type,
        address=address,
        auth_method=auth.pop("auth_method", "token"),
        token=token,
        **auth,
    )


def _start_wg_with_backends(processes: ProcessManager, backends, **kwargs):
    wg = processes.start_wg(**kwargs)
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    with admin_client(f"https://localhost:{wg.http_port}") as api:
        for backend in backends:
            api.create_secret_backend(backend)
    return wg


def _backend_ids(api) -> dict:
    return {b.name: b.id for b in api.get_secret_backends()}


def _resolve_status(api, reference: str) -> int:
    """HTTP status of a resolve test: 204 when the reference resolves."""
    try:
        return api.test_secret_resolve_with_http_info(
            sdk.TestResolveRequest(reference=reference)
        ).status_code
    except sdk.ApiException as e:
        return e.status


# `processes` (and the Docker containers / Warpgate binaries it spawns) is session-scoped, so
# nothing about it stops a wg/vault instance once a test is done with it -- left alone, this
# file's ~13 tests x 2 backend engines pile up ~20 concurrently-running dev-mode Vault/OpenBao
# containers plus a dozen RUST_LOG=debug Warpgate processes by its second half, which reliably
# kills later Warpgate processes outright (observed: they exit with no error output at all,
# consistent with the OS stepping in under the accumulated memory/thread pressure) well before
# the session-end teardown ever gets a chance to run. Tests register their wg/vault instances
# here so each is torn down as soon as the test that owns it finishes, keeping the concurrent
# footprint flat instead of monotonically growing across the file.
@pytest.fixture
def stop_at_end():
    stoppers = []
    yield stoppers.append
    for stop in reversed(stoppers):
        stop()


def _stop_wg(wg: WarpgateProcess):
    wg.process.terminate()
    wg.process.wait()


def _stop_vault(vault: VaultInstance):
    subprocess.run(
        ["docker", "stop", vault.container_name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


# Every test that talks to a live backend server is parametrized over this fixture so the whole
# suite runs unmodified against both supported implementations -- Vault and its OpenBao fork.
@pytest.fixture(params=["vault", "openbao"])
def backend_engine(request):
    return request.param


class TestSecretBackendVault:

    def test_resolve_via_admin_api(self, processes: ProcessManager, backend_engine, timeout, stop_at_end):
        vault: VaultInstance = processes.start_vault(engine=backend_engine)
        stop_at_end(lambda: _stop_vault(vault))
        vault.kv_put("secret", "myapp", password="hunter2")

        wg = _start_wg_with_backends(
            processes,
            [_vault_backend("vault-test", vault.addr, token=vault.root_token, backend_type=vault.backend_type)],
        )
        stop_at_end(lambda: _stop_wg(wg))
        url = f"https://localhost:{wg.http_port}"
        scheme = vault.backend_type

        with admin_client(url) as api:
            assert _resolve_status(api, f"{scheme}://vault-test/secret/myapp#password") == 204

            # wrong field within an existing secret -> NotFound
            assert _resolve_status(api, f"{scheme}://vault-test/secret/myapp#nope") == 404

            # wrong KV path -> NotFound
            assert _resolve_status(api, f"{scheme}://vault-test/secret/nope#password") == 404

            # reference to a backend name that isn't configured
            assert _resolve_status(api, f"{scheme}://not-configured/secret/myapp#password") == 404

            # malformed URI -> 400 Bad Request
            with pytest.raises(sdk.ApiException) as exc:
                api.test_secret_resolve(sdk.TestResolveRequest(reference="not-a-valid-uri"))
            assert exc.value.status == 400

    def test_backend_health_and_listing(self, processes: ProcessManager, backend_engine, timeout, stop_at_end):
        vault: VaultInstance = processes.start_vault(engine=backend_engine)
        stop_at_end(lambda: _stop_vault(vault))
        wg = _start_wg_with_backends(
            processes,
            [_vault_backend("vault-test", vault.addr, token=vault.root_token, backend_type=vault.backend_type)],
        )
        stop_at_end(lambda: _stop_wg(wg))
        url = f"https://localhost:{wg.http_port}"

        with admin_client(url) as api:
            backends = api.get_secret_backends()
            assert len(backends) == 1
            assert backends[0].name == "vault-test"
            assert backends[0].address == vault.addr

            health = api.check_secret_backend_health(backends[0].id)
            assert health.health == "ok", health.error
            assert health.error is None

            with pytest.raises(sdk.ApiException) as exc:
                api.check_secret_backend_health(str(uuid4()))
            assert exc.value.status == 404

    def test_multiple_backends_resolve_independently(self, processes: ProcessManager, backend_engine, timeout, stop_at_end):
        vault_a: VaultInstance = processes.start_vault(engine=backend_engine)
        stop_at_end(lambda: _stop_vault(vault_a))
        vault_b: VaultInstance = processes.start_vault(engine=backend_engine)
        stop_at_end(lambda: _stop_vault(vault_b))
        vault_a.kv_put("secret", "myapp", password="from-a")
        vault_b.kv_put("secret", "myapp", password="from-b")

        wg = _start_wg_with_backends(
            processes,
            [
                _vault_backend("vault-a", vault_a.addr, token=vault_a.root_token, backend_type=vault_a.backend_type),
                _vault_backend("vault-b", vault_b.addr, token=vault_b.root_token, backend_type=vault_b.backend_type),
            ],
        )
        stop_at_end(lambda: _stop_wg(wg))
        url = f"https://localhost:{wg.http_port}"
        scheme = vault_a.backend_type

        with admin_client(url) as api:
            backends = api.get_secret_backends()
            assert {b.name for b in backends} == {"vault-a", "vault-b"}
            assert {b.address for b in backends} == {vault_a.addr, vault_b.addr}
            assert all(api.check_secret_backend_health(b.id).health == "ok" for b in backends)

            # each backend name routes to its own Vault instance, not to the other one's data
            assert _resolve_status(api, f"{scheme}://vault-a/secret/myapp#password") == 204

            assert _resolve_status(api, f"{scheme}://vault-b/secret/myapp#password") == 204

            # a path that only exists in vault_a is not visible through the vault-b backend
            vault_a.kv_put("secret", "only-in-a", password="secret")
            assert _resolve_status(api, f"{scheme}://vault-b/secret/only-in-a#password") == 404

    def test_multiple_backends_independent_health(self, processes: ProcessManager, backend_engine, timeout, stop_at_end):
        vault: VaultInstance = processes.start_vault(engine=backend_engine)
        stop_at_end(lambda: _stop_vault(vault))
        bogus_port = alloc_port()  # nothing is listening here

        wg = _start_wg_with_backends(
            processes,
            [
                _vault_backend("vault-healthy", vault.addr, token=vault.root_token, backend_type=vault.backend_type),
                _vault_backend(
                    "vault-unreachable",
                    f"http://127.0.0.1:{bogus_port}",
                    token="bogus",
                    backend_type=vault.backend_type,
                ),
            ],
        )
        stop_at_end(lambda: _stop_wg(wg))
        url = f"https://localhost:{wg.http_port}"

        with admin_client(url) as api:
            ids = _backend_ids(api)
            healthy = api.check_secret_backend_health(ids["vault-healthy"])
            assert healthy.health == "ok"
            assert healthy.error is None
            unreachable = api.check_secret_backend_health(ids["vault-unreachable"])
            assert unreachable.health == "error"
            assert unreachable.error is not None

            # the broken backend must not prevent resolving secrets from the healthy one
            vault.kv_put("secret", "myapp", password="hunter2")
            assert _resolve_status(api, f"{vault.backend_type}://vault-healthy/secret/myapp#password") == 204

    def test_duplicate_or_invalid_backend_name_is_rejected(self, processes: ProcessManager, shared_wg, timeout):
        url = f"https://localhost:{shared_wg.http_port}"
        name = f"vault-{uuid4().hex[:8]}"
        with admin_client(url) as api:
            created = api.create_secret_backend(
                _vault_backend(name, "https://vault.invalid:8200", token="x")
            )
            with pytest.raises(sdk.ApiException) as exc:
                api.create_secret_backend(
                    _vault_backend(name, "https://vault.invalid:8200", token="x")
                )
            assert exc.value.status == 409

            api.delete_secret_backend(created.id)
            assert name not in _backend_ids(api)

    def test_update_keeps_secret_when_omitted(self, processes: ProcessManager, backend_engine, timeout, stop_at_end):
        vault: VaultInstance = processes.start_vault(engine=backend_engine)
        stop_at_end(lambda: _stop_vault(vault))
        vault.kv_put("secret", "myapp", password="hunter2")
        wg = _start_wg_with_backends(
            processes,
            [_vault_backend("vault-test", vault.addr, token=vault.root_token, backend_type=vault.backend_type)],
        )
        stop_at_end(lambda: _stop_wg(wg))
        reference = f"{vault.backend_type}://vault-test/secret/myapp#password"

        with admin_client(f"https://localhost:{wg.http_port}") as api:
            backend_id = _backend_ids(api)["vault-test"]
            assert _resolve_status(api, reference) == 204

            # no token in the update -> the stored one stays, and is picked up without a restart
            api.update_secret_backend(
                backend_id,
                _vault_backend("vault-test", vault.addr, backend_type=vault.backend_type),
            )
            assert _resolve_status(api, reference) == 204

            api.update_secret_backend(
                backend_id,
                _vault_backend("vault-test", vault.addr, token="wrong", backend_type=vault.backend_type),
            )
            assert _resolve_status(api, reference) == 502

            # switching the auth method without its secret is refused, not silently broken
            with pytest.raises(sdk.ApiException) as exc:
                api.update_secret_backend(
                    backend_id,
                    _vault_backend(
                        "vault-test",
                        vault.addr,
                        backend_type=vault.backend_type,
                        auth_method="app_role",
                        app_role_id="role",
                    ),
                )
            assert exc.value.status == 400

            # a backend that a target references can't be deleted from under it
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    require_approval=False,
                    ticket_requests_disabled=False,
                    ticket_require_approval=False,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            allow_insecure_algos=False,
                            host="localhost",
                            port=22,
                            username="root",
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPasswordAuth(kind="Password", password=reference)
                            ),
                        )
                    ),
                )
            )
            with pytest.raises(sdk.ApiException) as exc:
                api.delete_secret_backend(backend_id)
            assert exc.value.status == 409
            api.delete_target(target.id)
            api.delete_secret_backend(backend_id)

    def test_secret_reference_usage_reports_target(self, processes: ProcessManager, shared_wg, timeout):
        # secret_references() only inspects stored target config, so this doesn't need a
        # live/reachable backend at all -- the shared wg instance (no backend configured) is fine.
        url = f"https://localhost:{shared_wg.http_port}"
        reference = "vault://vault-test/secret/shared#password"

        with admin_client(url) as api:
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    require_approval=False,
                    ticket_requests_disabled=False,
                    ticket_require_approval=False,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            allow_insecure_algos=False,
                            host="localhost",
                            port=22,
                            username="root",
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPasswordAuth(
                                    kind="Password",
                                    password=reference,
                                )
                            ),
                        )
                    ),
                )
            )

            usage = api.get_secret_reference_usage()
            entry = next(u for u in usage if u.reference == reference)
            assert entry.backend == "vault-test"
            assert entry.target_count == 1
            assert entry.targets[0].id == target.id
            assert entry.targets[0].name == target.name

    def test_secret_reference_usage_multiple_targets_share_secret(
        self, processes: ProcessManager, backend_engine, timeout, stop_at_end
    ):
        # two targets of different kinds pointing at the exact same vault:// reference must both
        # show up under a single usage entry, and deleting one must leave the other -- and the
        # underlying secret -- untouched.
        vault: VaultInstance = processes.start_vault(engine=backend_engine)
        stop_at_end(lambda: _stop_vault(vault))
        vault.kv_put("secret", "shared", password="hunter2")
        reference = f"{vault.backend_type}://vault-test/secret/shared#password"

        wg = _start_wg_with_backends(
            processes,
            [_vault_backend("vault-test", vault.addr, token=vault.root_token, backend_type=vault.backend_type)],
        )
        stop_at_end(lambda: _stop_wg(wg))
        url = f"https://localhost:{wg.http_port}"

        with admin_client(url) as api:
            ssh_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    require_approval=False,
                    ticket_requests_disabled=False,
                    ticket_require_approval=False,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            allow_insecure_algos=False,
                            host="localhost",
                            port=22,
                            username="root",
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPasswordAuth(
                                    kind="Password",
                                    password=reference,
                                )
                            ),
                        )
                    ),
                )
            )
            postgres_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"postgres-{uuid4()}",
                    require_approval=False,
                    ticket_requests_disabled=False,
                    ticket_require_approval=False,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetPostgresOptions(
                            kind="Postgres",
                            protocol_version="3.2",
                            host="localhost",
                            port=5432,
                            username="user",
                            auth=sdk.DatabaseTargetAuth(
                                sdk.DatabaseTargetAuthDatabaseTargetPasswordAuth(
                                    kind="Password",
                                    password=reference,
                                )
                            ),
                            tls=sdk.Tls(mode=sdk.TlsMode.PREFERRED, verify=False),
                        )
                    ),
                )
            )

            usage = api.get_secret_reference_usage()
            entry = next(u for u in usage if u.reference == reference)
            assert entry.backend == "vault-test"
            assert entry.target_count == 2
            assert {t.id for t in entry.targets} == {ssh_target.id, postgres_target.id}

            # deleting one of the two sharing targets must not touch the upstream secret, and the
            # other target must keep resolving it fine
            api.delete_target(ssh_target.id)

            usage = api.get_secret_reference_usage()
            entry = next(u for u in usage if u.reference == reference)
            assert entry.target_count == 1
            assert entry.targets[0].id == postgres_target.id

            assert _resolve_status(api, reference) == 204

    def test_postgres_target_password_from_vault(self, processes: ProcessManager, backend_engine, timeout, stop_at_end):
        db_port = processes.start_postgres_server()
        vault: VaultInstance = processes.start_vault(engine=backend_engine)
        stop_at_end(lambda: _stop_vault(vault))
        vault.kv_put("secret", "db", password="123")

        wg = _start_wg_with_backends(
            processes,
            [_vault_backend("vault-test", vault.addr, token=vault.root_token, backend_type=vault.backend_type)],
        )
        stop_at_end(lambda: _stop_wg(wg))
        url = f"https://localhost:{wg.http_port}"

        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
            api.add_user_role(user.id, role.id)
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"postgres-{uuid4()}",
                    require_approval=False,
                    ticket_requests_disabled=False,
                    ticket_require_approval=False,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetPostgresOptions(
                            kind="Postgres",
                            protocol_version="3.2",
                            host="localhost",
                            port=db_port,
                            username="user",
                            auth=sdk.DatabaseTargetAuth(
                                sdk.DatabaseTargetAuthDatabaseTargetPasswordAuth(
                                    kind="Password",
                                    password=f"{vault.backend_type}://vault-test/secret/db#password",
                                )
                            ),
                            tls=sdk.Tls(mode=sdk.TlsMode.PREFERRED, verify=False),
                        )
                    ),
                )
            )
            api.add_target_role(target.id, role.id)

        wait_port(db_port, recv=False)
        wait_port(wg.postgres_port, recv=False)

        def psql():
            return processes.start(
                [
                    "psql",
                    "--user",
                    f"{user.username}#{target.name}",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(wg.postgres_port),
                    "db",
                ],
                env={"PGPASSWORD": "123", **os.environ},
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )

        client = psql()
        out = client.communicate(b"\\dt\n", timeout=timeout)[0]
        assert b"tbl" in out
        assert client.returncode == 0

        # flip the Vault-stored value; the same target must now fail, proving the password
        # is re-resolved from Vault on every connect rather than cached/inlined at creation time
        vault.kv_put("secret", "db", password="wrong")
        client = psql()
        client.communicate(b"\\dt\n", timeout=timeout)
        assert client.returncode != 0

    # def test_mysql_target_password_from_vault(self, processes: ProcessManager, timeout):
    #     db_port = processes.start_mysql_server()
    #     wait_mysql_port(db_port)

    #     vault: VaultInstance = processes.start_vault()
    #     vault.kv_put("secret", "db", password="123")

    #     wg = _start_wg_with_backends(processes, [_vault_backend("vault-test", vault.addr, token=vault.root_token)])
    #     url = f"https://localhost:{wg.http_port}"

    #     with admin_client(url) as api:
    #         role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
    #         user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
    #         api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
    #         api.add_user_role(user.id, role.id)
    #         target = api.create_target(
    #             sdk.TargetDataRequest(
    #                 name=f"mysql-{uuid4()}",
    #                 options=sdk.TargetOptions(
    #                     sdk.TargetOptionsTargetMySqlOptions(
    #                         kind="MySql",
    #                         host="localhost",
    #                         port=db_port,
    #                         username="root",
    #                         auth=sdk.DatabaseTargetAuth(
    #                             sdk.DatabaseTargetAuthDatabaseTargetPasswordAuth(
    #                                 kind="Password",
    #                                 password="vault://vault-test/secret/db#password",
    #                             )
    #                         ),
    #                         tls=sdk.Tls(mode=sdk.TlsMode.PREFERRED, verify=False),
    #                     )
    #                 ),
    #             )
    #         )
    #         api.add_target_role(target.id, role.id)

    #     wait_port(wg.mysql_port, recv=False)

    #     client = processes.start(
    #         [
    #             "mysql",
    #             "--user",
    #             f"{user.username}#{target.name}",
    #             "-p123",
    #             "--host",
    #             "127.0.0.1",
    #             "--port",
    #             str(wg.mysql_port),
    #             *mysql_client_opts,
    #             mysql_client_ssl_opt,
    #             "db",
    #         ],
    #         stdin=subprocess.PIPE,
    #         stdout=subprocess.PIPE,
    #     )
    #     out = client.communicate(b"show tables;", timeout=timeout)[0]
    #     assert b"table" in out
    #     assert client.returncode == 0

    def test_ssh_target_password_from_vault(self, processes: ProcessManager, backend_engine, timeout, stop_at_end):
        ssh_port = processes.start_ssh_server(root_password="hunter2")
        wait_port(ssh_port)

        vault: VaultInstance = processes.start_vault(engine=backend_engine)
        stop_at_end(lambda: _stop_vault(vault))
        vault.kv_put("secret", "sshtarget", password="hunter2")

        wg = _start_wg_with_backends(
            processes,
            [_vault_backend("vault-test", vault.addr, token=vault.root_token, backend_type=vault.backend_type)],
        )
        stop_at_end(lambda: _stop_wg(wg))
        wait_port(wg.ssh_port, for_process=wg.process)
        url = f"https://localhost:{wg.http_port}"

        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
            api.add_user_role(user.id, role.id)
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    require_approval=False,
                    ticket_requests_disabled=False,
                    ticket_require_approval=False,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            allow_insecure_algos=False,
                            host="localhost",
                            port=ssh_port,
                            username="root",
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPasswordAuth(
                                    kind="Password",
                                    password=f"{vault.backend_type}://vault-test/secret/sshtarget#password",
                                )
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(target.id, role.id)

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{target.name}@localhost",
            "-p",
            str(wg.ssh_port),
            "-i",
            "/dev/null",
            "-o",
            "PreferredAuthentications=password",
            "echo",
            "hello",
            password="123",
        )
        output = ssh_client.communicate(timeout=timeout)[0]
        assert b"hello" in output
        assert ssh_client.returncode == 0

    def test_vnc_target_password_from_vault(self, processes: ProcessManager, backend_engine, timeout, stop_at_end):
        vnc_port = processes.start_vnc_server(require_password=True)
        wait_port(vnc_port)

        vault: VaultInstance = processes.start_vault(engine=backend_engine)
        stop_at_end(lambda: _stop_vault(vault))
        vault.kv_put("secret", "vnctarget", password="123")

        wg = _start_wg_with_backends(
            processes,
            [_vault_backend("vault-test", vault.addr, token=vault.root_token, backend_type=vault.backend_type)],
        )
        stop_at_end(lambda: _stop_wg(wg))
        wait_port(wg.vnc_port)
        url = f"https://localhost:{wg.http_port}"

        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
            api.add_user_role(user.id, role.id)
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"vnc-{uuid4()}",
                    require_approval=False,
                    ticket_requests_disabled=False,
                    ticket_require_approval=False,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetVncOptions(
                            kind="Vnc",
                            host="localhost",
                            port=vnc_port,
                            auth=sdk.VncTargetAuth(
                                sdk.VncTargetAuthVncTargetPasswordAuth(
                                    kind="Password",
                                    password=f"{vault.backend_type}://vault-test/secret/vnctarget#password",
                                )
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(target.id, role.id)

        client = VncClient(
            "localhost", wg.vnc_port, f"{user.username}:{target.name}", "123", timeout=timeout
        )
        try:
            client.connect()
            # Reaching the resize means the relay authenticated to the backend using the
            # password resolved from Vault.
            assert client.wait_for_resize() == VNC_BACKEND_SIZE
        finally:
            client.close()

        # flip the Vault-stored value; a fresh connection must now fail to relay, proving the
        # password is re-resolved from Vault on every connect rather than cached/inlined at
        # target-creation time
        vault.kv_put("secret", "vnctarget", password="wrong")
        client = VncClient(
            "localhost", wg.vnc_port, f"{user.username}:{target.name}", "123", timeout=timeout
        )
        try:
            client.connect()
            with pytest.raises((VncError, OSError)):
                client.wait_for_resize()
        finally:
            client.close()

    def test_rdp_target_password_from_vault(self, processes: ProcessManager, backend_engine, timeout, stop_at_end):
        # RDP's native listener can't observe a post-handshake backend-auth rejection (see
        # rdp_client.py), so unlike the other protocols this drives a real backend connection
        # via the web-desktop relay and looks for a relayed framebuffer, the same bar
        # test_rdp_web.py uses to prove a real connection got made.
        #
        # No "wrong password must fail" counterpart here (unlike the other protocols): the
        # e2e xrdp image runs `security_layer=negotiate` and, per its own Dockerfile comment,
        # has "limited NLA-server support" that's still an open question -- empirically, a
        # second connection against it produces a relayed framebuffer regardless of the
        # password passed, whether that's xrdp reattaching the already-running X session for
        # the `user` OS account or falling back to an in-band login screen instead of
        # rejecting pre-session over CredSSP. Either way that's a backend-image property, not
        # something this test can use to assert on Warpgate's behavior.
        rdp_backend_port = processes.start_rdp_server()
        wait_port(rdp_backend_port, recv=False)
        # xrdp accepts TCP before sesman is ready to start a session; give it a moment.
        time.sleep(3)

        vault: VaultInstance = processes.start_vault(engine=backend_engine)
        stop_at_end(lambda: _stop_vault(vault))
        vault.kv_put("secret", "rdptarget", password="123")

        wg = _start_wg_with_backends(
            processes,
            [_vault_backend("vault-test", vault.addr, token=vault.root_token, backend_type=vault.backend_type)],
        )
        stop_at_end(lambda: _stop_wg(wg))
        url = f"https://localhost:{wg.http_port}"

        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
            api.add_user_role(user.id, role.id)
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"rdp-{uuid4()}",
                    require_approval=False,
                    ticket_requests_disabled=False,
                    ticket_require_approval=False,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetRdpOptions(
                            kind="Rdp",
                            compression=sdk.RdpTargetCompression.REMOTEFX,
                            tls_security=sdk.RdpTlsSecurity.TLS12,
                            interactive_logon=False,
                            host="localhost",
                            port=rdp_backend_port,
                            username="user",  # the xrdp login baked into the image
                            auth=sdk.RdpTargetAuth(
                                sdk.RdpTargetAuthRdpTargetPasswordAuth(
                                    kind="Password",
                                    password=f"{vault.backend_type}://vault-test/secret/rdptarget#password",
                                )
                            ),
                            verify_tls=False,
                        )
                    ),
                )
            )
            api.add_target_role(target.id, role.id)

        async def open_desktop_session():
            headers = {"Host": f"localhost:{wg.http_port}"}
            session = aiohttp.ClientSession()
            try:
                login = await session.post(
                    f"{url}/@warpgate/api/auth/login",
                    json={"username": user.username, "password": "123"},
                    headers=headers,
                    ssl=False,
                )
                assert login.status // 100 == 2, f"login failed: {login.status}"

                created = await session.post(
                    f"{url}/@warpgate/api/web-desktop/sessions",
                    json={"target_id": str(target.id)},
                    headers=headers,
                    ssl=False,
                )
                assert created.status == 201, (
                    f"session create failed: {created.status} {await created.text()}"
                )
                session_id = (await created.json())["session_id"]

                ws = await session.ws_connect(
                    url.replace("https:", "wss:")
                    + f"/@warpgate/api/web-desktop/sessions/{session_id}/stream",
                    ssl=False,
                )

                got_image = False
                got_resize = False
                got_error = False
                messages = []
                deadline = time.monotonic() + FRAME_TIMEOUT
                while time.monotonic() < deadline and not (got_image or got_resize or got_error):
                    try:
                        msg = await ws.receive(timeout=deadline - time.monotonic())
                    except asyncio.TimeoutError:
                        break
                    if msg.type == aiohttp.WSMsgType.BINARY:
                        got_image = True
                    elif msg.type == aiohttp.WSMsgType.TEXT:
                        parsed = json.loads(msg.data)
                        messages.append(parsed)
                        if parsed.get("type") == "resize":
                            got_resize = True
                        if parsed.get("type") == "error":
                            got_error = True
                    else:  # CLOSED / CLOSING / ERROR
                        break

                await session.delete(
                    f"{url}/@warpgate/api/web-desktop/sessions/{session_id}",
                    headers=headers,
                    ssl=False,
                )
                return got_image, got_resize, got_error, messages
            finally:
                await session.close()

        loop = asyncio.new_event_loop()
        try:
            got_image, got_resize, got_error, messages = loop.run_until_complete(open_desktop_session())
        finally:
            loop.close()
        assert got_image or got_resize, (
            f"backend never relayed a framebuffer with the vault-resolved password; "
            f"messages: {messages}"
        )
        assert not got_error, f"unexpected error resolving the vault password: {messages}"

    def test_unreachable_backend_is_isolated(self, processes: ProcessManager, timeout, stop_at_end):
        bogus_port = alloc_port()  # nothing is listening here

        # AppRole so building the client actually logs in over the network and fails; the
        # failure must stay contained to that backend.
        wg = _start_wg_with_backends(
            processes,
            [
                _vault_backend(
                    "unreachable",
                    f"http://127.0.0.1:{bogus_port}",
                    auth_method="app_role",
                    app_role_id="bogus-role-id",
                    app_role_secret_id="bogus-secret-id",
                )
            ],
        )
        stop_at_end(lambda: _stop_wg(wg))
        wait_port(wg.ssh_port, for_process=wg.process)

        url = f"https://localhost:{wg.http_port}"
        db_port = processes.start_postgres_server()

        with admin_client(url) as api:
            backend_id = _backend_ids(api)["unreachable"]
            assert api.check_secret_backend_health(backend_id).health == "error"

            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
            api.add_user_role(user.id, role.id)
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"postgres-{uuid4()}",
                    require_approval=False,
                    ticket_requests_disabled=False,
                    ticket_require_approval=False,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetPostgresOptions(
                            kind="Postgres",
                            protocol_version="3.2",
                            host="localhost",
                            port=db_port,
                            username="user",
                            auth=sdk.DatabaseTargetAuth(
                                sdk.DatabaseTargetAuthDatabaseTargetPasswordAuth(
                                    kind="Password",
                                    password="123",
                                )
                            ),
                            tls=sdk.Tls(mode=sdk.TlsMode.PREFERRED, verify=False),
                        )
                    ),
                )
            )
            api.add_target_role(target.id, role.id)

        # an ordinary target with an inline password is unaffected by the broken backend
        wait_port(db_port, recv=False)
        wait_port(wg.postgres_port, recv=False)
        client = processes.start(
            [
                "psql",
                "--user",
                f"{user.username}#{target.name}",
                "--host",
                "127.0.0.1",
                "--port",
                str(wg.postgres_port),
                "db",
            ],
            env={"PGPASSWORD": "123", **os.environ},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        out = client.communicate(b"\\dt\n", timeout=timeout)[0]
        assert b"tbl" in out
        assert client.returncode == 0

    def test_ssh_host_keys_from_vault(self, processes: ProcessManager, backend_engine, timeout, stop_at_end):
        vault: VaultInstance = processes.start_vault(engine=backend_engine)
        stop_at_end(lambda: _stop_vault(vault))

        key_path = processes.ctx.tmpdir / f"host-key-{uuid4()}"
        subprocess.check_call(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-m", "PKCS8", "-f", str(key_path)],
            stdout=subprocess.DEVNULL,
        )
        public_key = key_path.with_suffix(".pub").read_text().split()[1]
        vault.kv_put("secret", "warpgate-host-keys", ed25519=key_path.read_text())

        wg = _start_wg_with_backends(
            processes,
            [_vault_backend("vault-test", vault.addr, token=vault.root_token, backend_type=vault.backend_type)],
        )
        wait_port(wg.ssh_port, for_process=wg.process)
        with admin_client(f"https://localhost:{wg.http_port}") as api:
            api.update_parameters(
                sdk.ParameterUpdate(
                    ssh_host_key_secret_ref=f"{vault.backend_type}://vault-test/secret/warpgate-host-keys"
                )
            )
        _stop_wg(wg)

        # the parameter is read when the SSH listener binds
        wg = processes.start_wg(share_with=wg)
        stop_at_end(lambda: _stop_wg(wg))
        wait_port(wg.ssh_port, for_process=wg.process)

        # The host key is exchanged before authentication, so a login attempt that
        # goes nowhere still records it.
        known_hosts = processes.ctx.tmpdir / f"known-hosts-{uuid4()}"
        subprocess.run(
            [
                "ssh",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", f"UserKnownHostsFile={known_hosts}",
                "-o", "HostKeyAlgorithms=ssh-ed25519",
                "-o", "PreferredAuthentications=none",
                "-o", "BatchMode=yes",
                "-p", str(wg.ssh_port),
                "nobody@localhost",
                "true",
            ],
            capture_output=True,
            timeout=timeout,
        )
        assert public_key in known_hosts.read_text()

    def test_ssh_client_key_from_vault(self, processes: ProcessManager, backend_engine, timeout, stop_at_end):
        vault: VaultInstance = processes.start_vault(engine=backend_engine)
        stop_at_end(lambda: _stop_vault(vault))

        key_path = processes.ctx.tmpdir / f"client-key-{uuid4()}"
        subprocess.check_call(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key_path)],
            stdout=subprocess.DEVNULL,
        )
        public_key = key_path.with_suffix(".pub").read_text().strip()
        vault.kv_put("secret", "warpgate-client-key", private_key=key_path.read_text())

        ssh_port = processes.start_ssh_server(trusted_keys=[public_key])
        wait_port(ssh_port)

        wg = _start_wg_with_backends(
            processes,
            [_vault_backend("vault-test", vault.addr, token=vault.root_token, backend_type=vault.backend_type)],
        )
        stop_at_end(lambda: _stop_wg(wg))
        wait_port(wg.ssh_port, for_process=wg.process)

        with admin_client(f"https://localhost:{wg.http_port}") as api:
            key = api.import_ssh_own_key_reference(
                sdk.ImportSSHClientKeyReferenceRequest(
                    label="vault-key",
                    reference=f"{vault.backend_type}://vault-test/secret/warpgate-client-key#private_key",
                    is_default=False,
                )
            )
            assert key.backend == "vault-test"
            assert key.public_key.split()[1] == public_key.split()[1]

            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
            api.add_user_role(user.id, role.id)
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    require_approval=False,
                    ticket_requests_disabled=False,
                    ticket_require_approval=False,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            allow_insecure_algos=False,
                            host="localhost",
                            port=ssh_port,
                            username="root",
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey", key_id=key.id)
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(target.id, role.id)

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{target.name}@localhost",
            "-p",
            str(wg.ssh_port),
            "-i",
            "/dev/null",
            "-o",
            "PreferredAuthentications=password",
            "echo",
            "hello",
            password="123",
        )
        output = ssh_client.communicate(timeout=timeout)[0]
        assert b"hello" in output
        assert ssh_client.returncode == 0

    # ── AppRole auth method (not just static Token) ──────────────────────────

    def test_approle_auth_method(self, processes: ProcessManager, backend_engine, timeout, stop_at_end):
        vault: VaultInstance = processes.start_vault(engine=backend_engine)
        stop_at_end(lambda: _stop_vault(vault))
        vault.kv_put("secret", "myapp", password="hunter2")
        vault.enable_approle()
        role_id, secret_id = vault.create_approle_role(
            "warpgate-role",
            policy_hcl=(
                'path "secret/data/*" { capabilities = ["read", "create", "update"] }\n'
                'path "secret/metadata/*" { capabilities = ["read", "list"] }\n'
            ),
        )

        wg = _start_wg_with_backends(
            processes,
            [
                _vault_backend(
                    "vault-test",
                    vault.addr,
                    auth_method="app_role",
                    app_role_id=role_id,
                    app_role_secret_id=secret_id,
                    backend_type=vault.backend_type,
                )
            ],
        )
        stop_at_end(lambda: _stop_wg(wg))
        url = f"https://localhost:{wg.http_port}"

        with admin_client(url) as api:
            assert _resolve_status(api, f"{vault.backend_type}://vault-test/secret/myapp#password") == 204
