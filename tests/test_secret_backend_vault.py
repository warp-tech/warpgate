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
import yaml

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


def _vault_backend(name: str, address: str, token: str = None, auth: dict = None, backend_type: str = "vault") -> dict:
    return {
        "name": name,
        "type": backend_type,
        "address": address,
        "auth": auth or {"method": "token", "token": token},
    }


def _start_wg_with_backends(processes: ProcessManager, backends, **kwargs):
    wg = processes.start_wg(config_patch={"secrets": {"backends": backends}}, **kwargs)
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    return wg


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
            resp = api.test_secret_resolve(
                sdk.TestResolveRequest(reference=f"{scheme}://vault-test/secret/myapp#password")
            )
            assert resp.ok is True
            assert resp.error is None

            # wrong field within an existing secret -> NotFound
            resp = api.test_secret_resolve(
                sdk.TestResolveRequest(reference=f"{scheme}://vault-test/secret/myapp#nope")
            )
            assert resp.ok is False
            assert resp.error

            # wrong KV path -> NotFound
            resp = api.test_secret_resolve(
                sdk.TestResolveRequest(reference=f"{scheme}://vault-test/secret/nope#password")
            )
            assert resp.ok is False
            assert resp.error

            # reference to a backend name that isn't configured
            resp = api.test_secret_resolve(
                sdk.TestResolveRequest(reference=f"{scheme}://not-configured/secret/myapp#password")
            )
            assert resp.ok is False
            assert "not configured" in resp.error

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
            assert backends[0].health == "ok"
            assert backends[0].health_error is None

            health = api.check_secret_backend_health("vault-test")
            assert health.health == "ok"
            assert health.error is None

            with pytest.raises(sdk.ApiException) as exc:
                api.check_secret_backend_health("does-not-exist")
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
            assert all(b.health == "ok" for b in backends)

            # each backend name routes to its own Vault instance, not to the other one's data
            resp = api.test_secret_resolve(
                sdk.TestResolveRequest(reference=f"{scheme}://vault-a/secret/myapp#password")
            )
            assert resp.ok is True

            resp = api.test_secret_resolve(
                sdk.TestResolveRequest(reference=f"{scheme}://vault-b/secret/myapp#password")
            )
            assert resp.ok is True

            # a path that only exists in vault_a is not visible through the vault-b backend
            vault_a.kv_put("secret", "only-in-a", password="secret")
            resp = api.test_secret_resolve(
                sdk.TestResolveRequest(reference=f"{scheme}://vault-b/secret/only-in-a#password")
            )
            assert resp.ok is False

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
            backends = {b.name: b for b in api.get_secret_backends()}
            assert backends["vault-healthy"].health == "ok"
            assert backends["vault-healthy"].health_error is None
            assert backends["vault-unreachable"].health == "error"
            assert backends["vault-unreachable"].health_error is not None

            # per-name health check agrees with the listing
            assert api.check_secret_backend_health("vault-healthy").health == "ok"
            assert api.check_secret_backend_health("vault-unreachable").health == "error"

            # the broken backend must not prevent resolving secrets from the healthy one
            vault.kv_put("secret", "myapp", password="hunter2")
            resp = api.test_secret_resolve(
                sdk.TestResolveRequest(reference=f"{vault.backend_type}://vault-healthy/secret/myapp#password")
            )
            assert resp.ok is True

    def test_duplicate_backend_name_keeps_first_definition(self, processes: ProcessManager, backend_engine, timeout, stop_at_end):
        vault_first: VaultInstance = processes.start_vault(engine=backend_engine)
        stop_at_end(lambda: _stop_vault(vault_first))
        vault_second: VaultInstance = processes.start_vault(engine=backend_engine)
        stop_at_end(lambda: _stop_vault(vault_second))
        vault_first.kv_put("secret", "myapp", password="from-first")
        vault_second.kv_put("secret", "myapp", password="from-second")

        # two backend entries sharing the same name -- the registry keeps only the first and
        # logs+skips the second, so resolution must always hit vault_first, never vault_second
        wg = _start_wg_with_backends(
            processes,
            [
                _vault_backend(
                    "vault-test", vault_first.addr, token=vault_first.root_token, backend_type=vault_first.backend_type
                ),
                _vault_backend(
                    "vault-test",
                    vault_second.addr,
                    token=vault_second.root_token,
                    backend_type=vault_second.backend_type,
                ),
            ],
        )
        stop_at_end(lambda: _stop_wg(wg))
        url = f"https://localhost:{wg.http_port}"
        scheme = vault_first.backend_type

        with admin_client(url) as api:
            resp = api.test_secret_resolve(
                sdk.TestResolveRequest(reference=f"{scheme}://vault-test/secret/myapp#password")
            )
            assert resp.ok is True

            # a path that only exists in the second (shadowed) Vault is unreachable, proving the
            # first definition -- not the second -- is the one actually serving the name
            vault_second.kv_put("secret", "only-in-second", password="x")
            resp = api.test_secret_resolve(
                sdk.TestResolveRequest(reference=f"{scheme}://vault-test/secret/only-in-second#password")
            )
            assert resp.ok is False

    def test_secret_reference_usage_reports_target(self, processes: ProcessManager, shared_wg, timeout):
        # secret_references() only inspects stored target config, so this doesn't need a
        # live/reachable backend at all -- the shared wg instance (no backend configured) is fine.
        url = f"https://localhost:{shared_wg.http_port}"
        reference = "vault://vault-test/secret/shared#password"

        with admin_client(url) as api:
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
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
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
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
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetPostgresOptions(
                            kind="Postgres",
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

            resp = api.test_secret_resolve(sdk.TestResolveRequest(reference=reference))
            assert resp.ok is True

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
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetPostgresOptions(
                            kind="Postgres",
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
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
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
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetRdpOptions(
                            kind="Rdp",
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

    def test_unreachable_backend_does_not_block_startup(self, processes: ProcessManager, timeout, stop_at_end):
        bogus_port = alloc_port()  # nothing is listening here

        # AppRole (rather than Token) so the initial-authentication login actually goes over
        # the network and fails -- exercising VaultBackend::new()'s documented "best-effort
        # initial authentication" resilience, not just a backend that never touched the network.
        role_id_file = processes.ctx.tmpdir / f"bogus-role-id-{uuid4()}"
        secret_id_file = processes.ctx.tmpdir / f"bogus-secret-id-{uuid4()}"
        role_id_file.write_text("bogus-role-id")
        secret_id_file.write_text("bogus-secret-id")

        wg = _start_wg_with_backends(
            processes,
            [
                _vault_backend(
                    "unreachable",
                    f"http://127.0.0.1:{bogus_port}",
                    auth={
                        "method": "app_role",
                        "role_id_file": str(role_id_file),
                        "secret_id_file": str(secret_id_file),
                    },
                )
            ],
        )
        stop_at_end(lambda: _stop_wg(wg))
        # startup succeeded and the ssh listener came up fine despite the broken backend
        wait_port(wg.ssh_port, for_process=wg.process)

        url = f"https://localhost:{wg.http_port}"
        db_port = processes.start_postgres_server()

        with admin_client(url) as api:
            backends = api.get_secret_backends()
            assert backends[0].health == "error"

            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
            api.add_user_role(user.id, role.id)
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"postgres-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetPostgresOptions(
                            kind="Postgres",
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

    def test_config_reload_picks_up_new_backend(self, processes: ProcessManager, backend_engine, timeout, stop_at_end):
        vault: VaultInstance = processes.start_vault(engine=backend_engine)
        stop_at_end(lambda: _stop_vault(vault))
        vault.kv_put("secret", "myapp", password="hunter2")
        reference = f"{vault.backend_type}://vault-test/secret/myapp#password"

        # start with NO secrets.backends configured at all
        wg = processes.start_wg()
        stop_at_end(lambda: _stop_wg(wg))
        wait_port(wg.http_port, for_process=wg.process, recv=False)
        url = f"https://localhost:{wg.http_port}"

        with admin_client(url) as api:
            resp = api.test_secret_resolve(sdk.TestResolveRequest(reference=reference))
            assert resp.ok is False
            assert "not configured" in resp.error

        # edit warpgate.yaml on disk to add the backend while the process keeps running
        config = yaml.safe_load(wg.config_path.open())
        config.setdefault("secrets", {})["backends"] = [
            _vault_backend("vault-test", vault.addr, token=vault.root_token, backend_type=vault.backend_type)
        ]
        with wg.config_path.open("w") as f:
            yaml.safe_dump(config, f)

        def wait_reload():
            while True:
                with admin_client(url) as api:
                    resp = api.test_secret_resolve(sdk.TestResolveRequest(reference=reference))
                if resp.ok:
                    return
                time.sleep(0.2)

        _wait_timeout(
            wait_reload, "config reload did not pick up the new secret backend", timeout=timeout
        )

    def test_ssh_host_and_client_keys_stored_in_vault(self, processes: ProcessManager, backend_engine, timeout, stop_at_end):
        vault: VaultInstance = processes.start_vault(engine=backend_engine)
        stop_at_end(lambda: _stop_vault(vault))

        wg = _start_wg_with_backends(
            processes,
            [_vault_backend("vault-test", vault.addr, token=vault.root_token, backend_type=vault.backend_type)],
        )
        wait_port(wg.ssh_port, for_process=wg.process)

        # switch `ssh.keys` from its default disk path to the configured backend directly on
        # disk (a plain string -> mapping change, done by editing the YAML dict in place rather
        # than via config_patch) and reboot against the same data dir.
        wg.process.terminate()
        wg.process.wait()

        config = yaml.safe_load(wg.config_path.open())
        config["ssh"]["keys"] = {"backend": "vault-test", "path": "secret/warpgate-keys"}
        with wg.config_path.open("w") as f:
            yaml.safe_dump(config, f)

        wg1 = processes.start_wg(share_with=wg)
        wait_port(wg1.http_port, for_process=wg1.process, recv=False)
        wait_port(wg1.ssh_port, for_process=wg1.process)

        data, _version = vault.kv_get("secret", "warpgate-keys")
        for field in ["host-ed25519", "host-rsa", "client-ed25519", "client-rsa"]:
            assert field in data, f"{field} was not generated into Vault"
            assert "PRIVATE KEY" in data[field]

        # restart again against the same config; keys must be reused, not regenerated
        wg1.process.terminate()
        wg1.process.wait()

        wg2 = processes.start_wg(share_with=wg)
        stop_at_end(lambda: _stop_wg(wg2))
        wait_port(wg2.http_port, for_process=wg2.process, recv=False)
        wait_port(wg2.ssh_port, for_process=wg2.process)

        data_after, _version_after = vault.kv_get("secret", "warpgate-keys")
        for field in ["host-ed25519", "host-rsa", "client-ed25519", "client-rsa"]:
            assert data_after[field] == data[field], f"{field} was regenerated across restart"

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

        role_id_file = processes.ctx.tmpdir / f"vault-role-id-{uuid4()}"
        secret_id_file = processes.ctx.tmpdir / f"vault-secret-id-{uuid4()}"
        role_id_file.write_text(role_id)
        secret_id_file.write_text(secret_id)

        wg = _start_wg_with_backends(
            processes,
            [
                _vault_backend(
                    "vault-test",
                    vault.addr,
                    auth={
                        "method": "app_role",
                        "role_id_file": str(role_id_file),
                        "secret_id_file": str(secret_id_file),
                    },
                    backend_type=vault.backend_type,
                )
            ],
        )
        stop_at_end(lambda: _stop_wg(wg))
        url = f"https://localhost:{wg.http_port}"

        with admin_client(url) as api:
            resp = api.test_secret_resolve(
                sdk.TestResolveRequest(reference=f"{vault.backend_type}://vault-test/secret/myapp#password")
            )
            assert resp.ok is True, resp.error
