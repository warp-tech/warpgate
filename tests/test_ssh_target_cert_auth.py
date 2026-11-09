"""
SSH targets authenticated with an OpenSSH certificate that a secret backend's SSH
CA signs per connection, against a real dev-mode Vault.

Refusals are asserted on the gateway's own log: a failed target connection in
exec mode ends the session before the client reads the reason (#2548).
"""
import subprocess
import time
from uuid import uuid4

import pytest
import requests

from .api_client import admin_client, sdk
from .conftest import ProcessManager, VaultInstance, WarpgateProcess
from .test_ssh_proto import setup_user_and_target
from .test_web_ssh import _create_session
from .util import wait_port

MOUNT = "ssh"

BASE_ROLE = {
    "key_type": "ca",
    "allow_user_certificates": True,
    "allowed_users": "root",
    "allow_user_key_ids": True,
    "ttl": "2m",
    "max_ttl": "5m",
    "default_extensions": {"permit-pty": ""},
}


@pytest.fixture(scope="module")
def vault(processes: ProcessManager) -> VaultInstance:
    return processes.start_vault()


@pytest.fixture(scope="module")
def ca_key(vault: VaultInstance) -> str:
    key = vault.enable_ssh_ca(MOUNT)
    vault.write_ssh_role(MOUNT, "warpgate", **BASE_ROLE)
    vault.write_ssh_role(
        MOUNT,
        "forwarding",
        **{
            **BASE_ROLE,
            "default_extensions": {"permit-pty": "", "permit-port-forwarding": ""},
        },
    )
    vault.write_ssh_role(
        MOUNT,
        "forced",
        **{**BASE_ROLE, "default_critical_options": {"force-command": "/bin/echo forced"}},
    )
    vault.write_ssh_role(
        MOUNT, "no-ttl", **{k: v for k, v in BASE_ROLE.items() if k not in ("ttl", "max_ttl")}
    )
    return key


@pytest.fixture(scope="module")
def ssh_port(processes: ProcessManager, ca_key: str) -> int:
    port = processes.start_ssh_server(trusted_ca=[ca_key])
    wait_port(port)
    return port


def create_backend(wg: WarpgateProcess, vault: VaultInstance, allowed_paths=None) -> str:
    name = f"vault-{uuid4()}"
    with admin_client(f"https://localhost:{wg.http_port}") as api:
        api.create_secret_backend(
            sdk.SecretBackendRequest(
                name=name,
                backend_type="vault",
                address=vault.addr,
                auth=sdk.SecretBackendAuth(
                    sdk.SecretBackendAuthVaultTokenAuth(method="Token", token=vault.root_token)
                ),
                allowed_paths=allowed_paths or [],
            )
        )
    return name


@pytest.fixture(scope="module")
def backend(shared_wg: WarpgateProcess, vault: VaultInstance) -> str:
    return create_backend(shared_wg, vault)


def cert_auth(backend: str, role: str = "warpgate", **fields) -> sdk.SSHTargetAuth:
    return sdk.SSHTargetAuth(
        sdk.SSHTargetAuthSshTargetCertificateAuth(
            kind="Certificate", backend=backend, role=role, **fields
        )
    )


def sshd_log(processes: ProcessManager, port: int) -> str:
    r = subprocess.run(
        ["docker", "logs", processes.ssh_containers[port]],
        capture_output=True,
        text=True,
    )
    return r.stdout + r.stderr


def connect(processes: ProcessManager, wg: WarpgateProcess, user, target, timeout):
    client = processes.start_ssh_client(
        f"{user.username}:{target.name}@localhost",
        "-p",
        str(wg.ssh_port),
        "-o",
        "IdentityFile=ssh-keys/id_ed25519",
        "-o",
        "PreferredAuthentications=publickey",
        "ls",
        "/bin/sh",
    )
    stdout = client.communicate(timeout=timeout)[0]
    return client.returncode, stdout


def refusal(processes, wg, user, target, timeout) -> str:
    """Connects, expects a failure, returns what the gateway logged meanwhile."""
    offset = wg.log_path.stat().st_size
    code, stdout = connect(processes, wg, user, target, timeout)
    assert code != 0, stdout
    return wg.log_path.read_text()[offset:]


def behind_a_jump_host(processes, wg, pubkey, ssh_port, ca_key, backend):
    """A certificate target reached through a certificate jump host; returns
    the target's user, the target, and the jump host's target and port."""
    jump_port = processes.start_ssh_server(trusted_ca=[ca_key])
    wait_port(jump_port)
    _, jump = setup_user_and_target(
        processes, wg, pubkey, ssh_port=jump_port, auth=cert_auth(backend, role="forwarding")
    )
    user, target = setup_user_and_target(
        processes,
        wg,
        pubkey,
        ssh_port=ssh_port,
        host="host.docker.internal",
        jump_host=jump.id,
        auth=cert_auth(backend),
    )
    return user, target, jump, jump_port


class TestCertificateAuth:
    def test_connects_and_the_target_logs_the_key_id(
        self, processes, shared_wg, wg_c_ed25519_pubkey, ssh_port, backend, timeout
    ):
        user, target = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey, ssh_port=ssh_port, auth=cert_auth(backend)
        )
        code, stdout = connect(processes, shared_wg, user, target, timeout)
        assert code == 0, stdout
        assert stdout == b"/bin/sh\n"
        log = sshd_log(processes, ssh_port)
        assert f"ID warpgate:{user.username}:" in log
        assert "CA ED25519" in log

    def test_role_without_a_ttl(
        self, processes, shared_wg, wg_c_ed25519_pubkey, ssh_port, backend, timeout
    ):
        user, target = setup_user_and_target(
            processes,
            shared_wg,
            wg_c_ed25519_pubkey,
            ssh_port=ssh_port,
            auth=cert_auth(backend, role="no-ttl"),
        )
        code, stdout = connect(processes, shared_wg, user, target, timeout)
        assert code == 0, stdout

    def test_principal_outside_the_role_is_refused(
        self, processes, shared_wg, wg_c_ed25519_pubkey, ssh_port, backend, timeout
    ):
        user, target = setup_user_and_target(
            processes,
            shared_wg,
            wg_c_ed25519_pubkey,
            ssh_port=ssh_port,
            username="deploy",
            auth=cert_auth(backend),
        )
        logged = refusal(processes, shared_wg, user, target, timeout)
        assert "deploy is not a valid value for valid_principals" in logged

    def test_unknown_role_is_reported(
        self, processes, shared_wg, wg_c_ed25519_pubkey, ssh_port, backend, timeout
    ):
        user, target = setup_user_and_target(
            processes,
            shared_wg,
            wg_c_ed25519_pubkey,
            ssh_port=ssh_port,
            auth=cert_auth(backend, role="nope"),
        )
        logged = refusal(processes, shared_wg, user, target, timeout)
        assert "SshSigning" in logged and "nope" in logged

    def test_signing_is_gated_by_the_backends_allowed_paths(
        self, processes, shared_wg, vault, wg_c_ed25519_pubkey, ssh_port, timeout
    ):
        """A targets-only administrator can name any mount and role, so the
        backend's path list has to cover `mount/sign/role` as it covers KV."""
        kv_only = create_backend(shared_wg, vault, allowed_paths=["secret/app"])
        user, target = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey, ssh_port=ssh_port, auth=cert_auth(kv_only)
        )
        logged = refusal(processes, shared_wg, user, target, timeout)
        assert "PathNotAllowed" in logged and f"{MOUNT}/sign/warpgate" in logged

        this_role = create_backend(shared_wg, vault, allowed_paths=[f"{MOUNT}/sign/warpgate"])
        user, target = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey, ssh_port=ssh_port, auth=cert_auth(this_role)
        )
        code, stdout = connect(processes, shared_wg, user, target, timeout)
        assert code == 0, stdout
        assert stdout == b"/bin/sh\n"

    def test_unknown_backend_is_reported(
        self, processes, shared_wg, wg_c_ed25519_pubkey, ssh_port, backend, timeout
    ):
        user, target = setup_user_and_target(
            processes,
            shared_wg,
            wg_c_ed25519_pubkey,
            ssh_port=ssh_port,
            auth=cert_auth("nope"),
        )
        logged = refusal(processes, shared_wg, user, target, timeout)
        assert "BackendNotConfigured" in logged

    def test_forced_command_from_the_role_is_refused(
        self, processes, shared_wg, wg_c_ed25519_pubkey, ssh_port, backend, timeout
    ):
        user, target = setup_user_and_target(
            processes,
            shared_wg,
            wg_c_ed25519_pubkey,
            ssh_port=ssh_port,
            auth=cert_auth(backend, role="forced"),
        )
        logged = refusal(processes, shared_wg, user, target, timeout)
        assert "Refusing the issued certificate" in logged
        assert "force-command" in logged

    def test_host_key_check_issues_no_certificate(
        self, processes, shared_wg, wg_c_ed25519_pubkey, ssh_port, backend
    ):
        _, target = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey, ssh_port=ssh_port, auth=cert_auth(backend)
        )
        logins_before = sshd_log(processes, ssh_port).count("Accepted publickey")
        with admin_client(f"https://localhost:{shared_wg.http_port}") as api:
            result = api.check_ssh_host_key(sdk.CheckSshHostKeyRequest(target_id=target.id))
        assert result.remote_key_type == "ssh-ed25519"
        assert sshd_log(processes, ssh_port).count("Accepted publickey") == logins_before

    def test_session_through_a_jump_host(
        self, processes, shared_wg, wg_c_ed25519_pubkey, ssh_port, ca_key, backend, timeout
    ):
        user, target, _, jump_port = behind_a_jump_host(
            processes, shared_wg, wg_c_ed25519_pubkey, ssh_port, ca_key, backend
        )
        code, stdout = connect(processes, shared_wg, user, target, timeout)
        assert code == 0, stdout
        assert stdout == b"/bin/sh\n"
        assert f"ID warpgate:{user.username}:" in sshd_log(processes, jump_port)

    def test_host_key_check_through_a_jump_host_stops_at_the_target(
        self, processes, shared_wg, wg_c_ed25519_pubkey, ssh_port, ca_key, backend
    ):
        """The jump host has to be authenticated to reach the target, and its
        certificate names whoever ran the check; the target is never logged in to."""
        _, target, jump, jump_port = behind_a_jump_host(
            processes, shared_wg, wg_c_ed25519_pubkey, ssh_port, ca_key, backend
        )
        target_logins = sshd_log(processes, ssh_port).count("Accepted publickey")
        with admin_client(f"https://localhost:{shared_wg.http_port}") as api:
            # A jump host's key has to be trusted before anything behind it is
            # checked, the way an administrator would: check it, then trust it.
            jump_key = api.check_ssh_host_key(sdk.CheckSshHostKeyRequest(target_id=jump.id))
            api.add_ssh_known_host(
                sdk.AddSshKnownHostRequest(
                    host=jump.options.actual_instance.host,
                    port=jump_port,
                    key_type=jump_key.remote_key_type,
                    key_base64=jump_key.remote_key_base64,
                )
            )
            result = api.check_ssh_host_key(sdk.CheckSshHostKeyRequest(target_id=target.id))
        assert result.remote_key_type == "ssh-ed25519"
        assert sshd_log(processes, ssh_port).count("Accepted publickey") == target_logins
        assert "ID warpgate:admin-token:" in sshd_log(processes, jump_port)

    def test_web_client_failure_is_logged(
        self, processes, shared_wg, wg_c_ed25519_pubkey, ssh_port, backend, timeout
    ):
        """The browser is only told a sanitised reason, so the gateway log has
        to carry the real one. The session is reaped as soon as the connection
        fails, so the log is asserted rather than the stream."""
        user, target = setup_user_and_target(
            processes,
            shared_wg,
            wg_c_ed25519_pubkey,
            ssh_port=ssh_port,
            username="deploy",
            auth=cert_auth(backend),
        )
        url = f"https://localhost:{shared_wg.http_port}"
        http = requests.Session()
        http.verify = False
        resp = http.post(
            f"{url}/@warpgate/api/auth/login",
            json={"username": user.username, "password": "123"},
        )
        assert resp.status_code // 100 == 2

        offset = shared_wg.log_path.stat().st_size
        _create_session(url, http, target)
        deadline = time.time() + timeout
        while time.time() < deadline:
            logged = shared_wg.log_path.read_text()[offset:]
            if "deploy is not a valid value for valid_principals" in logged:
                return
            time.sleep(0.2)
        raise AssertionError(f"the refusal was not logged: {logged}")
