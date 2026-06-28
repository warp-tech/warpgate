"""
E2E coverage for the ``active_web_session_ttl_seconds`` SSO option that lets
an SSH ``WebUserApproval`` prompt be auto-satisfied when the same user already
holds a fresh browser session (from the same IP).
"""

import subprocess
import time
from pathlib import Path
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .test_http_user_auth_oidc import (
    _do_oidc_login,
    _make_sso_provider_config,
)
from .util import alloc_port, wait_port


OIDC_EMAIL = "sam.tailor@gmail.com"


def _start_wg(processes, wg_http_port, oidc_port, *, ttl_seconds):
    """Start warpgate with an SSO provider, optionally enabling the fast-path."""
    sso_config = _make_sso_provider_config(oidc_port)
    if ttl_seconds is not None:
        sso_config["active_web_session_ttl_seconds"] = ttl_seconds
    wg = processes.start_wg(
        http_port=wg_http_port,
        config_patch={
            "sso_providers": [sso_config],
            "external_host": "127.0.0.1",
        },
    )
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    wait_port(wg.ssh_port, for_process=wg.process)
    return wg


def _provision(api, ssh_port, username):
    role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
    user = api.create_user(sdk.CreateUserRequest(username=username))
    api.create_sso_credential(
        user.id,
        sdk.NewSsoCredential(email=OIDC_EMAIL, provider="test-oidc"),
    )
    api.add_user_role(user.id, role.id)
    api.update_user(
        user.id,
        sdk.UserDataRequest(
            username=user.username,
            credential_policy=sdk.UserRequireCredentialsPolicy(
                ssh=[sdk.CredentialKind.WEBUSERAPPROVAL],
            ),
        ),
    )
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
                        sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                    ),
                )
            ),
        )
    )
    api.add_target_role(target.id, role.id)
    return user, target


def _start_ssh(processes, wg, user, target):
    """Spawn an ssh client targeting wg, letting the client negotiate methods.

    The user is provisioned with the ``WebUserApproval``-only credential
    policy, so the client will fall through publickey/password and end up on
    keyboard-interactive, where the fast-path (or the standard prompt) is
    served.

    Connects via ``127.0.0.1`` (not ``localhost``) so that the SSH peer's
    address matches the IPv4 address the HTTP login was recorded against.
    """
    return processes.start_ssh_client(
        f"{user.username}:{target.name}@127.0.0.1",
        "-p",
        str(wg.ssh_port),
        "-o",
        "IdentityFile=ssh-keys/id_ed25519",
        "ls",
        "/bin/sh",
    )


def _wait_for_pending(session, wg_url, attempts=40, delay=0.25):
    """Poll the WebUserApproval pending-requests endpoint until non-empty."""
    for _ in range(attempts):
        resp = session.get(f"{wg_url}/@warpgate/api/auth/web-auth-requests")
        if resp.status_code == 200:
            pending = resp.json()
            if pending:
                return pending
        time.sleep(delay)
    return []


class TestSshWebSessionFastPath:
    def test_ssh_skipped_when_provider_ttl_set(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
    ):
        """SSO web login should auto-satisfy the SSH WebUserApproval prompt."""
        target_ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(target_ssh_port)

        wg_http_port = alloc_port()
        oidc_port = processes.start_oidc_server(wg_http_port)
        wg = _start_wg(processes, wg_http_port, oidc_port, ttl_seconds=300)
        wg_url = f"https://127.0.0.1:{wg.http_port}"

        with admin_client(wg_url) as api:
            user, ssh_target = _provision(api, target_ssh_port, "sam_tailor")

        # Drive the OIDC flow; this `touch`es active_web_sessions for the user.
        _, resp = _do_oidc_login(wg_url, oidc_port)
        assert resp.status_code in (302, 307)

        ssh_client = _start_ssh(processes, wg, user, ssh_target)

        # No prompt expected: SSH should connect and run `ls /bin/sh` directly.
        stdout, _ = ssh_client.communicate(timeout=timeout)
        assert ssh_client.returncode == 0, stdout
        assert stdout == b"/bin/sh\n"

    def test_ssh_still_prompts_when_provider_ttl_absent(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
    ):
        """Without the new option, every SSH session must still request approval."""
        target_ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(target_ssh_port)

        wg_http_port = alloc_port()
        oidc_port = processes.start_oidc_server(wg_http_port)
        wg = _start_wg(processes, wg_http_port, oidc_port, ttl_seconds=None)
        wg_url = f"https://127.0.0.1:{wg.http_port}"

        with admin_client(wg_url) as api:
            user, ssh_target = _provision(api, target_ssh_port, "sam_tailor")

        wg_session, resp = _do_oidc_login(wg_url, oidc_port)
        assert resp.status_code in (302, 307)

        ssh_client = _start_ssh(processes, wg, user, ssh_target)

        # SSH should be sitting on a WebUserApproval prompt. Confirm by polling
        # the authenticated `web-auth-requests` endpoint.
        pending = _wait_for_pending(wg_session, wg_url)
        assert pending, "expected at least one pending WebUserApproval"

        approve = wg_session.post(
            f"{wg_url}/@warpgate/api/auth/state/{pending[0]['id']}/approve"
        )
        assert approve.status_code == 200

        # Release the "Press Enter when done" prompt and finish the SSH command.
        ssh_client.stdin.write(b"\r\n")
        ssh_client.stdin.flush()
        stdout, _ = ssh_client.communicate(timeout=timeout)
        assert ssh_client.returncode == 0, stdout
        assert stdout == b"/bin/sh\n"

    def test_logout_clears_fastpath(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
    ):
        """After /auth/logout the in-memory entry must be forgotten.

        We do not re-login (that would simply re-register the fast-path); we
        only verify that the SSH attempt blocks waiting on browser approval
        instead of being auto-accepted.
        """
        target_ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(target_ssh_port)

        wg_http_port = alloc_port()
        oidc_port = processes.start_oidc_server(wg_http_port)
        wg = _start_wg(processes, wg_http_port, oidc_port, ttl_seconds=300)
        wg_url = f"https://127.0.0.1:{wg.http_port}"

        with admin_client(wg_url) as api:
            user, ssh_target = _provision(api, target_ssh_port, "sam_tailor")

        wg_session, resp = _do_oidc_login(wg_url, oidc_port)
        assert resp.status_code in (302, 307)

        # Sanity check: the fresh login enables the fast-path.
        ssh_pre = _start_ssh(processes, wg, user, ssh_target)
        stdout_pre, _ = ssh_pre.communicate(timeout=timeout)
        assert ssh_pre.returncode == 0, stdout_pre

        # After logout the in-memory entry must be cleared.
        logout = wg_session.post(f"{wg_url}/@warpgate/api/auth/logout")
        assert logout.status_code in (200, 201, 204), logout.text

        ssh_client = _start_ssh(processes, wg, user, ssh_target)

        # SSH must NOT auto-accept; it should be blocked on the keyboard-
        # interactive "Press Enter when done" prompt. We don't approve it --
        # we just verify it is still running after a brief grace period and
        # then terminate it.
        time.sleep(2)
        assert ssh_client.poll() is None, (
            "ssh exited without WebUserApproval; "
            "fast-path likely fired after logout"
        )

        ssh_client.terminate()
        try:
            ssh_client.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            ssh_client.kill()
            ssh_client.communicate(timeout=5)
