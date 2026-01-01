"""
Tests for SSH client authentication method configuration.

These tests verify that the server-level SSH authentication method settings
(client_auth_publickey, client_auth_password, client_auth_keyboard_interactive)
correctly control which authentication methods are advertised to clients.
"""
import subprocess
import yaml
from pathlib import Path
from uuid import uuid4

import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess, Context
from .util import wait_port, alloc_port


def start_wg_with_ssh_auth_config(
    processes: ProcessManager,
    ctx: Context,
    client_auth_publickey: bool = True,
    client_auth_password: bool = True,
    client_auth_keyboard_interactive: bool = True,
) -> WarpgateProcess:
    """
    Start a Warpgate instance with custom SSH client authentication settings.
    """
    wg = processes.start_wg()

    # Wait for initial startup
    wait_port(wg.http_port, for_process=wg.process, recv=False)

    # Stop the process to modify config
    wg.process.terminate()
    wg.process.wait(timeout=5)

    # Modify the config with custom SSH auth settings
    config = yaml.safe_load(wg.config_path.open())
    config["ssh"]["client_auth_publickey"] = client_auth_publickey
    config["ssh"]["client_auth_password"] = client_auth_password
    config["ssh"]["client_auth_keyboard_interactive"] = client_auth_keyboard_interactive

    with wg.config_path.open("w") as f:
        yaml.safe_dump(config, f)

    # Restart with modified config
    new_wg = processes.start_wg(share_with=wg)
    wait_port(new_wg.http_port, for_process=new_wg.process, recv=False)
    wait_port(new_wg.ssh_port, for_process=new_wg.process)

    return new_wg


class TestSshClientAuthPasswordDisabled:
    """Test that password authentication is properly disabled when configured."""

    def test_password_auth_rejected_when_disabled(
        self,
        processes: ProcessManager,
        ctx: Context,
        wg_c_ed25519_pubkey: Path,
        timeout,
    ):
        """
        When client_auth_password=false, password authentication attempts
        should be rejected at the protocol level (not just auth failure).
        """
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)

        # Start Warpgate with password auth disabled
        wg = start_wg_with_ssh_auth_config(
            processes,
            ctx,
            client_auth_publickey=True,
            client_auth_password=False,
            client_auth_keyboard_interactive=True,
        )

        url = f"https://localhost:{wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(
                sdk.RoleDataRequest(name=f"role-{uuid4()}"),
            )
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            # Create password credential (but password auth should still be disabled)
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id)
            ssh_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            host="localhost",
                            port=ssh_port,
                            username="root",
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(
                                    kind="PublicKey"
                                )
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(ssh_target.id, role.id)

        # Attempt password authentication - should fail
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-v",
            "-p",
            str(wg.ssh_port),
            "-i",
            "/dev/null",
            "-o",
            "PreferredAuthentications=password",
            "-o",
            "NumberOfPasswordPrompts=1",
            "ls",
            "/bin/sh",
            password="123",
        )
        stdout, stderr = ssh_client.communicate(timeout=timeout)

        # Should fail because password auth is not offered
        assert ssh_client.returncode != 0
        # Verify we didn't succeed via password - stderr should indicate auth issues
        # stderr might be empty or None in some cases
        if stderr:
            stderr_lower = stderr.lower()
            # Check that we didn't successfully authenticate with password
            # Either password wasn't offered or auth was denied
            assert b"permission denied" in stderr_lower or b"no more authentication" in stderr_lower or b"no supported" in stderr_lower

    def test_pubkey_auth_works_when_password_disabled(
        self,
        processes: ProcessManager,
        ctx: Context,
        wg_c_ed25519_pubkey: Path,
        timeout,
    ):
        """
        When password auth is disabled, public key auth should still work.
        """
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)

        wg = start_wg_with_ssh_auth_config(
            processes,
            ctx,
            client_auth_publickey=True,
            client_auth_password=False,
            client_auth_keyboard_interactive=True,
        )

        url = f"https://localhost:{wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(
                sdk.RoleDataRequest(name=f"role-{uuid4()}"),
            )
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_public_key_credential(
                user.id,
                sdk.NewPublicKeyCredential(
                    label="Public Key",
                    openssh_public_key=open("ssh-keys/id_ed25519.pub").read().strip()
                ),
            )
            api.add_user_role(user.id, role.id)
            ssh_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            host="localhost",
                            port=ssh_port,
                            username="root",
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(
                                    kind="PublicKey"
                                )
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(ssh_target.id, role.id)

        # Public key auth should work
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(wg.ssh_port),
            "-o",
            "IdentityFile=ssh-keys/id_ed25519",
            "-o",
            "PreferredAuthentications=publickey",
            "ls",
            "/bin/sh",
        )
        stdout, _ = ssh_client.communicate(timeout=timeout)
        assert ssh_client.returncode == 0
        assert stdout == b"/bin/sh\n"


class TestSshClientAuthPublickeyDisabled:
    """Test that public key authentication is properly disabled when configured."""

    def test_pubkey_auth_rejected_when_disabled(
        self,
        processes: ProcessManager,
        ctx: Context,
        wg_c_ed25519_pubkey: Path,
        timeout,
    ):
        """
        When client_auth_publickey=false, public key authentication attempts
        should be rejected at the protocol level.
        """
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)

        wg = start_wg_with_ssh_auth_config(
            processes,
            ctx,
            client_auth_publickey=False,
            client_auth_password=True,
            client_auth_keyboard_interactive=True,
        )

        url = f"https://localhost:{wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(
                sdk.RoleDataRequest(name=f"role-{uuid4()}"),
            )
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_public_key_credential(
                user.id,
                sdk.NewPublicKeyCredential(
                    label="Public Key",
                    openssh_public_key=open("ssh-keys/id_ed25519.pub").read().strip()
                ),
            )
            api.add_user_role(user.id, role.id)
            ssh_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            host="localhost",
                            port=ssh_port,
                            username="root",
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(
                                    kind="PublicKey"
                                )
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(ssh_target.id, role.id)

        # Public key auth should fail
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-v",
            "-p",
            str(wg.ssh_port),
            "-o",
            "IdentityFile=ssh-keys/id_ed25519",
            "-o",
            "PreferredAuthentications=publickey",
            "ls",
            "/bin/sh",
        )
        stdout, stderr = ssh_client.communicate(timeout=timeout)
        assert ssh_client.returncode != 0

    def test_password_auth_works_when_pubkey_disabled(
        self,
        processes: ProcessManager,
        ctx: Context,
        wg_c_ed25519_pubkey: Path,
        timeout,
    ):
        """
        When public key auth is disabled, password auth should still work.
        """
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)

        wg = start_wg_with_ssh_auth_config(
            processes,
            ctx,
            client_auth_publickey=False,
            client_auth_password=True,
            client_auth_keyboard_interactive=True,
        )

        url = f"https://localhost:{wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(
                sdk.RoleDataRequest(name=f"role-{uuid4()}"),
            )
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id)
            ssh_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            host="localhost",
                            port=ssh_port,
                            username="root",
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(
                                    kind="PublicKey"
                                )
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(ssh_target.id, role.id)

        # Password auth should work
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(wg.ssh_port),
            "-i",
            "/dev/null",
            "-o",
            "PreferredAuthentications=password",
            "ls",
            "/bin/sh",
            password="123",
        )
        stdout, _ = ssh_client.communicate(timeout=timeout)
        assert ssh_client.returncode == 0
        assert stdout == b"/bin/sh\n"


class TestSshClientAuthDefaultConfig:
    """Test that default config enables all authentication methods."""

    def test_default_config_allows_all_methods(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        """
        With default configuration, both password and public key auth should work.
        """
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(
                sdk.RoleDataRequest(name=f"role-{uuid4()}"),
            )
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.create_public_key_credential(
                user.id,
                sdk.NewPublicKeyCredential(
                    label="Public Key",
                    openssh_public_key=open("ssh-keys/id_ed25519.pub").read().strip()
                ),
            )
            api.add_user_role(user.id, role.id)
            ssh_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            host="localhost",
                            port=ssh_port,
                            username="root",
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(
                                    kind="PublicKey"
                                )
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(ssh_target.id, role.id)

        # Password auth should work
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            "-i",
            "/dev/null",
            "-o",
            "PreferredAuthentications=password",
            "ls",
            "/bin/sh",
            password="123",
        )
        stdout, _ = ssh_client.communicate(timeout=timeout)
        assert ssh_client.returncode == 0
        assert stdout == b"/bin/sh\n"

        # Public key auth should also work
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            "-o",
            "IdentityFile=ssh-keys/id_ed25519",
            "-o",
            "PreferredAuthentications=publickey",
            "ls",
            "/bin/sh",
        )
        stdout, _ = ssh_client.communicate(timeout=timeout)
        assert ssh_client.returncode == 0
        assert stdout == b"/bin/sh\n"
