"""
Tests for SSH client authentication method configuration via Parameters API.

These tests verify that SSH auth methods can be configured via the Parameters API
and that the configuration actually affects SSH authentication behavior.
"""
import time
from pathlib import Path
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port


class TestSSHClientAuthConfigAPI:
    """Test SSH client authentication method configuration via API."""

    def test_get_ssh_auth_parameters(
        self,
        shared_wg: WarpgateProcess,
    ):
        """Test that SSH auth parameters are returned by the API."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            params = api.get_parameters()
            # Verify the new SSH auth fields exist and default to True
            assert hasattr(params, 'ssh_client_auth_publickey')
            assert hasattr(params, 'ssh_client_auth_password')
            assert hasattr(params, 'ssh_client_auth_keyboard_interactive')
            # Default values should be True
            assert params.ssh_client_auth_publickey is True
            assert params.ssh_client_auth_password is True
            assert params.ssh_client_auth_keyboard_interactive is True

    def test_update_ssh_auth_parameters(
        self,
        shared_wg: WarpgateProcess,
    ):
        """Test that SSH auth parameters can be updated via the API."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            # Get current parameters
            params = api.get_parameters()

            # Update to disable password auth
            api.update_parameters(sdk.ParameterUpdate(
                allow_own_credential_management=params.allow_own_credential_management,
                rate_limit_bytes_per_second=params.rate_limit_bytes_per_second,
                ssh_client_auth_publickey=True,
                ssh_client_auth_password=False,
                ssh_client_auth_keyboard_interactive=True,
            ))

            # Verify the update
            updated_params = api.get_parameters()
            assert updated_params.ssh_client_auth_password is False
            assert updated_params.ssh_client_auth_publickey is True

            # Restore original settings
            api.update_parameters(sdk.ParameterUpdate(
                allow_own_credential_management=params.allow_own_credential_management,
                rate_limit_bytes_per_second=params.rate_limit_bytes_per_second,
                ssh_client_auth_publickey=True,
                ssh_client_auth_password=True,
                ssh_client_auth_keyboard_interactive=True,
            ))


class TestSSHClientAuthConfigE2E:
    """E2E tests verifying SSH auth methods are actually enforced."""

    def _start_ssh_server(self, processes, wg_c_ed25519_pubkey):
        """Start SSH server with delay for Docker port forwarding."""
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        # Give Docker time to set up port forwarding
        time.sleep(3)
        wait_port(ssh_port)
        return ssh_port

    def _setup_user_and_target(self, api, ssh_port, wg_c_ed25519_pubkey: Path):
        """Helper to create user, credentials, and target."""
        role = api.create_role(
            sdk.RoleDataRequest(name=f"role-{uuid4()}"),
        )
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        # Add password credential
        api.create_password_credential(
            user.id, sdk.NewPasswordCredential(password="testpass123")
        )
        # Add pubkey credential
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
        return user, ssh_target

    def _update_ssh_auth_params(self, api, pubkey=True, password=True, keyboard_interactive=True):
        """Helper to update SSH auth parameters."""
        params = api.get_parameters()
        api.update_parameters(sdk.ParameterUpdate(
            allow_own_credential_management=params.allow_own_credential_management,
            rate_limit_bytes_per_second=params.rate_limit_bytes_per_second,
            ssh_client_auth_publickey=pubkey,
            ssh_client_auth_password=password,
            ssh_client_auth_keyboard_interactive=keyboard_interactive,
        ))

    def test_password_auth_disabled(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        """Test that disabling password auth blocks password-based SSH login."""
        ssh_port = self._start_ssh_server(processes, wg_c_ed25519_pubkey)

        wg = processes.start_wg()
        wait_port(wg.http_port, for_process=wg.process, recv=False)
        wait_port(wg.ssh_port, for_process=wg.process)

        url = f"https://localhost:{wg.http_port}"
        with admin_client(url) as api:
            user, ssh_target = self._setup_user_and_target(api, ssh_port, wg_c_ed25519_pubkey)
            self._update_ssh_auth_params(api, pubkey=True, password=False, keyboard_interactive=False)

        wg.process.terminate()
        wg.process.wait()

        wg2 = processes.start_wg(share_with=wg)
        wait_port(wg2.http_port, for_process=wg2.process, recv=False)
        wait_port(wg2.ssh_port, for_process=wg2.process)

        # Try password auth - should fail
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p", str(wg2.ssh_port),
            "-i", "/dev/null",
            "-o", "PreferredAuthentications=password",
            "-o", "NumberOfPasswordPrompts=1",
            "ls", "/bin/sh",
            password="testpass123",
        )
        ssh_client.communicate(timeout=timeout)
        assert ssh_client.returncode != 0

    def test_pubkey_auth_disabled(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        """Test that disabling pubkey auth blocks pubkey-based SSH login."""
        ssh_port = self._start_ssh_server(processes, wg_c_ed25519_pubkey)

        wg = processes.start_wg()
        wait_port(wg.http_port, for_process=wg.process, recv=False)
        wait_port(wg.ssh_port, for_process=wg.process)

        url = f"https://localhost:{wg.http_port}"
        with admin_client(url) as api:
            user, ssh_target = self._setup_user_and_target(api, ssh_port, wg_c_ed25519_pubkey)
            self._update_ssh_auth_params(api, pubkey=False, password=True, keyboard_interactive=False)

        wg.process.terminate()
        wg.process.wait()

        wg2 = processes.start_wg(share_with=wg)
        wait_port(wg2.http_port, for_process=wg2.process, recv=False)
        wait_port(wg2.ssh_port, for_process=wg2.process)

        # Try pubkey auth - should fail
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p", str(wg2.ssh_port),
            "-o", "IdentityFile=ssh-keys/id_ed25519",
            "-o", "PreferredAuthentications=publickey",
            "ls", "/bin/sh",
        )
        ssh_client.communicate(timeout=timeout)
        assert ssh_client.returncode != 0

    def test_pubkey_auth_enabled_works(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        """Test that pubkey auth works when enabled."""
        ssh_port = self._start_ssh_server(processes, wg_c_ed25519_pubkey)

        wg = processes.start_wg()
        wait_port(wg.http_port, for_process=wg.process, recv=False)
        wait_port(wg.ssh_port, for_process=wg.process)

        url = f"https://localhost:{wg.http_port}"
        with admin_client(url) as api:
            user, ssh_target = self._setup_user_and_target(api, ssh_port, wg_c_ed25519_pubkey)
            self._update_ssh_auth_params(api, pubkey=True, password=False, keyboard_interactive=False)

        wg.process.terminate()
        wg.process.wait()

        wg2 = processes.start_wg(share_with=wg)
        wait_port(wg2.http_port, for_process=wg2.process, recv=False)
        wait_port(wg2.ssh_port, for_process=wg2.process)

        # Try pubkey auth - should succeed
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p", str(wg2.ssh_port),
            "-o", "IdentityFile=ssh-keys/id_ed25519",
            "-o", "PreferredAuthentications=publickey",
            "ls", "/bin/sh",
        )
        output, _ = ssh_client.communicate(timeout=timeout)
        assert output == b"/bin/sh\n"
        assert ssh_client.returncode == 0

    def test_password_auth_enabled_works(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        """Test that password auth works when enabled."""
        ssh_port = self._start_ssh_server(processes, wg_c_ed25519_pubkey)

        wg = processes.start_wg()
        wait_port(wg.http_port, for_process=wg.process, recv=False)
        wait_port(wg.ssh_port, for_process=wg.process)

        url = f"https://localhost:{wg.http_port}"
        with admin_client(url) as api:
            user, ssh_target = self._setup_user_and_target(api, ssh_port, wg_c_ed25519_pubkey)
            self._update_ssh_auth_params(api, pubkey=False, password=True, keyboard_interactive=False)

        wg.process.terminate()
        wg.process.wait()

        wg2 = processes.start_wg(share_with=wg)
        wait_port(wg2.http_port, for_process=wg2.process, recv=False)
        wait_port(wg2.ssh_port, for_process=wg2.process)

        # Try password auth - should succeed
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p", str(wg2.ssh_port),
            "-i", "/dev/null",
            "-o", "PreferredAuthentications=password",
            "ls", "/bin/sh",
            password="testpass123",
        )
        output, _ = ssh_client.communicate(timeout=timeout)
        assert output == b"/bin/sh\n"
        assert ssh_client.returncode == 0

    def test_both_auth_methods_work(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        """Test both pubkey and password work when both enabled."""
        ssh_port = self._start_ssh_server(processes, wg_c_ed25519_pubkey)

        wg = processes.start_wg()
        wait_port(wg.http_port, for_process=wg.process, recv=False)
        wait_port(wg.ssh_port, for_process=wg.process)

        url = f"https://localhost:{wg.http_port}"
        with admin_client(url) as api:
            user, ssh_target = self._setup_user_and_target(api, ssh_port, wg_c_ed25519_pubkey)
            self._update_ssh_auth_params(api, pubkey=True, password=True, keyboard_interactive=False)

        wg.process.terminate()
        wg.process.wait()

        wg2 = processes.start_wg(share_with=wg)
        wait_port(wg2.http_port, for_process=wg2.process, recv=False)
        wait_port(wg2.ssh_port, for_process=wg2.process)

        # Pubkey should work
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p", str(wg2.ssh_port),
            "-o", "IdentityFile=ssh-keys/id_ed25519",
            "-o", "PreferredAuthentications=publickey",
            "ls", "/bin/sh",
        )
        output, _ = ssh_client.communicate(timeout=timeout)
        assert output == b"/bin/sh\n"
        assert ssh_client.returncode == 0

        # Password should also work
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p", str(wg2.ssh_port),
            "-i", "/dev/null",
            "-o", "PreferredAuthentications=password",
            "ls", "/bin/sh",
            password="testpass123",
        )
        output, _ = ssh_client.communicate(timeout=timeout)
        assert output == b"/bin/sh\n"
        assert ssh_client.returncode == 0

    def test_all_disabled_fallback(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        """Test that when all methods disabled, fallback enables all."""
        ssh_port = self._start_ssh_server(processes, wg_c_ed25519_pubkey)

        wg = processes.start_wg()
        wait_port(wg.http_port, for_process=wg.process, recv=False)
        wait_port(wg.ssh_port, for_process=wg.process)

        url = f"https://localhost:{wg.http_port}"
        with admin_client(url) as api:
            user, ssh_target = self._setup_user_and_target(api, ssh_port, wg_c_ed25519_pubkey)
            # Disable ALL - should trigger fallback
            self._update_ssh_auth_params(api, pubkey=False, password=False, keyboard_interactive=False)

        wg.process.terminate()
        wg.process.wait()

        wg2 = processes.start_wg(share_with=wg)
        wait_port(wg2.http_port, for_process=wg2.process, recv=False)
        wait_port(wg2.ssh_port, for_process=wg2.process)

        # Both should work due to fallback
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p", str(wg2.ssh_port),
            "-o", "IdentityFile=ssh-keys/id_ed25519",
            "-o", "PreferredAuthentications=publickey",
            "ls", "/bin/sh",
        )
        output, _ = ssh_client.communicate(timeout=timeout)
        assert output == b"/bin/sh\n"
        assert ssh_client.returncode == 0

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p", str(wg2.ssh_port),
            "-i", "/dev/null",
            "-o", "PreferredAuthentications=password",
            "ls", "/bin/sh",
            password="testpass123",
        )
        output, _ = ssh_client.communicate(timeout=timeout)
        assert output == b"/bin/sh\n"
        assert ssh_client.returncode == 0
