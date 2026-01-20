"""
E2E tests for SCP/SFTP file transfer access control.

Tests verify that file transfer permissions are enforced correctly:
- Upload permission controls SCP -t and SFTP write operations
- Download permission controls SCP -f and SFTP read operations
- Permissions are per role-target assignment
- Permissive model: any role granting access wins
"""

from uuid import uuid4
import subprocess
import tempfile
import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port


def setup_user_and_target(
    processes: ProcessManager,
    wg: WarpgateProcess,
    warpgate_client_key,
):
    """Set up a user, role, and SSH target for testing."""
    ssh_port = processes.start_ssh_server(
        trusted_keys=[warpgate_client_key.read_text()],
    )
    wait_port(ssh_port)

    url = f"https://localhost:{wg.http_port}"
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
                openssh_public_key=open("ssh-keys/id_ed25519.pub").read().strip(),
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
                            sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                        ),
                    )
                ),
            )
        )
        api.add_target_role(ssh_target.id, role.id)
        return user, ssh_target, role


def set_file_transfer_permission(
    wg: WarpgateProcess,
    target_id: str,
    role_id: str,
    allow_upload: bool,
    allow_download: bool,
    allowed_paths=None,
    blocked_extensions=None,
    max_file_size=None,
):
    """Set file transfer permissions for a target-role assignment."""
    url = f"https://localhost:{wg.http_port}"
    with admin_client(url) as api:
        return api.update_target_role_file_transfer_permission(
            target_id,
            role_id,
            sdk.FileTransferPermissionData(
                allow_file_upload=allow_upload,
                allow_file_download=allow_download,
                allowed_paths=allowed_paths,
                blocked_extensions=blocked_extensions,
                max_file_size=max_file_size,
            ),
        )


def get_file_transfer_permission(
    wg: WarpgateProcess,
    target_id: str,
    role_id: str,
):
    """Get file transfer permissions for a target-role assignment."""
    url = f"https://localhost:{wg.http_port}"
    with admin_client(url) as api:
        return api.get_target_role_file_transfer_permission(target_id, role_id)


class TestFileTransferPermissions:
    """Tests for SCP/SFTP access control."""

    def test_default_permissions_allow_transfer(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """By default, file transfers should be allowed (backward compat)."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Get default permissions
        perm = get_file_transfer_permission(shared_wg, ssh_target.id, role.id)

        # Default should allow both upload and download
        assert perm.allow_file_upload is True
        assert perm.allow_file_download is True

    def test_sftp_download_allowed(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """SFTP download should work when download permission is granted."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Ensure download is allowed
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=False,
            allow_download=True,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [
                    "sftp",
                    "-P",
                    str(shared_wg.ssh_port),
                    "-o",
                    f"User={user.username}:{ssh_target.name}",
                    "-o",
                    "IdentitiesOnly=yes",
                    "-o",
                    "IdentityFile=ssh-keys/id_ed25519",
                    "-o",
                    "PreferredAuthentications=publickey",
                    "-o",
                    "StrictHostKeychecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "localhost:/etc/passwd",
                    tmpdir,
                ],
                capture_output=True,
            )

            assert result.returncode == 0, (
                f"SFTP download failed: {result.stderr.decode()}"
            )
            assert "root:x:0:0:root" in open(f"{tmpdir}/passwd").read()

    def test_sftp_download_denied(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """SFTP should be denied when both upload and download are disabled."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Disable all file transfers
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=False,
            allow_download=False,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [
                    "sftp",
                    "-P",
                    str(shared_wg.ssh_port),
                    "-o",
                    f"User={user.username}:{ssh_target.name}",
                    "-o",
                    "IdentitiesOnly=yes",
                    "-o",
                    "IdentityFile=ssh-keys/id_ed25519",
                    "-o",
                    "PreferredAuthentications=publickey",
                    "-o",
                    "StrictHostKeychecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "localhost:/etc/passwd",
                    tmpdir,
                ],
                capture_output=True,
            )

            # Should fail because SFTP subsystem is denied
            assert result.returncode != 0, "SFTP should have been denied"

    def test_scp_download_allowed(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """SCP download should work when download permission is granted."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Ensure download is allowed
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=False,
            allow_download=True,
        )

        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            result = subprocess.run(
                [
                    "scp",
                    "-P",
                    str(shared_wg.ssh_port),
                    "-o",
                    f"User={user.username}:{ssh_target.name}",
                    "-o",
                    "IdentitiesOnly=yes",
                    "-o",
                    "IdentityFile=ssh-keys/id_ed25519",
                    "-o",
                    "PreferredAuthentications=publickey",
                    "-o",
                    "StrictHostKeychecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "localhost:/etc/passwd",
                    tmpfile.name,
                ],
                capture_output=True,
            )

            assert result.returncode == 0, (
                f"SCP download failed: {result.stderr.decode()}"
            )
            assert "root:x:0:0:root" in open(tmpfile.name).read()

    def test_sftp_download_blocked_when_upload_only(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """SFTP download should be blocked when only upload is permitted (fine-grained blocking)."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Only allow upload - download should be blocked at operation level
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=False,
        )

        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            result = subprocess.run(
                [
                    "scp",
                    "-P",
                    str(shared_wg.ssh_port),
                    "-o",
                    f"User={user.username}:{ssh_target.name}",
                    "-o",
                    "IdentitiesOnly=yes",
                    "-o",
                    "IdentityFile=ssh-keys/id_ed25519",
                    "-o",
                    "PreferredAuthentications=publickey",
                    "-o",
                    "StrictHostKeychecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "localhost:/etc/passwd",
                    tmpfile.name,
                ],
                capture_output=True,
            )

            # Fine-grained blocking: SFTP subsystem allowed but read operations blocked
            assert result.returncode != 0, (
                "Download should be blocked when only upload is permitted"
            )

    def test_scp_upload_allowed(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """SCP upload should work when upload permission is granted."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Ensure upload is allowed
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=False,
        )

        with tempfile.NamedTemporaryFile(delete=False, mode="w") as tmpfile:
            tmpfile.write("test content")
            tmpfile.flush()

            result = subprocess.run(
                [
                    "scp",
                    "-P",
                    str(shared_wg.ssh_port),
                    "-o",
                    f"User={user.username}:{ssh_target.name}",
                    "-o",
                    "IdentitiesOnly=yes",
                    "-o",
                    "IdentityFile=ssh-keys/id_ed25519",
                    "-o",
                    "PreferredAuthentications=publickey",
                    "-o",
                    "StrictHostKeychecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    tmpfile.name,
                    "localhost:/tmp/",
                ],
                capture_output=True,
            )

            assert result.returncode == 0, (
                f"SCP upload failed: {result.stderr.decode()}"
            )

    def test_sftp_upload_blocked_when_download_only(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """SFTP upload should be blocked when only download is permitted (fine-grained blocking)."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Only allow download - upload should be blocked at operation level
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=False,
            allow_download=True,
        )

        with tempfile.NamedTemporaryFile(delete=False, mode="w") as tmpfile:
            tmpfile.write("test content")
            tmpfile.flush()

            result = subprocess.run(
                [
                    "scp",
                    "-P",
                    str(shared_wg.ssh_port),
                    "-o",
                    f"User={user.username}:{ssh_target.name}",
                    "-o",
                    "IdentitiesOnly=yes",
                    "-o",
                    "IdentityFile=ssh-keys/id_ed25519",
                    "-o",
                    "PreferredAuthentications=publickey",
                    "-o",
                    "StrictHostKeychecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    tmpfile.name,
                    "localhost:/tmp/",
                ],
                capture_output=True,
            )

            # Fine-grained blocking: SFTP subsystem allowed but write operations blocked
            assert result.returncode != 0, (
                "Upload should be blocked when only download is permitted"
            )

    def test_api_get_file_transfer_permission(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """Test GET endpoint for file transfer permissions."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        perm = get_file_transfer_permission(shared_wg, ssh_target.id, role.id)

        assert hasattr(perm, "allow_file_upload")
        assert hasattr(perm, "allow_file_download")
        assert hasattr(perm, "allowed_paths")
        assert hasattr(perm, "blocked_extensions")
        assert hasattr(perm, "max_file_size")

    def test_api_update_file_transfer_permission(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """Test PUT endpoint for file transfer permissions."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Update permissions
        updated = set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=False,
            allow_download=True,
            allowed_paths=["/home/*", "/tmp/*"],
            blocked_extensions=[".exe", ".dll"],
            max_file_size=1024 * 1024,  # 1MB
        )

        assert updated.allow_file_upload is False
        assert updated.allow_file_download is True
        assert updated.allowed_paths == ["/home/*", "/tmp/*"]
        assert updated.blocked_extensions == [".exe", ".dll"]
        assert updated.max_file_size == 1024 * 1024

        # Verify the update persisted
        perm = get_file_transfer_permission(shared_wg, ssh_target.id, role.id)
        assert perm.allow_file_upload is False
        assert perm.allow_file_download is True
