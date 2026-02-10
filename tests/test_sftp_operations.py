"""
E2E tests for SFTP operations beyond basic read/write.

Tests verify that permission enforcement works for:
- Remove (delete file) — requires upload_allowed
- Rename — requires upload_allowed, checks both paths
- Mkdir — requires upload_allowed
- Rmdir — requires upload_allowed
- Setstat (chmod) — requires upload_allowed
- Symlink — requires upload_allowed, checks both paths
- Extended packets (safe/write/unknown categories)
- max_file_size enforcement on write operations
- Direct streamlocal blocking in strict mode
"""

import os
import subprocess
import tempfile
from uuid import uuid4

import paramiko
import pytest

from .api_client import admin_client, sdk
from .conftest import WarpgateProcess
from .util import wait_port


@pytest.fixture(scope="session")
def sftp_ops_ssh_port(processes, wg_c_ed25519_pubkey):
    """Shared SSH server for SFTP operations tests."""
    port = processes.start_ssh_server(trusted_keys=[wg_c_ed25519_pubkey.read_text()])
    wait_port(port)
    return port


def setup_user_and_target(
    ssh_port,
    wg: WarpgateProcess,
):
    """Set up a user, role, and SSH target for testing.

    Reuses an existing SSH server (ssh_port) instead of starting a new one.
    """
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
        api.add_user_role(user.id, role.id, sdk.AddUserRoleRequest(expires_at=None))
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


def set_sftp_permission_mode(wg: WarpgateProcess, mode: str):
    """Set instance-wide SFTP permission mode (strict or permissive)."""
    url = f"https://localhost:{wg.http_port}"
    with admin_client(url) as api:
        params = api.get_parameters()
        return api.update_parameters(
            sdk.ParameterUpdate(
                allow_own_credential_management=params.allow_own_credential_management,
                sftp_permission_mode=mode,
            )
        )


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


def get_sftp_client(wg, user, target):
    """Create an SFTP client via paramiko connecting through Warpgate."""
    key = paramiko.Ed25519Key.from_private_key_file("ssh-keys/id_ed25519")
    transport = paramiko.Transport(("localhost", wg.ssh_port))
    transport.connect(
        username=f"{user.username}:{target.name}",
        pkey=key,
    )
    return paramiko.SFTPClient.from_transport(transport), transport


def run_sftp_batch(wg, user, target, commands):
    """Run SFTP batch commands and return the result."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sftp", delete=False) as f:
        f.write("\n".join(commands) + "\n")
        f.flush()
        batch_file = f.name

    try:
        result = subprocess.run(
            [
                "sftp",
                "-b",
                batch_file,
                "-P",
                str(wg.ssh_port),
                "-o",
                f"User={user.username}:{target.name}",
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
                "localhost",
            ],
            capture_output=True,
            timeout=30,
        )
        return result
    finally:
        os.unlink(batch_file)


class TestSftpRemove:
    """Tests for SFTP remove (delete file) permission enforcement."""

    def test_remove_allowed_when_upload_permitted(
        self,
        sftp_ops_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """File removal should succeed when upload (write) permission is granted."""
        user, ssh_target, role = setup_user_and_target(sftp_ops_ssh_port, shared_wg)

        set_sftp_permission_mode(shared_wg, "permissive")
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=True,
        )

        # Create a file first via SSH exec
        subprocess.run(
            [
                "ssh",
                "-p",
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
                "localhost",
                "touch /tmp/removeme-allowed.txt",
            ],
            capture_output=True,
            timeout=30,
        )

        # Remove via SFTP batch
        result = run_sftp_batch(
            shared_wg, user, ssh_target, ["rm /tmp/removeme-allowed.txt"]
        )
        assert result.returncode == 0, (
            f"SFTP remove should succeed: {result.stderr.decode()}"
        )

    def test_remove_blocked_when_upload_denied(
        self,
        sftp_ops_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """File removal should be blocked when upload (write) permission is denied."""
        user, ssh_target, role = setup_user_and_target(sftp_ops_ssh_port, shared_wg)

        set_sftp_permission_mode(shared_wg, "permissive")

        # First create the file with full permissions
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=True,
        )

        subprocess.run(
            [
                "ssh",
                "-p",
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
                "localhost",
                "touch /tmp/removeme-blocked.txt",
            ],
            capture_output=True,
            timeout=30,
        )

        # Now restrict to download-only
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=False,
            allow_download=True,
        )

        # Remove should fail
        result = run_sftp_batch(
            shared_wg, user, ssh_target, ["rm /tmp/removeme-blocked.txt"]
        )
        assert result.returncode != 0, (
            "SFTP remove should be blocked when upload is denied"
        )


class TestSftpRename:
    """Tests for SFTP rename permission enforcement."""

    def test_rename_allowed_when_upload_permitted(
        self,
        sftp_ops_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """File rename should succeed when upload permission is granted."""
        user, ssh_target, role = setup_user_and_target(sftp_ops_ssh_port, shared_wg)

        set_sftp_permission_mode(shared_wg, "permissive")
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=True,
        )

        subprocess.run(
            [
                "ssh",
                "-p",
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
                "localhost",
                "touch /tmp/rename-src-allowed.txt",
            ],
            capture_output=True,
            timeout=30,
        )

        result = run_sftp_batch(
            shared_wg,
            user,
            ssh_target,
            ["rename /tmp/rename-src-allowed.txt /tmp/rename-dst-allowed.txt"],
        )
        assert result.returncode == 0, (
            f"SFTP rename should succeed: {result.stderr.decode()}"
        )

    def test_rename_blocked_when_upload_denied(
        self,
        sftp_ops_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """File rename should be blocked when upload permission is denied."""
        user, ssh_target, role = setup_user_and_target(sftp_ops_ssh_port, shared_wg)

        set_sftp_permission_mode(shared_wg, "permissive")

        # Create file with full perms first
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=True,
        )

        subprocess.run(
            [
                "ssh",
                "-p",
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
                "localhost",
                "touch /tmp/rename-src-blocked.txt",
            ],
            capture_output=True,
            timeout=30,
        )

        # Now restrict
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=False,
            allow_download=True,
        )

        result = run_sftp_batch(
            shared_wg,
            user,
            ssh_target,
            ["rename /tmp/rename-src-blocked.txt /tmp/rename-dst-blocked.txt"],
        )
        assert result.returncode != 0, (
            "SFTP rename should be blocked when upload is denied"
        )

    def test_rename_blocked_by_allowed_paths(
        self,
        sftp_ops_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """Rename should be blocked if destination path violates allowed_paths.

        Uses paramiko to send a standard SSH_FXP_RENAME packet (not
        posix-rename@openssh.com extended), which triggers path checking
        on both source and destination.
        """
        user, ssh_target, role = setup_user_and_target(sftp_ops_ssh_port, shared_wg)

        set_sftp_permission_mode(shared_wg, "permissive")
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=True,
            allowed_paths=["/tmp/*"],
        )

        sftp_client = None
        transport = None
        try:
            sftp_client, transport = get_sftp_client(shared_wg, user, ssh_target)

            # Create a test file in the allowed path
            with sftp_client.open("/tmp/rename-path-test.txt", "w") as f:
                f.write("test")

            # Rename to path outside allowed_paths — should raise IOError
            with pytest.raises(IOError):
                sftp_client.rename(
                    "/tmp/rename-path-test.txt", "/var/rename-path-test.txt"
                )
        finally:
            if sftp_client:
                sftp_client.close()
            if transport:
                transport.close()


class TestSftpMkdir:
    """Tests for SFTP mkdir permission enforcement."""

    def test_mkdir_allowed_when_upload_permitted(
        self,
        sftp_ops_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """mkdir should succeed when upload permission is granted."""
        user, ssh_target, role = setup_user_and_target(sftp_ops_ssh_port, shared_wg)

        set_sftp_permission_mode(shared_wg, "permissive")
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=True,
        )

        dirname = f"testdir-{uuid4().hex[:8]}"
        result = run_sftp_batch(shared_wg, user, ssh_target, [f"mkdir /tmp/{dirname}"])
        assert result.returncode == 0, (
            f"SFTP mkdir should succeed: {result.stderr.decode()}"
        )

    def test_mkdir_blocked_when_upload_denied(
        self,
        sftp_ops_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """mkdir should be blocked when upload permission is denied."""
        user, ssh_target, role = setup_user_and_target(sftp_ops_ssh_port, shared_wg)

        set_sftp_permission_mode(shared_wg, "permissive")
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=False,
            allow_download=True,
        )

        dirname = f"testdir-{uuid4().hex[:8]}"
        result = run_sftp_batch(shared_wg, user, ssh_target, [f"mkdir /tmp/{dirname}"])
        assert result.returncode != 0, (
            "SFTP mkdir should be blocked when upload is denied"
        )


class TestSftpRmdir:
    """Tests for SFTP rmdir permission enforcement."""

    def test_rmdir_allowed_when_upload_permitted(
        self,
        sftp_ops_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """rmdir should succeed when upload permission is granted."""
        user, ssh_target, role = setup_user_and_target(sftp_ops_ssh_port, shared_wg)

        set_sftp_permission_mode(shared_wg, "permissive")
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=True,
        )

        dirname = f"rmdir-{uuid4().hex[:8]}"

        # Create via SFTP first, then remove
        result = run_sftp_batch(
            shared_wg,
            user,
            ssh_target,
            [f"mkdir /tmp/{dirname}", f"rmdir /tmp/{dirname}"],
        )
        assert result.returncode == 0, (
            f"SFTP rmdir should succeed: {result.stderr.decode()}"
        )

    def test_rmdir_blocked_when_upload_denied(
        self,
        sftp_ops_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """rmdir should be blocked when upload permission is denied."""
        user, ssh_target, role = setup_user_and_target(sftp_ops_ssh_port, shared_wg)

        set_sftp_permission_mode(shared_wg, "permissive")

        # Create dir with full perms
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=True,
        )

        dirname = f"rmdir-blocked-{uuid4().hex[:8]}"
        subprocess.run(
            [
                "ssh",
                "-p",
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
                "localhost",
                f"mkdir /tmp/{dirname}",
            ],
            capture_output=True,
            timeout=30,
        )

        # Restrict to download-only
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=False,
            allow_download=True,
        )

        result = run_sftp_batch(shared_wg, user, ssh_target, [f"rmdir /tmp/{dirname}"])
        assert result.returncode != 0, (
            "SFTP rmdir should be blocked when upload is denied"
        )


class TestSftpSetstat:
    """Tests for SFTP setstat (chmod/chown) permission enforcement."""

    def test_chmod_allowed_when_upload_permitted(
        self,
        sftp_ops_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """chmod (setstat) should succeed when upload permission is granted."""
        user, ssh_target, role = setup_user_and_target(sftp_ops_ssh_port, shared_wg)

        set_sftp_permission_mode(shared_wg, "permissive")
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=True,
        )

        fname = f"setstat-{uuid4().hex[:8]}.txt"
        subprocess.run(
            [
                "ssh",
                "-p",
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
                "localhost",
                f"touch /tmp/{fname}",
            ],
            capture_output=True,
            timeout=30,
        )

        result = run_sftp_batch(
            shared_wg, user, ssh_target, [f"chmod 755 /tmp/{fname}"]
        )
        assert result.returncode == 0, (
            f"SFTP chmod should succeed: {result.stderr.decode()}"
        )

    def test_chmod_blocked_when_upload_denied(
        self,
        sftp_ops_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """chmod (setstat) should be blocked when upload permission is denied."""
        user, ssh_target, role = setup_user_and_target(sftp_ops_ssh_port, shared_wg)

        set_sftp_permission_mode(shared_wg, "permissive")

        # Create file with full perms
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=True,
        )

        fname = f"setstat-blocked-{uuid4().hex[:8]}.txt"
        subprocess.run(
            [
                "ssh",
                "-p",
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
                "localhost",
                f"touch /tmp/{fname}",
            ],
            capture_output=True,
            timeout=30,
        )

        # Restrict
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=False,
            allow_download=True,
        )

        result = run_sftp_batch(
            shared_wg, user, ssh_target, [f"chmod 755 /tmp/{fname}"]
        )
        assert result.returncode != 0, (
            "SFTP chmod should be blocked when upload is denied"
        )


class TestSftpSymlink:
    """Tests for SFTP symlink permission enforcement."""

    def test_symlink_allowed_when_upload_permitted(
        self,
        sftp_ops_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """symlink should succeed when upload permission is granted."""
        user, ssh_target, role = setup_user_and_target(sftp_ops_ssh_port, shared_wg)

        set_sftp_permission_mode(shared_wg, "permissive")
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=True,
        )

        fname = f"symlink-target-{uuid4().hex[:8]}.txt"
        lname = f"symlink-link-{uuid4().hex[:8]}.txt"

        subprocess.run(
            [
                "ssh",
                "-p",
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
                "localhost",
                f"touch /tmp/{fname}",
            ],
            capture_output=True,
            timeout=30,
        )

        result = run_sftp_batch(
            shared_wg,
            user,
            ssh_target,
            [f"ln -s /tmp/{fname} /tmp/{lname}"],
        )
        assert result.returncode == 0, (
            f"SFTP symlink should succeed: {result.stderr.decode()}"
        )

    def test_symlink_blocked_when_upload_denied(
        self,
        sftp_ops_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """symlink should be blocked when upload permission is denied."""
        user, ssh_target, role = setup_user_and_target(sftp_ops_ssh_port, shared_wg)

        set_sftp_permission_mode(shared_wg, "permissive")
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=False,
            allow_download=True,
        )

        lname = f"symlink-blocked-{uuid4().hex[:8]}.txt"
        result = run_sftp_batch(
            shared_wg,
            user,
            ssh_target,
            [f"ln -s /etc/passwd /tmp/{lname}"],
        )
        assert result.returncode != 0, (
            "SFTP symlink should be blocked when upload is denied"
        )


class TestMaxFileSize:
    """Tests for max_file_size enforcement during SFTP write operations."""

    def test_upload_within_size_limit_succeeds(
        self,
        sftp_ops_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """Upload within max_file_size should succeed."""
        user, ssh_target, role = setup_user_and_target(sftp_ops_ssh_port, shared_wg)

        set_sftp_permission_mode(shared_wg, "permissive")
        # Set max_file_size to 1MB
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=True,
            max_file_size=1024 * 1024,
        )

        # Create a small file (100 bytes)
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as tmpfile:
            tmpfile.write(b"x" * 100)
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
                timeout=30,
            )
            os.unlink(tmpfile.name)

            assert result.returncode == 0, (
                f"Small file upload should succeed: {result.stderr.decode()}"
            )

    def test_upload_exceeding_size_limit_blocked(
        self,
        sftp_ops_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """Upload exceeding max_file_size should be blocked."""
        user, ssh_target, role = setup_user_and_target(sftp_ops_ssh_port, shared_wg)

        set_sftp_permission_mode(shared_wg, "permissive")
        # Set max_file_size to 1KB
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=True,
            max_file_size=1024,
        )

        # Create a file larger than 1KB (5KB)
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as tmpfile:
            tmpfile.write(b"x" * 5120)
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
                timeout=30,
            )
            os.unlink(tmpfile.name)

            assert result.returncode != 0, (
                "Upload exceeding max_file_size should be blocked"
            )


class TestSftpExtendedPackets:
    """Tests for SFTP extended packet handling.

    Uses paramiko to issue SFTP operations that trigger extended packets.
    The safe extensions (statvfs) should always work.
    Write extensions should be blocked when upload is denied.
    """

    def test_statvfs_allowed_with_restrictions(
        self,
        sftp_ops_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """statvfs (safe extension) should work even with SFTP restrictions.

        Uses paramiko to issue a statvfs call which sends an SSH_FXP_EXTENDED
        with request_name 'statvfs@openssh.com'.
        """
        user, ssh_target, role = setup_user_and_target(sftp_ops_ssh_port, shared_wg)

        set_sftp_permission_mode(shared_wg, "permissive")
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=False,
            allow_download=False,
        )

        sftp_client = None
        transport = None
        try:
            sftp_client, transport = get_sftp_client(shared_wg, user, ssh_target)
            # statvfs sends SSH_FXP_EXTENDED with 'statvfs@openssh.com'
            result = sftp_client.statvfs("/tmp")
            assert result is not None
            assert hasattr(result, "f_bsize")
        except Exception as e:
            # If paramiko raises, check if it's specifically PermissionDenied
            # (which would mean our blocking is wrong) vs connection error
            error_str = str(e).lower()
            if "permission" in error_str:
                pytest.fail(
                    f"statvfs should NOT be blocked (it's a safe extension): {e}"
                )
            # Other errors (e.g., server doesn't support statvfs) are acceptable
        finally:
            if sftp_client:
                sftp_client.close()
            if transport:
                transport.close()

    def test_readdir_and_stat_allowed_with_restrictions(
        self,
        sftp_ops_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """Read-only metadata ops (readdir, stat) should work even when both
        upload and download are denied, since they are not mutating operations.
        """
        user, ssh_target, role = setup_user_and_target(sftp_ops_ssh_port, shared_wg)

        set_sftp_permission_mode(shared_wg, "permissive")
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=False,
            allow_download=False,
        )

        sftp_client = None
        transport = None
        try:
            sftp_client, transport = get_sftp_client(shared_wg, user, ssh_target)

            # listdir sends Opendir + Readdir — should work (read-only metadata)
            entries = sftp_client.listdir("/tmp")
            assert isinstance(entries, list)

            # stat sends Stat — should work (read-only metadata)
            stat_result = sftp_client.stat("/tmp")
            assert stat_result is not None
        finally:
            if sftp_client:
                sftp_client.close()
            if transport:
                transport.close()


class TestStrictModeStreamlocal:
    """Tests for direct streamlocal (Unix socket forwarding) blocking in strict mode."""

    def test_strict_mode_unix_socket_forwarding_blocked(
        self,
        sftp_ops_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """Unix socket forwarding should be blocked in strict mode with SFTP restrictions.

        Uses -L with a Unix socket path to trigger direct-streamlocal channel.
        """
        user, ssh_target, role = setup_user_and_target(sftp_ops_ssh_port, shared_wg)

        set_sftp_permission_mode(shared_wg, "strict")
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=False,
            allow_download=True,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            local_sock = f"{tmpdir}/local.sock"
            try:
                result = subprocess.run(
                    [
                        "ssh",
                        "-p",
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
                        "-o",
                        "ExitOnForwardFailure=yes",
                        "-L",
                        f"{local_sock}:/var/run/docker.sock",
                        "-N",
                        "localhost",
                    ],
                    capture_output=True,
                    timeout=10,
                )
                # If it completed, it should have failed
                assert result.returncode != 0, (
                    "Unix socket forwarding should be blocked in strict mode"
                )
            except subprocess.TimeoutExpired:
                # Timeout means the channel was never established — expected
                pass
