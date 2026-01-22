"""
E2E tests for SCP/SFTP file transfer access control.

Tests verify that file transfer permissions are enforced correctly:
- Upload permission controls SCP -t and SFTP write operations
- Download permission controls SCP -f and SFTP read operations
- Permissions are per role-target assignment
- Permissive model: any role granting access wins
"""

import json
import os
import time
from pathlib import Path
from uuid import uuid4
import subprocess
import tempfile
import pytest
import yaml

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
        """By default, file transfers should be allowed (backward compat).

        With the new inheritance model:
        - Target-role permissions default to NULL (inherit from role)
        - Role defaults are True for both upload and download
        - Effective permission is True (inherited from role)
        """
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Get default permissions
        perm = get_file_transfer_permission(shared_wg, ssh_target.id, role.id)

        # Default is NULL (inherit from role), not explicit True
        # This means "inherit from role defaults which are True"
        # None means "inherit", True/False means explicit override
        assert perm.allow_file_upload is None or perm.allow_file_upload is True
        assert perm.allow_file_download is None or perm.allow_file_download is True

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

    def test_multi_role_permissive_model(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """Test permissive model: if any role grants permission, transfer is allowed."""
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()],
        )
        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            # Create two roles
            role1 = api.create_role(
                sdk.RoleDataRequest(name=f"role1-{uuid4()}"),
            )
            role2 = api.create_role(
                sdk.RoleDataRequest(name=f"role2-{uuid4()}"),
            )

            # Create user with both roles
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_public_key_credential(
                user.id,
                sdk.NewPublicKeyCredential(
                    label="Public Key",
                    openssh_public_key=open("ssh-keys/id_ed25519.pub").read().strip(),
                ),
            )
            api.add_user_role(
                user.id, role1.id, sdk.AddUserRoleRequest(expires_at=None)
            )
            api.add_user_role(
                user.id, role2.id, sdk.AddUserRoleRequest(expires_at=None)
            )

            # Create target with both roles
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
            api.add_target_role(ssh_target.id, role1.id)
            api.add_target_role(ssh_target.id, role2.id)

            # Set role1 to allow upload only
            api.update_target_role_file_transfer_permission(
                ssh_target.id,
                role1.id,
                sdk.FileTransferPermissionData(
                    allow_file_upload=True,
                    allow_file_download=False,
                ),
            )

            # Set role2 to allow download only
            api.update_target_role_file_transfer_permission(
                ssh_target.id,
                role2.id,
                sdk.FileTransferPermissionData(
                    allow_file_upload=False,
                    allow_file_download=True,
                ),
            )

        # Permissive model: user should be able to both upload AND download
        # because role1 grants upload and role2 grants download

        # Test download works (from role2)
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
                f"Download should work via role2: {result.stderr.decode()}"
            )

        # Test upload works (from role1)
        with tempfile.NamedTemporaryFile(delete=False, mode="w") as tmpfile:
            tmpfile.write("test content for permissive model")
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
                f"Upload should work via role1: {result.stderr.decode()}"
            )


class TestFileTransferLogging:
    """Tests for file transfer logging functionality."""

    def test_file_transfer_logging(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        timeout,
    ):
        """Test that file transfers are logged with correct event_type and fields."""
        # Create a temporary file to capture log output
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", delete=False
        ) as log_file:
            log_output_path = Path(log_file.name)

        try:
            # Start Warpgate to do initial setup
            wg = processes.start_wg()
            wait_port(wg.http_port, for_process=wg.process, recv=False, timeout=timeout)

            # Set up user and target
            ssh_port = processes.start_ssh_server(
                trusted_keys=[wg_c_ed25519_pubkey.read_text()],
            )
            wait_port(ssh_port)

            url = f"https://localhost:{wg.http_port}"
            with admin_client(url) as api:
                role = api.create_role(
                    sdk.RoleDataRequest(name=f"role-{uuid4()}"),
                )
                user = api.create_user(
                    sdk.CreateUserRequest(username=f"user-{uuid4()}")
                )
                api.create_public_key_credential(
                    user.id,
                    sdk.NewPublicKeyCredential(
                        label="Public Key",
                        openssh_public_key=open("ssh-keys/id_ed25519.pub")
                        .read()
                        .strip(),
                    ),
                )
                api.add_user_role(
                    user.id, role.id, sdk.AddUserRoleRequest(expires_at=None)
                )
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

                # Ensure file transfer is allowed
                api.update_target_role_file_transfer_permission(
                    ssh_target.id,
                    role.id,
                    sdk.FileTransferPermissionData(
                        allow_file_upload=True,
                        allow_file_download=True,
                    ),
                )

            # Stop the process so we can restart with JSON logging
            wg.process.terminate()
            try:
                wg.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                wg.process.kill()
                wg.process.wait()

            # Modify config to enable JSON logs
            config = yaml.safe_load(wg.config_path.open())
            config["log"] = config.get("log", {})
            config["log"]["format"] = "json"
            with wg.config_path.open("w") as f:
                yaml.safe_dump(config, f)

            # Restart with JSON logging
            with open(log_output_path, "w") as log_capture:
                wg_json = processes.start_wg(
                    share_with=wg,
                    args=["run", "--enable-admin-token"],
                    stdout=log_capture,
                    stderr=subprocess.STDOUT,
                )

                wait_port(
                    wg_json.http_port,
                    for_process=wg_json.process,
                    recv=False,
                    timeout=timeout,
                )
                # Also wait for SSH port
                wait_port(
                    wg_json.ssh_port,
                    for_process=wg_json.process,
                    recv=False,
                    timeout=timeout,
                )

                # Perform a file download
                with tempfile.TemporaryDirectory() as tmpdir:
                    result = subprocess.run(
                        [
                            "sftp",
                            "-P",
                            str(wg_json.ssh_port),
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
                        timeout=30,
                    )
                    assert result.returncode == 0, (
                        f"SFTP failed: {result.stderr.decode()}"
                    )

                # Give time for logs to flush
                time.sleep(1.0)

            # Give extra time after context closes for any remaining flushes
            time.sleep(0.5)

            # Check logs for file transfer events
            log_content = log_output_path.read_text()

            # Debug: print number of log lines and some content
            print(
                f"DEBUG: Log file has {len(log_content)} bytes, {log_content.count(chr(10))} lines"
            )
            lines = [line.strip() for line in log_content.split("\n") if line.strip()]

            file_transfer_events = []
            for line in lines:
                try:
                    entry = json.loads(line)
                    if entry.get("event_type") == "file_transfer":
                        file_transfer_events.append(entry)
                except json.JSONDecodeError:
                    continue

            # Also check for file_transfer string anywhere in logs (for debugging)
            has_file_transfer_string = (
                "file_transfer" in log_content or "File transfer" in log_content
            )
            has_sftp_subsystem = "SFTP subsystem" in log_content

            assert len(file_transfer_events) >= 1, (
                f"Expected at least 1 file_transfer log entry, got {len(file_transfer_events)}. "
                f"Found 'file_transfer' string: {has_file_transfer_string}, "
                f"Found 'SFTP subsystem': {has_sftp_subsystem}. "
                f"Log content:\n{log_content[:10000]}"
            )

            # Check that we have started and/or completed events
            statuses = [e.get("status") for e in file_transfer_events]
            assert "started" in statuses or "completed" in statuses, (
                f"Expected 'started' or 'completed' status in file_transfer events. "
                f"Got statuses: {statuses}"
            )

            # Verify event structure for a file_transfer event
            event = file_transfer_events[0]
            assert "protocol" in event, "Missing 'protocol' field"
            assert event["protocol"] in ["sftp", "scp"], (
                f"Invalid protocol: {event['protocol']}"
            )
            assert "direction" in event, "Missing 'direction' field"
            assert "status" in event, "Missing 'status' field"

        finally:
            log_output_path.unlink(missing_ok=True)

    def test_denied_transfer_logging(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        timeout,
    ):
        """Test that denied file transfers are logged."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", delete=False
        ) as log_file:
            log_output_path = Path(log_file.name)

        try:
            # Start Warpgate to do initial setup
            wg = processes.start_wg()
            wait_port(wg.http_port, for_process=wg.process, recv=False, timeout=timeout)

            # Set up user and target
            ssh_port = processes.start_ssh_server(
                trusted_keys=[wg_c_ed25519_pubkey.read_text()],
            )
            wait_port(ssh_port)

            url = f"https://localhost:{wg.http_port}"
            with admin_client(url) as api:
                role = api.create_role(
                    sdk.RoleDataRequest(name=f"role-{uuid4()}"),
                )
                user = api.create_user(
                    sdk.CreateUserRequest(username=f"user-{uuid4()}")
                )
                api.create_public_key_credential(
                    user.id,
                    sdk.NewPublicKeyCredential(
                        label="Public Key",
                        openssh_public_key=open("ssh-keys/id_ed25519.pub")
                        .read()
                        .strip(),
                    ),
                )
                api.add_user_role(
                    user.id, role.id, sdk.AddUserRoleRequest(expires_at=None)
                )
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

                # Deny file transfers
                api.update_target_role_file_transfer_permission(
                    ssh_target.id,
                    role.id,
                    sdk.FileTransferPermissionData(
                        allow_file_upload=True,  # Allow SFTP subsystem
                        allow_file_download=False,  # But block downloads
                    ),
                )

            # Stop and restart with JSON logging
            wg.process.terminate()
            try:
                wg.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                wg.process.kill()
                wg.process.wait()

            config = yaml.safe_load(wg.config_path.open())
            config["log"] = config.get("log", {})
            config["log"]["format"] = "json"
            with wg.config_path.open("w") as f:
                yaml.safe_dump(config, f)

            with open(log_output_path, "w") as log_capture:
                wg_json = processes.start_wg(
                    share_with=wg,
                    args=["run", "--enable-admin-token"],
                    stdout=log_capture,
                    stderr=subprocess.STDOUT,
                )

                wait_port(
                    wg_json.http_port,
                    for_process=wg_json.process,
                    recv=False,
                    timeout=timeout,
                )
                # Also wait for SSH port
                wait_port(
                    wg_json.ssh_port,
                    for_process=wg_json.process,
                    recv=False,
                    timeout=timeout,
                )

                # Attempt a file download (should be denied)
                with tempfile.TemporaryDirectory() as tmpdir:
                    result = subprocess.run(
                        [
                            "sftp",
                            "-P",
                            str(wg_json.ssh_port),
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
                        timeout=30,
                    )
                    # Should fail because download is denied
                    assert result.returncode != 0

                time.sleep(0.5)

            # Check logs for denied event
            log_content = log_output_path.read_text()
            lines = [line.strip() for line in log_content.split("\n") if line.strip()]

            denied_events = []
            for line in lines:
                try:
                    entry = json.loads(line)
                    if (
                        entry.get("event_type") == "file_transfer"
                        and entry.get("status") == "denied"
                    ):
                        denied_events.append(entry)
                except json.JSONDecodeError:
                    continue

            assert len(denied_events) >= 1, (
                f"Expected at least 1 denied file_transfer event. "
                f"Log excerpt:\n{log_content[:2000]}"
            )

            # Verify denied event has reason
            event = denied_events[0]
            assert "denied_reason" in event or "message" in event, (
                "Denied event should have a reason"
            )

        finally:
            log_output_path.unlink(missing_ok=True)
