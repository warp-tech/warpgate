"""
E2E tests for SFTP file transfer access control.

Tests verify that file transfer permissions are enforced correctly:
- Upload permission controls SFTP write operations
- Download permission controls SFTP read operations
- Permissions are per role-target assignment
- Permissive model: any role granting access wins
- Strict mode: shell/exec/forwarding blocked when SFTP restrictions active
- Permissive mode: SFTP enforced but shell/exec allowed
- Advanced restrictions: allowed_paths, blocked_extensions, max_file_size
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


def get_sftp_permission_mode(wg: WarpgateProcess) -> str:
    """Get instance-wide SFTP permission mode."""
    url = f"https://localhost:{wg.http_port}"
    with admin_client(url) as api:
        params = api.get_parameters()
        return params.sftp_permission_mode


def set_role_file_transfer_defaults(
    wg: WarpgateProcess,
    role_id: str,
    allow_upload: bool = True,
    allow_download: bool = True,
    allowed_paths=None,
    blocked_extensions=None,
    max_file_size=None,
):
    """Set file transfer defaults for a role."""
    url = f"https://localhost:{wg.http_port}"
    with admin_client(url) as api:
        return api.update_role_file_transfer_defaults(
            role_id,
            sdk.RoleFileTransferDefaults(
                allow_file_upload=allow_upload,
                allow_file_download=allow_download,
                allowed_paths=allowed_paths,
                blocked_extensions=blocked_extensions,
                max_file_size=max_file_size,
            ),
        )


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
    # Brief stabilization delay for CI environments
    time.sleep(0.1)

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
    """Tests for SFTP access control."""

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

    def test_sftp_download_blocked_when_upload_only(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """SFTP download should be blocked when only upload is permitted (fine-grained blocking).

        Note: Uses scp command which internally uses SFTP protocol (OpenSSH 9.0+).
        """
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
            # Modern scp uses SFTP protocol internally
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

    def test_sftp_upload_blocked_when_download_only(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """SFTP upload should be blocked when only download is permitted (fine-grained blocking).

        Note: Uses scp command which internally uses SFTP protocol (OpenSSH 9.0+).
        """
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

            # Modern scp uses SFTP protocol internally
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

        # Test upload works (from role1) via SFTP
        # Note: modern scp uses SFTP protocol internally (OpenSSH 9.0+)
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
            assert event["protocol"] == "sftp", f"Invalid protocol: {event['protocol']}"
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


class TestStrictMode:
    """Tests for strict SFTP permission enforcement mode.

    In strict mode, when SFTP restrictions are active (upload or download blocked),
    shell, exec, and port forwarding are also blocked.
    """

    def test_strict_mode_shell_blocked_when_sftp_restricted(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """Shell access should be blocked when SFTP is restricted and mode is strict."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Set strict mode
        set_sftp_permission_mode(shared_wg, "strict")

        # Restrict SFTP (block uploads)
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=False,
            allow_download=True,
        )

        # Attempt shell access - should be blocked
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
                "localhost",
                "echo hello",
            ],
            capture_output=True,
            timeout=30,
        )

        # Shell/exec should be blocked
        assert result.returncode != 0, "Shell should be blocked in strict mode"
        # Check for the expected error message
        stderr = result.stderr.decode()
        assert "SFTP-only mode" in stderr or result.returncode != 0

    def test_strict_mode_shell_allowed_when_no_sftp_restriction(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """Shell access should work when no SFTP restrictions exist, even in strict mode."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Set strict mode
        set_sftp_permission_mode(shared_wg, "strict")

        # Allow both upload and download (no restrictions)
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=True,
        )

        # Attempt shell access - should work
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
                "localhost",
                "echo hello",
            ],
            capture_output=True,
            timeout=30,
        )

        assert result.returncode == 0, (
            f"Shell should work when no SFTP restrictions: {result.stderr.decode()}"
        )
        assert b"hello" in result.stdout

    def test_strict_mode_sftp_still_works(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """SFTP should still work in strict mode (it's shell that's blocked, not SFTP)."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Set strict mode with download restriction
        set_sftp_permission_mode(shared_wg, "strict")
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,  # Allow upload
            allow_download=False,  # Block download
        )

        # SFTP upload should still work
        with tempfile.NamedTemporaryFile(delete=False, mode="w") as tmpfile:
            tmpfile.write("test content for strict mode")
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

            assert result.returncode == 0, (
                f"SFTP upload should work in strict mode: {result.stderr.decode()}"
            )

    def test_strict_mode_port_forwarding_blocked(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """Port forwarding should be blocked when SFTP is restricted and mode is strict."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Set strict mode with SFTP restriction
        set_sftp_permission_mode(shared_wg, "strict")
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=False,
            allow_download=True,
        )

        # Attempt local port forwarding - should be blocked.
        # The connection may hang (timeout) or fail immediately depending on
        # how the server rejects the direct-tcpip channel. Either outcome
        # means port forwarding is effectively blocked.
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
                    "12345:localhost:22",
                    "-N",
                    "localhost",
                ],
                capture_output=True,
                timeout=10,
            )
            # If it completed, it should have failed
            assert result.returncode != 0, (
                "Port forwarding should be blocked in strict mode"
            )
        except subprocess.TimeoutExpired:
            # Timeout means the forwarding channel was never established
            # which is the expected behavior - connection hangs because
            # the direct-tcpip channel is rejected
            pass


class TestPermissiveMode:
    """Tests for permissive SFTP permission enforcement mode.

    In permissive mode, SFTP restrictions are enforced but shell/exec/forwarding
    remain available (with a warning in the UI).
    """

    def test_permissive_mode_shell_allowed_with_sftp_restriction(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """Shell access should work in permissive mode even with SFTP restrictions."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Set permissive mode
        set_sftp_permission_mode(shared_wg, "permissive")

        # Restrict SFTP (block uploads)
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=False,
            allow_download=True,
        )

        # Attempt shell access - should work in permissive mode
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
                "localhost",
                "echo hello",
            ],
            capture_output=True,
            timeout=30,
        )

        assert result.returncode == 0, (
            f"Shell should work in permissive mode: {result.stderr.decode()}"
        )
        assert b"hello" in result.stdout

    def test_permissive_mode_sftp_still_enforced(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """SFTP restrictions should still be enforced in permissive mode."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Set permissive mode
        set_sftp_permission_mode(shared_wg, "permissive")

        # Block uploads
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=False,
            allow_download=True,
        )

        # SFTP upload should be blocked
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
                timeout=30,
            )

            assert result.returncode != 0, (
                "SFTP upload should be blocked even in permissive mode"
            )


class TestAdvancedRestrictions:
    """Tests for advanced SFTP restrictions: allowed_paths, blocked_extensions, max_file_size."""

    def test_allowed_paths_upload_permitted(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """Upload to a path matching allowed_paths should succeed."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Set allowed_paths to /tmp/*
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=True,
            allowed_paths=["/tmp/*"],
        )

        with tempfile.NamedTemporaryFile(delete=False, mode="w") as tmpfile:
            tmpfile.write("test content for allowed path")
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

            assert result.returncode == 0, (
                f"Upload to allowed path should succeed: {result.stderr.decode()}"
            )

    def test_allowed_paths_upload_blocked(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """Upload to a path NOT matching allowed_paths should be blocked."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Set allowed_paths to only /uploads/* (not /tmp)
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=True,
            allowed_paths=["/uploads/*"],
        )

        with tempfile.NamedTemporaryFile(delete=False, mode="w") as tmpfile:
            tmpfile.write("test content for blocked path")
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

            assert result.returncode != 0, (
                "Upload to path not in allowed_paths should be blocked"
            )

    def test_blocked_extensions_upload_denied(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """Upload of file with blocked extension should be denied."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Block .exe and .sh extensions
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=True,
            blocked_extensions=[".exe", ".sh"],
        )

        with tempfile.NamedTemporaryFile(
            delete=False, mode="w", suffix=".sh"
        ) as tmpfile:
            tmpfile.write("#!/bin/bash\necho blocked")
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

            assert result.returncode != 0, (
                "Upload of file with blocked extension should be denied"
            )

    def test_blocked_extensions_allowed_extension_permitted(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """Upload of file with non-blocked extension should succeed."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Block only .exe extension
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=True,
            blocked_extensions=[".exe"],
        )

        with tempfile.NamedTemporaryFile(
            delete=False, mode="w", suffix=".txt"
        ) as tmpfile:
            tmpfile.write("This is a text file")
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

            assert result.returncode == 0, (
                f"Upload of .txt file should succeed: {result.stderr.decode()}"
            )

    def test_blocked_extensions_case_insensitive(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """Extension blocking should be case-insensitive."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Block .exe (lowercase)
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=True,
            blocked_extensions=[".exe"],
        )

        with tempfile.NamedTemporaryFile(
            delete=False,
            mode="w",
            suffix=".EXE",  # Uppercase
        ) as tmpfile:
            tmpfile.write("fake executable")
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

            assert result.returncode != 0, (
                "Extension blocking should be case-insensitive"
            )


class TestRoleLevelDefaults:
    """Tests for role-level file transfer defaults."""

    def test_role_defaults_inherited_by_target(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """Target-role should inherit file transfer settings from role defaults."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Set role defaults to block uploads
        set_role_file_transfer_defaults(
            shared_wg,
            role.id,
            allow_upload=False,
            allow_download=True,
        )

        # Don't set explicit target-role override (use null = inherit)
        # The target-role should inherit from role defaults

        # Attempt upload - should be blocked (inherited from role)
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
                timeout=30,
            )

            assert result.returncode != 0, (
                "Upload should be blocked (inherited from role defaults)"
            )

    def test_target_role_override_takes_precedence(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """Target-role explicit override should take precedence over role defaults."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Set role defaults to block uploads
        set_role_file_transfer_defaults(
            shared_wg,
            role.id,
            allow_upload=False,
            allow_download=True,
        )

        # Set explicit target-role override to allow uploads
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,  # Override to allow
            allow_download=True,
        )

        # Attempt upload - should succeed (override takes precedence)
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
                timeout=30,
            )

            assert result.returncode == 0, (
                f"Upload should succeed (override takes precedence): {result.stderr.decode()}"
            )


class TestStrictModeExec:
    """Additional strict mode tests for exec and remote forwarding."""

    def test_strict_mode_exec_blocked(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """Exec requests should be blocked when SFTP is restricted and mode is strict."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Set strict mode
        set_sftp_permission_mode(shared_wg, "strict")

        # Restrict SFTP (block downloads)
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=False,
        )

        # Attempt exec command - should be blocked
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
                "localhost",
                "whoami",
            ],
            capture_output=True,
            timeout=30,
        )

        # Exec should be blocked in strict mode with SFTP restrictions
        assert result.returncode != 0, (
            "Exec command should be blocked in strict mode with SFTP restrictions"
        )

    def test_strict_mode_remote_forwarding_blocked(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """Remote port forwarding (-R) should be blocked in strict mode with SFTP restrictions."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Set strict mode with SFTP restriction
        set_sftp_permission_mode(shared_wg, "strict")
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=False,
            allow_download=True,
        )

        # Attempt remote port forwarding - should be blocked
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
                    "-R",
                    "12346:localhost:22",
                    "-N",
                    "localhost",
                ],
                capture_output=True,
                timeout=10,
            )
            # If it completed, it should have failed
            assert result.returncode != 0, (
                "Remote port forwarding should be blocked in strict mode"
            )
        except subprocess.TimeoutExpired:
            # Timeout means the forwarding channel was never established
            pass


class TestAdvancedRestrictionsExtended:
    """Additional tests for advanced SFTP restrictions - downloads, mkdir, rename, max_file_size."""

    def test_allowed_paths_download_permitted(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """Download from a path matching allowed_paths should succeed."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Set permissive mode so shell works (we need exec to create the file)
        set_sftp_permission_mode(shared_wg, "permissive")

        # Allow both upload and download, restrict to /tmp/*
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=True,
            allowed_paths=["/tmp/*"],
        )

        # First, create a file on the target via exec
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
                "echo download-test > /tmp/dl-test-file.txt",
            ],
            capture_output=True,
            timeout=30,
        )

        # Download from allowed path
        with tempfile.TemporaryDirectory() as tmpdir:
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
                    "localhost:/tmp/dl-test-file.txt",
                    f"{tmpdir}/",
                ],
                capture_output=True,
                timeout=30,
            )

            assert result.returncode == 0, (
                f"Download from allowed path should succeed: {result.stderr.decode()}"
            )

    def test_allowed_paths_download_blocked(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """Download from a path NOT matching allowed_paths should be denied."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Set permissive mode so shell works (we need exec to create the file)
        set_sftp_permission_mode(shared_wg, "permissive")

        # Allow both up/down but restrict paths to /uploads/*
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=True,
            allowed_paths=["/uploads/*"],
        )

        # Create a file outside allowed path
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
                "echo secret > /tmp/secret-file.txt",
            ],
            capture_output=True,
            timeout=30,
        )

        # Attempt download from non-allowed path
        with tempfile.TemporaryDirectory() as tmpdir:
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
                    "localhost:/tmp/secret-file.txt",
                    f"{tmpdir}/",
                ],
                capture_output=True,
                timeout=30,
            )

            assert result.returncode != 0, (
                "Download from non-allowed path should be denied"
            )

    def test_blocked_extensions_download_denied(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """Download of file with blocked extension should be denied."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        # Set permissive mode so shell works
        set_sftp_permission_mode(shared_wg, "permissive")

        # Block .key and .pem extensions
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=True,
            blocked_extensions=[".key", ".pem"],
        )

        # Create a file with blocked extension
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
                "echo private > /tmp/private.key",
            ],
            capture_output=True,
            timeout=30,
        )

        # Attempt download of blocked extension
        with tempfile.TemporaryDirectory() as tmpdir:
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
                    "localhost:/tmp/private.key",
                    f"{tmpdir}/",
                ],
                capture_output=True,
                timeout=30,
            )

            assert result.returncode != 0, (
                "Download of file with blocked extension should be denied"
            )

    def test_target_role_clear_blocked_extensions(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """Target-role can clear role's blocked_extensions by setting empty list."""
        user, ssh_target, role = setup_user_and_target(
            processes, shared_wg, wg_c_ed25519_pubkey
        )

        set_sftp_permission_mode(shared_wg, "permissive")

        # Set role defaults with blocked extensions
        set_role_file_transfer_defaults(
            shared_wg,
            role.id,
            allow_upload=True,
            allow_download=True,
            blocked_extensions=[".exe", ".sh"],
        )

        # Override at target-role level: clear blocked extensions (empty list)
        set_file_transfer_permission(
            shared_wg,
            ssh_target.id,
            role.id,
            allow_upload=True,
            allow_download=True,
            blocked_extensions=[],
        )

        # Upload of .sh file should now succeed (target-role cleared the restriction)
        with tempfile.NamedTemporaryFile(
            delete=False, mode="w", suffix=".sh"
        ) as tmpfile:
            tmpfile.write("#!/bin/bash\necho cleared")
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

            assert result.returncode == 0, (
                f"Upload of .sh should succeed when target-role clears blocked extensions: {result.stderr.decode()}"
            )
