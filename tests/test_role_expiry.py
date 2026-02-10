"""
E2E tests for user role expiry and history tracking.

Tests verify that:
- Roles can be granted with a TTL (expires_at timestamp)
- Expired roles deny SSH access
- Expired roles can be re-enabled via update_user_role_expiry
- Revoked (soft-deleted) roles deny SSH access
- Revoked roles can be re-activated by updating/removing expiry
- Role history audit trail records all changes
- get_user_roles returns all assignments including expired/revoked
"""

import subprocess
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from .api_client import admin_client, sdk
from .conftest import WarpgateProcess


def setup_user_and_target(
    ssh_port,
    wg: WarpgateProcess,
):
    """Set up a user, role, and SSH target for testing (no role assigned yet).

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


def try_ssh_command(wg, user, target, command="echo hello"):
    """Attempt an SSH command and return the result."""
    return subprocess.run(
        [
            "ssh",
            "-p",
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
            command,
        ],
        capture_output=True,
        timeout=30,
    )


class TestRoleExpiryAccess:
    """Tests for role expiry affecting SSH access."""

    def test_grant_role_with_future_expiry_allows_access(
        self,
        shared_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """A role granted with a future expiry should allow access."""
        user, ssh_target, role = setup_user_and_target(shared_ssh_port, shared_wg)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            future_expiry = (
                datetime.now(timezone.utc) + timedelta(hours=4)
            ).isoformat()
            assignment = api.add_user_role(
                user.id,
                role.id,
                sdk.AddUserRoleRequest(expires_at=future_expiry),
            )
            assert assignment.is_active is True
            assert assignment.is_expired is False
            assert assignment.expires_at is not None

        result = try_ssh_command(shared_wg, user, ssh_target)
        assert result.returncode == 0, (
            f"SSH should work with future expiry: {result.stderr.decode()}"
        )
        assert b"hello" in result.stdout

    def test_expired_role_denies_access(
        self,
        shared_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """A role that has already expired should deny SSH access."""
        user, ssh_target, role = setup_user_and_target(shared_ssh_port, shared_wg)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            # Set expiry 2 seconds in the future
            near_expiry = (
                datetime.now(timezone.utc) + timedelta(seconds=2)
            ).isoformat()
            api.add_user_role(
                user.id,
                role.id,
                sdk.AddUserRoleRequest(expires_at=near_expiry),
            )

        # Wait for the role to expire
        time.sleep(3)

        # Verify via API that the role is now expired
        with admin_client(url) as api:
            assignment = api.get_user_role(user.id, role.id)
            assert assignment.is_expired is True
            assert assignment.is_active is False

        # SSH should be denied
        result = try_ssh_command(shared_wg, user, ssh_target)
        assert result.returncode != 0, "SSH should fail with expired role"

    def test_reenable_expired_role_restores_access(
        self,
        shared_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """Re-enabling an expired role by updating expiry should restore SSH access."""
        user, ssh_target, role = setup_user_and_target(shared_ssh_port, shared_wg)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            # Grant with short expiry
            near_expiry = (
                datetime.now(timezone.utc) + timedelta(seconds=2)
            ).isoformat()
            api.add_user_role(
                user.id,
                role.id,
                sdk.AddUserRoleRequest(expires_at=near_expiry),
            )

        # Wait for expiry
        time.sleep(3)

        # Verify expired
        with admin_client(url) as api:
            assignment = api.get_user_role(user.id, role.id)
            assert assignment.is_expired is True

        # SSH should fail
        result = try_ssh_command(shared_wg, user, ssh_target)
        assert result.returncode != 0, "SSH should fail with expired role"

        # Re-enable with new future expiry
        with admin_client(url) as api:
            new_expiry = (datetime.now(timezone.utc) + timedelta(hours=4)).isoformat()
            updated = api.update_user_role_expiry(
                user.id,
                role.id,
                sdk.UpdateUserRoleExpiryRequest(expires_at=new_expiry),
            )
            assert updated.is_active is True
            assert updated.is_expired is False

        # SSH should work again
        result = try_ssh_command(shared_wg, user, ssh_target)
        assert result.returncode == 0, (
            f"SSH should work after re-enabling expired role: {result.stderr.decode()}"
        )
        assert b"hello" in result.stdout

    def test_remove_expiry_makes_permanent(
        self,
        shared_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """Removing expiry from a role should make it permanent."""
        user, ssh_target, role = setup_user_and_target(shared_ssh_port, shared_wg)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            # Grant with short expiry
            near_expiry = (
                datetime.now(timezone.utc) + timedelta(seconds=2)
            ).isoformat()
            api.add_user_role(
                user.id,
                role.id,
                sdk.AddUserRoleRequest(expires_at=near_expiry),
            )

        # Wait for expiry
        time.sleep(3)

        # Remove expiry (make permanent)
        with admin_client(url) as api:
            updated = api.remove_user_role_expiry(user.id, role.id)
            assert updated.expires_at is None
            assert updated.is_active is True
            assert updated.is_expired is False

        # SSH should work (permanent role)
        result = try_ssh_command(shared_wg, user, ssh_target)
        assert result.returncode == 0, (
            f"SSH should work after removing expiry: {result.stderr.decode()}"
        )
        assert b"hello" in result.stdout


class TestRoleRevocation:
    """Tests for role soft-delete (revocation)."""

    def test_revoked_role_denies_access(
        self,
        shared_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """A revoked (soft-deleted) role should deny SSH access."""
        user, ssh_target, role = setup_user_and_target(shared_ssh_port, shared_wg)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            api.add_user_role(user.id, role.id, sdk.AddUserRoleRequest(expires_at=None))

        # Verify access works first
        result = try_ssh_command(shared_wg, user, ssh_target)
        assert result.returncode == 0, (
            f"SSH should work before revocation: {result.stderr.decode()}"
        )

        # Revoke the role (soft delete)
        with admin_client(url) as api:
            api.delete_user_role(user.id, role.id)

        # SSH should be denied
        result = try_ssh_command(shared_wg, user, ssh_target)
        assert result.returncode != 0, "SSH should fail with revoked role"

    def test_reactivate_revoked_role_via_update_expiry(
        self,
        shared_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """Updating expiry on a revoked role should re-activate it (clears revoked_at)."""
        user, ssh_target, role = setup_user_and_target(shared_ssh_port, shared_wg)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            api.add_user_role(user.id, role.id, sdk.AddUserRoleRequest(expires_at=None))
            # Revoke
            api.delete_user_role(user.id, role.id)

        # SSH should fail
        result = try_ssh_command(shared_wg, user, ssh_target)
        assert result.returncode != 0, "SSH should fail with revoked role"

        # Re-activate by updating expiry (this clears revoked_at)
        with admin_client(url) as api:
            new_expiry = (datetime.now(timezone.utc) + timedelta(hours=4)).isoformat()
            updated = api.update_user_role_expiry(
                user.id,
                role.id,
                sdk.UpdateUserRoleExpiryRequest(expires_at=new_expiry),
            )
            assert updated.is_active is True

        # SSH should work again
        result = try_ssh_command(shared_wg, user, ssh_target)
        assert result.returncode == 0, (
            f"SSH should work after re-activating: {result.stderr.decode()}"
        )
        assert b"hello" in result.stdout

    def test_reactivate_revoked_role_via_remove_expiry(
        self,
        shared_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """Removing expiry on a revoked role should re-activate it permanently."""
        user, ssh_target, role = setup_user_and_target(shared_ssh_port, shared_wg)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            api.add_user_role(user.id, role.id, sdk.AddUserRoleRequest(expires_at=None))
            # Revoke
            api.delete_user_role(user.id, role.id)

        # Re-activate by removing expiry (clears revoked_at, sets permanent)
        with admin_client(url) as api:
            updated = api.remove_user_role_expiry(user.id, role.id)
            assert updated.is_active is True
            assert updated.expires_at is None

        # SSH should work
        result = try_ssh_command(shared_wg, user, ssh_target)
        assert result.returncode == 0, (
            f"SSH should work after re-activating: {result.stderr.decode()}"
        )
        assert b"hello" in result.stdout


class TestRoleHistory:
    """Tests for role assignment history audit trail."""

    def test_grant_creates_history_entry(
        self,
        shared_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """Granting a role should create a 'granted' history entry."""
        user, ssh_target, role = setup_user_and_target(shared_ssh_port, shared_wg)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            api.add_user_role(user.id, role.id, sdk.AddUserRoleRequest(expires_at=None))

            history = api.get_user_role_history(user.id, role.id)
            assert history.total >= 1
            actions = [e.action for e in history.items]
            assert "granted" in actions

    def test_revoke_creates_history_entry(
        self,
        shared_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """Revoking a role should create a 'revoked' history entry."""
        user, ssh_target, role = setup_user_and_target(shared_ssh_port, shared_wg)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            api.add_user_role(user.id, role.id, sdk.AddUserRoleRequest(expires_at=None))
            api.delete_user_role(user.id, role.id)

            history = api.get_user_role_history(user.id, role.id)
            actions = [e.action for e in history.items]
            assert "granted" in actions
            assert "revoked" in actions

    def test_expiry_change_creates_history_entry(
        self,
        shared_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """Updating expiry should create an 'expiry_changed' history entry."""
        user, ssh_target, role = setup_user_and_target(shared_ssh_port, shared_wg)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            api.add_user_role(user.id, role.id, sdk.AddUserRoleRequest(expires_at=None))
            new_expiry = (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat()
            api.update_user_role_expiry(
                user.id,
                role.id,
                sdk.UpdateUserRoleExpiryRequest(expires_at=new_expiry),
            )

            history = api.get_user_role_history(user.id, role.id)
            actions = [e.action for e in history.items]
            assert "expiry_changed" in actions

    def test_expiry_removal_creates_history_entry(
        self,
        shared_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """Removing expiry should create an 'expiry_removed' history entry."""
        user, ssh_target, role = setup_user_and_target(shared_ssh_port, shared_wg)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            future_expiry = (
                datetime.now(timezone.utc) + timedelta(hours=4)
            ).isoformat()
            api.add_user_role(
                user.id,
                role.id,
                sdk.AddUserRoleRequest(expires_at=future_expiry),
            )
            api.remove_user_role_expiry(user.id, role.id)

            history = api.get_user_role_history(user.id, role.id)
            actions = [e.action for e in history.items]
            assert "expiry_removed" in actions

    def test_full_history_lifecycle(
        self,
        shared_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """Full lifecycle: grant → change expiry → revoke → re-enable."""
        user, ssh_target, role = setup_user_and_target(shared_ssh_port, shared_wg)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            # 1. Grant with expiry
            future_expiry = (
                datetime.now(timezone.utc) + timedelta(hours=4)
            ).isoformat()
            api.add_user_role(
                user.id,
                role.id,
                sdk.AddUserRoleRequest(expires_at=future_expiry),
            )

            # 2. Change expiry
            new_expiry = (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat()
            api.update_user_role_expiry(
                user.id,
                role.id,
                sdk.UpdateUserRoleExpiryRequest(expires_at=new_expiry),
            )

            # 3. Revoke
            api.delete_user_role(user.id, role.id)

            # 4. Re-enable (remove expiry, which also clears revoked_at)
            api.remove_user_role_expiry(user.id, role.id)

            # Check full history
            history = api.get_user_role_history(user.id, role.id)
            assert history.total >= 4
            actions = [e.action for e in history.items]
            assert "granted" in actions
            assert "expiry_changed" in actions
            assert "revoked" in actions
            assert "expiry_removed" in actions


class TestRoleAssignmentAPI:
    """Tests for the role assignment list API."""

    def test_get_user_roles_returns_all_states(
        self,
        shared_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """get_user_roles should return all assignments including expired and revoked."""
        user, ssh_target, role = setup_user_and_target(shared_ssh_port, shared_wg)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            # Create a second role
            role2 = api.create_role(
                sdk.RoleDataRequest(name=f"role2-{uuid4()}"),
            )

            # Grant role1 with short expiry
            near_expiry = (
                datetime.now(timezone.utc) + timedelta(seconds=2)
            ).isoformat()
            api.add_user_role(
                user.id,
                role.id,
                sdk.AddUserRoleRequest(expires_at=near_expiry),
            )

            # Grant role2 permanently then revoke
            api.add_user_role(
                user.id,
                role2.id,
                sdk.AddUserRoleRequest(expires_at=None),
            )
            api.delete_user_role(user.id, role2.id)

        # Wait for role1 to expire
        time.sleep(3)

        with admin_client(url) as api:
            roles = api.get_user_roles(user.id)
            role_ids = [r.id for r in roles]

            # Both roles should be returned (even though expired/revoked)
            assert role.id in role_ids
            assert role2.id in role_ids

            # Check states
            role1_assignment = next(r for r in roles if r.id == role.id)
            role2_assignment = next(r for r in roles if r.id == role2.id)

            assert role1_assignment.is_expired is True
            assert role1_assignment.is_active is False

            assert role2_assignment.is_active is False

    def test_add_role_with_expiry_409_on_duplicate(
        self,
        shared_ssh_port,
        shared_wg: WarpgateProcess,
    ):
        """Adding a role that already exists (even revoked) should return 409."""
        user, ssh_target, role = setup_user_and_target(shared_ssh_port, shared_wg)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            api.add_user_role(user.id, role.id, sdk.AddUserRoleRequest(expires_at=None))

            # Try adding the same role again - should fail
            with pytest.raises(sdk.ApiException) as exc_info:
                api.add_user_role(
                    user.id, role.id, sdk.AddUserRoleRequest(expires_at=None)
                )
            assert exc_info.value.status == 409
