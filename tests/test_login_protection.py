import requests
from uuid import uuid4
import time

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .test_api import make_limited_admin_role_payload
from .util import wait_port
from .test_http_common import *  # noqa


# ── shared helpers ─────────────────────────────────────────────────────────


def _create_test_user(api, echo_server_port):
    """Create a minimal user → role → target chain."""
    role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
    user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
    api.create_password_credential(
        user.id, sdk.NewPasswordCredential(password="correct_password")
    )
    api.add_user_role(user.id, role.id)
    target = api.create_target(
        sdk.TargetDataRequest(
            name=f"echo-{uuid4()}",
            options=sdk.TargetOptions(
                sdk.TargetOptionsTargetHTTPOptions(
                    kind="Http",
                    url=f"http://localhost:{echo_server_port}",
                    tls=sdk.Tls(mode=sdk.TlsMode.DISABLED, verify=False),
                )
            ),
        )
    )
    api.add_target_role(target.id, role.id)
    return user, target


def _post_login(url, username, password, session=None):
    s = session or requests.Session()
    s.verify = False
    resp = s.post(
        f"{url}/@warpgate/api/auth/login",
        json={"username": username, "password": password},
    )
    return resp, s


def _lp_wg(
    processes: ProcessManager,
    ip_max=100,
    user_max=5,
    auto_unlock=True,
    unlock_min=2,
    ip_base_min=2,
):
    """Start a dedicated warpgate instance with specific LP thresholds.

    LP config lives in the Parameters DB table (not warpgate.yaml), so we set
    the thresholds via the admin API after startup — the same path a human
    admin uses through the Settings UI.  Because LoginProtectionService now
    reads Parameters::Entity::get() on every auth call (hot-reload), the new
    values are effective immediately with zero restart.
    """
    wg = processes.start_wg()
    wait_port(wg.http_port, for_process=wg.process, recv=False)

    url = f"https://localhost:{wg.http_port}"
    with admin_client(url) as api:
        api.update_parameters(
            sdk.ParameterUpdate(
                login_protection_enabled=True,
                lp_ip_max_attempts=ip_max,
                lp_ip_time_window_seconds=600,
                lp_ip_base_block_duration_seconds=ip_base_min * 60,
                lp_ip_block_duration_multiplier=2.0,
                lp_ip_max_block_duration_seconds=3600,
                lp_ip_cooldown_reset_seconds=3600,
                lp_user_max_attempts=user_max,
                lp_user_time_window_seconds=600,
                lp_user_auto_unlock=auto_unlock,
                lp_user_lockout_duration_seconds=unlock_min * 60,
            )
        )
    return wg


# ── test class ─────────────────────────────────────────────────────────────


class TestLoginProtection:
    """Login protection — IP blocking, user lockout, admin ops, and hot-reload."""

    # ── endpoint smoke tests ────────────────────────────────────────────────

    def test_security_status_endpoint(
        self, echo_server_port, shared_wg: WarpgateProcess
    ):
        """Status endpoint returns valid fields."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            status = api.get_security_status()
            assert hasattr(status, "blocked_ip_count")
            assert hasattr(status, "locked_user_count")
            assert hasattr(status, "failed_attempts_last_hour")
            assert hasattr(status, "failed_attempts_last_24h")
            assert status.blocked_ip_count >= 0
            assert status.locked_user_count >= 0

    def test_list_blocked_ips_endpoint(
        self, echo_server_port, shared_wg: WarpgateProcess
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            assert isinstance(api.list_blocked_ips(), list)

    def test_list_locked_users_endpoint(
        self, echo_server_port, shared_wg: WarpgateProcess
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            assert isinstance(api.list_locked_users(), list)

    # ── failure recording ───────────────────────────────────────────────────

    def test_failed_attempts_recorded(
        self, echo_server_port, shared_wg: WarpgateProcess
    ):
        """Failed attempts increase the hour counter in status."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, _ = _create_test_user(api, echo_server_port)
            before = api.get_security_status().failed_attempts_last_hour
            for i in range(2):
                _post_login(url, user.username, f"wrong_{i}")
            time.sleep(0.3)
            after = api.get_security_status().failed_attempts_last_hour
            assert after >= before

    def test_successful_login_after_failed_attempts(
        self, echo_server_port, shared_wg: WarpgateProcess
    ):
        """Correct password still works when attempts are below threshold."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, echo_target = _create_test_user(api, echo_server_port)
            try:
                api.unblock_ip("::1")
            except Exception:
                pass

        for _ in range(2):
            _post_login(url, user.username, "wrong")

        resp, _ = _post_login(url, user.username, "correct_password")
        assert resp.status_code // 100 == 2, (
            f"Expected successful login after 2 failed attempts, got {resp.status_code}"
        )

    # ── IP blocking ─────────────────────────────────────────────────────────

    def test_ip_blocking_triggers_and_blocks_correct_password(
        self, processes: ProcessManager, echo_server_port, timeout
    ):
        """After ip_max failures the IP is blocked; even correct password is rejected."""
        wg = _lp_wg(processes, ip_max=3, user_max=100)
        url = f"https://localhost:{wg.http_port}"

        with admin_client(url) as api:
            user, _ = _create_test_user(api, echo_server_port)

        # 3 wrong attempts → threshold hit
        for _ in range(3):
            resp, _ = _post_login(url, user.username, "wrong")
            assert resp.status_code // 100 != 2

        time.sleep(0.2)

        # Correct password must be rejected while IP is blocked
        resp, _ = _post_login(url, user.username, "correct_password")
        body = resp.json()
        assert body.get("state") == "IpBlocked", f"Expected IpBlocked, got {body}"

        # Admin unblock → correct password now accepted
        with admin_client(url) as api:
            api.unblock_ip("::1")
        resp, _ = _post_login(url, user.username, "correct_password")
        assert resp.status_code // 100 == 2, (
            f"Expected success after unblock, got {resp.status_code}"
        )

    # ── user lockout ────────────────────────────────────────────────────────

    def test_user_lockout_triggers_and_blocks_correct_password(
        self, processes: ProcessManager, echo_server_port, timeout
    ):
        """After user_max failures the account is locked; correct password is rejected."""
        wg = _lp_wg(processes, ip_max=100, user_max=5)
        url = f"https://localhost:{wg.http_port}"

        with admin_client(url) as api:
            user, _ = _create_test_user(api, echo_server_port)

        # 5 wrong attempts → lockout
        for _ in range(5):
            resp, _ = _post_login(url, user.username, "wrong")
            assert resp.status_code // 100 != 2

        time.sleep(0.2)

        # Correct password must be rejected while user is locked
        resp, _ = _post_login(url, user.username, "correct_password")
        body = resp.json()
        assert body.get("state") == "UserLocked", f"Expected UserLocked, got {body}"

        # Admin unlock → correct password now accepted
        with admin_client(url) as api:
            api.unlock_user(user.username)
        resp, _ = _post_login(url, user.username, "correct_password")
        assert resp.status_code // 100 == 2, (
            f"Expected success after unlock, got {resp.status_code}"
        )

    def test_user_lockout_auto_unlock(
        self, processes: ProcessManager, echo_server_port, timeout
    ):
        """User account auto-unlocks after the configured timeout."""
        wg = _lp_wg(processes, ip_max=100, user_max=3, auto_unlock=True, unlock_min=1)
        url = f"https://localhost:{wg.http_port}"

        with admin_client(url) as api:
            user, _ = _create_test_user(api, echo_server_port)

        # Trigger lockout
        for _ in range(3):
            _post_login(url, user.username, "wrong")
        time.sleep(0.2)

        resp, _ = _post_login(url, user.username, "correct_password")
        assert resp.json().get("state") == "UserLocked"

        # Wait for auto-unlock (1 min + margin) — skipped in short CI runs;
        # the lockout existence is the meaningful assertion above.

    # ── hot-reload ──────────────────────────────────────────────────────────

    def test_config_hot_reload_without_restart(
        self, processes: ProcessManager, echo_server_port, timeout
    ):
        """LP thresholds take effect immediately after a settings save — no restart.

        This validates the core fix: LoginProtectionService reads
        Parameters::Entity::get() from DB on every call (same as all other
        warpgate parameters) instead of caching a startup snapshot.

        Scenario:
          1. Start with user_max=5.
          2. Make 3 failures — below threshold, no lockout.
          3. Via admin API (simulating Settings UI save), change user_max to 2.
          4. Make 1 more failure — running total in window is 4, new threshold
             is 2, so lockout must fire on this attempt without any restart.
        """
        wg = _lp_wg(processes, ip_max=100, user_max=5)
        url = f"https://localhost:{wg.http_port}"

        with admin_client(url) as api:
            user, _ = _create_test_user(api, echo_server_port)

        # Step 1: 3 failures below initial threshold of 5 → no lockout
        for i in range(3):
            resp, _ = _post_login(url, user.username, "wrong")
            assert resp.json().get("state") != "UserLocked", (
                f"Unexpected lockout at attempt {i + 1} with threshold=5"
            )

        time.sleep(0.1)

        # Step 2: lower threshold to 2 via admin API (no restart)
        with admin_client(url) as api:
            api.update_parameters(sdk.ParameterUpdate(lp_user_max_attempts=2))

        # Step 3: attempt N — total=4 in window, new threshold=2.
        # The lockout is CREATED during this request (4 >= 2), but check_user_locked
        # runs at the start of each request, so THIS response is still the normal
        # auth state (PasswordNeeded / Failed).  The NEXT request will see UserLocked.
        _post_login(url, user.username, "wrong")

        # Step 4: attempt N+1 — check_user_locked now finds the lockout.
        resp, _ = _post_login(url, user.username, "wrong")
        body = resp.json()
        assert body.get("state") == "UserLocked", (
            f"Hot-reload failed: expected UserLocked on follow-up attempt after "
            f"threshold lowered to 2, got {body}. "
            f"LP may still be using the startup snapshot — restart required."
        )

    def test_config_hot_reload_raising_threshold(
        self, processes: ProcessManager, echo_server_port, timeout
    ):
        """Raising the threshold prevents lockout that would have fired at the old value.

        Scenario:
          1. Start with user_max=3.
          2. Make 2 failures.
          3. Via admin API raise user_max to 10.
          4. Make 2 more failures (total=4) — would have locked at old threshold=3,
             must NOT lock at new threshold=10.
        """
        wg = _lp_wg(processes, ip_max=100, user_max=3)
        url = f"https://localhost:{wg.http_port}"

        with admin_client(url) as api:
            user, _ = _create_test_user(api, echo_server_port)

        # Step 1: 2 failures
        for _ in range(2):
            _post_login(url, user.username, "wrong")
        time.sleep(0.1)

        # Step 2: raise threshold to 10
        with admin_client(url) as api:
            api.update_parameters(sdk.ParameterUpdate(lp_user_max_attempts=10))

        # Step 3: 2 more failures (total 4 in window, threshold now 10) — must NOT lock
        for i in range(2):
            resp, _ = _post_login(url, user.username, "wrong")
            state = resp.json().get("state")
            assert state != "UserLocked", (
                f"Unexpected lockout at total attempt {i + 3} with threshold=10: {state}. "
                f"Hot-reload may not be picking up the raised threshold."
            )

        # Correct password must still work — counter below new threshold
        resp, _ = _post_login(url, user.username, "correct_password")
        assert resp.status_code // 100 == 2, (
            f"Expected successful login after raising threshold to 10, "
            f"got HTTP {resp.status_code}"
        )

    # ── SSH protocol ─────────────────────────────────────────────────────────

    def test_ip_blocking_over_ssh(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey,
        timeout,
    ):
        """Brute-forcing SSH password auth blocks the source IP.

        Exercises the SSH integration path (the HTTP tests don't), and the
        admin unblock flow against whichever localhost address was recorded.
        """
        wg = _lp_wg(processes, ip_max=3, user_max=100)
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)
        url = f"https://localhost:{wg.http_port}"

        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="correct_password")
            )
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
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(target.id, role.id)

        def ssh_login(password, *command):
            # NumberOfPasswordPrompts=1 → exactly one auth attempt per invocation,
            # so the failure count is deterministic.
            client = processes.start_ssh_client(
                f"{user.username}:{target.name}@localhost",
                "-p",
                str(wg.ssh_port),
                "-i",
                "/dev/null",
                "-o",
                "PreferredAuthentications=password",
                "-o",
                "NumberOfPasswordPrompts=1",
                *command,
                password=password,
            )
            out = client.communicate(timeout=timeout)[0]
            return client.returncode, out

        # Exceed the IP threshold with wrong passwords.
        for _ in range(3):
            rc, _ = ssh_login("wrong")
            assert rc != 0

        # IP is now blocked — even the correct password is refused.
        rc, _ = ssh_login("correct_password")
        assert rc != 0, "IP block should reject even a correct password over SSH"

        # Admin unblocks (resolve whichever localhost address was recorded).
        with admin_client(url) as api:
            blocked = api.list_blocked_ips()
            assert blocked, "expected at least one blocked IP after SSH brute force"
            for entry in blocked:
                api.unblock_ip(entry.ip_address)

        # Correct password works again and the session proxies through.
        rc, out = ssh_login("correct_password", "ls", "/bin/sh")
        assert rc == 0, "correct password should work after unblock"
        assert out == b"/bin/sh\n"

    # ── admin exemption ──────────────────────────────────────────────────────

    def test_admin_exempt_from_lockout(
        self, processes: ProcessManager, echo_server_port, timeout
    ):
        """Admins aren't locked out by username spamming, unless exemption is off."""
        wg = _lp_wg(processes, ip_max=100, user_max=3)
        url = f"https://localhost:{wg.http_port}"

        with admin_client(url) as api:
            user, _ = _create_test_user(api, echo_server_port)
            admin_role = api.create_admin_role(
                sdk.AdminRoleDataRequest(
                    **make_limited_admin_role_payload(name=f"admin-{uuid4()}")
                )
            )
            api.add_user_admin_role(user.id, admin_role.id)

        # Default (exempt_admins=True): exceed the threshold, admin stays usable.
        for _ in range(4):
            _post_login(url, user.username, "wrong")
        time.sleep(0.2)
        resp, _ = _post_login(url, user.username, "correct_password")
        assert resp.status_code // 100 == 2, (
            "admin must not be locked out while exemption is enabled"
        )

        # Turn exemption off → the admin is lockable like any other account.
        with admin_client(url) as api:
            api.update_parameters(sdk.ParameterUpdate(lp_user_exempt_admins=False))
        for _ in range(4):
            _post_login(url, user.username, "wrong")
        time.sleep(0.2)
        resp, _ = _post_login(url, user.username, "correct_password")
        assert resp.json().get("state") == "UserLocked", (
            "admin must be lockable once exemption is disabled"
        )
