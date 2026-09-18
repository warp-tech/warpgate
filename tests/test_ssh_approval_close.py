from pathlib import Path
import os
import subprocess
import tempfile
import time
from uuid import uuid4

import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .approval_util import wait_for_pending_approval
from .util import wait_port


class Test:
    def test_client_disconnect_clears_the_pending_approval(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        shared_wg: WarpgateProcess,
    ):
        # The hold runs off the session event loop, so russh keeps reading the
        # socket and notices the client leaving. Without that the request would
        # sit in the admin inbox until the approval window elapsed, and approving
        # it would stamp a grace-period bypass for a client that had gone.
        url, user, target = _held_ssh_target(processes, wg_c_ed25519_pubkey, shared_wg)
        client = _connect_held(processes, shared_wg, user, target)

        with admin_client(url) as api:
            wait_for_pending_approval(api, target.name, user.username)

        client.kill()
        client.wait(timeout=10)
        _assert_request_disappears(url, user, target)

    def test_target_is_not_reached_before_approval(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        # The whole point of the gate: nothing may reach the target until an
        # administrator says so. The hold runs off the session event loop, so
        # this is the assertion that keeps `connect_remote` behind it.
        url, user, target = _held_ssh_target(processes, wg_c_ed25519_pubkey, shared_wg)
        client = _connect_held(
            processes, shared_wg, user, target, "echo", "gate-marker"
        )

        with admin_client(url) as api:
            approval = wait_for_pending_approval(api, target.name, user.username)

            # A connection that slipped past the gate would have run the command
            # and exited by now.
            time.sleep(2)
            assert client.poll() is None, "session connected before approval"

            api.approve_session(
                approval.id,
                sdk.ApproveSessionRequest(scope=sdk.ApprovalScope.ONCE, target=approval.target),
            )

        assert b"gate-marker" in client.communicate(timeout=timeout)[0]

    def test_a_second_channel_shares_the_approved_connection(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        # One transport, two channels, one gate: the exec that opened the gate
        # and an SFTP subsystem opened over the same multiplexed connection
        # while the hold is still on. The remote client queues channel
        # operations until the target is dialed, so neither channel may reach
        # the target early, neither may be answered before it runs, and the
        # second one shares the first one's approval instead of asking again.
        url, user, target = _held_ssh_target(processes, wg_c_ed25519_pubkey, shared_wg)
        with tempfile.TemporaryDirectory() as tmp:
            control_path = os.path.join(tmp, "mux")
            master = _connect_held(
                processes,
                shared_wg,
                user,
                target,
                "echo gate-marker; sleep 30",
                options=[
                    "-o",
                    "ControlMaster=yes",
                    "-o",
                    f"ControlPath={control_path}",
                ],
            )
            # The master listens on the control socket as soon as it has
            # authenticated, which is well before the gate resolves.
            _wait_for_control_socket(control_path, master)
            sftp = processes.start(
                [
                    "sftp",
                    "-o",
                    f"ControlPath={control_path}",
                    "-o",
                    "ControlMaster=no",
                    f"{user.username}#{target.name}@localhost:/etc/passwd",
                    tmp,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            with admin_client(url) as api:
                approval = wait_for_pending_approval(api, target.name, user.username)

                time.sleep(2)
                assert master.poll() is None, "the exec channel ran before approval"
                assert sftp.poll() is None, "the subsystem channel ran before approval"
                held = [
                    a.id
                    for a in api.get_session_approvals()
                    if a.target == target.name and a.username == user.username
                ]
                assert held == [approval.id], "the second channel was gated separately"

                api.approve_session(
                    approval.id,
                    sdk.ApproveSessionRequest(scope=sdk.ApprovalScope.ONCE, target=approval.target),
                )

            assert sftp.wait(timeout=timeout) == 0, sftp.stderr.read()
            assert "root:x:0:0:root" in open(os.path.join(tmp, "passwd")).read()

            master.terminate()
            assert b"gate-marker" in master.communicate(timeout=timeout)[0]

    # The ungated case is the control: it pins that a plain exec is recorded
    # at all, so the gated case fails for the gate and nothing else.
    @pytest.mark.parametrize("gated", [False, True])
    def test_an_exec_through_the_gate_is_recorded(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
        gated,
    ):
        # The recording is started by the exec request, which arrives while the
        # gate still holds the session — before a target session exists to
        # record under. Approval must not lose it: a bastion that records
        # shells but not the commands run through an approved gate has a hole
        # exactly where the audit trail matters most.
        url, user, target = _held_ssh_target(
            processes, wg_c_ed25519_pubkey, shared_wg, require_approval=gated
        )
        client = _connect_held(processes, shared_wg, user, target, "echo", "gate-marker")

        if gated:
            with admin_client(url) as api:
                approval = wait_for_pending_approval(api, target.name, user.username)
                api.approve_session(
                    approval.id,
                    sdk.ApproveSessionRequest(scope=sdk.ApprovalScope.ONCE, target=approval.target),
                )
        assert b"gate-marker" in client.communicate(timeout=timeout)[0]

        with admin_client(url) as api:
            for _ in range(20):
                recordings = [
                    rec
                    for session in api.get_sessions().items
                    if session.username == user.username
                    for rec in api.get_session_recordings(session.id)
                    if rec.kind == sdk.RecordingKind.TERMINAL
                ]
                if recordings:
                    return
                time.sleep(0.25)
        raise AssertionError("the exec session was never recorded")

    def test_many_channels_on_a_held_connection(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        # An automation client (Ansible with forks, a mux'd batch job) opens
        # its sessions as fast as the transport allows, all of them landing
        # while the gate is still held. Every one of them must complete once
        # the approval lands — the session loop may not wedge on the count.
        url, user, target = _held_ssh_target(processes, wg_c_ed25519_pubkey, shared_wg)
        with tempfile.TemporaryDirectory() as tmp:
            control_path = os.path.join(tmp, "mux")
            master = _connect_held(
                processes,
                shared_wg,
                user,
                target,
                "sleep 60",
                options=["-o", "ControlMaster=yes", "-o", f"ControlPath={control_path}"],
            )
            _wait_for_control_socket(control_path, master)
            # Under the target sshd's default MaxSessions the exact per-channel
            # success is capped, so this asserts the node-level property: the
            # burst must not take the whole node down. The PR's reentrant
            # per-channel wait recurses one stack frame deeper per queued open
            # and overflows the worker stack around the sixth.
            clients = [
                processes.start(
                    [
                        "ssh",
                        "-o",
                        f"ControlPath={control_path}",
                        "-o",
                        "ControlMaster=no",
                        f"{user.username}#{target.name}@localhost",
                        "true",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                for _ in range(8)
            ]

            with admin_client(url) as api:
                approval = wait_for_pending_approval(api, target.name, user.username)
                api.approve_session(
                    approval.id,
                    sdk.ApproveSessionRequest(scope=sdk.ApprovalScope.ONCE, target=approval.target),
                )

            for c in clients:
                c.wait(timeout=timeout)
            master.terminate()

            # The node has to still be serving after the burst.
            with admin_client(url) as api:
                api.get_session_approvals()

    def test_a_held_session_outlives_the_inactivity_timeout(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
    ):
        # A session waiting for an administrator sends nothing, so every idle
        # timer sees it as abandoned — the session loop's, and the transport's
        # underneath it. Left that way the inactivity timeout silently caps the
        # approval window: with the defaults an administrator has five minutes
        # to answer a gate configured to wait ten, and the user is disconnected
        # mid-decision.
        wg = processes.start_wg(config_patch={"ssh": {"inactivity_timeout": "3s"}})
        wait_port(wg.http_port, recv=False)
        wait_port(wg.ssh_port)
        url, user, target = _held_ssh_target(processes, wg_c_ed25519_pubkey, wg)
        client = _connect_held(processes, wg, user, target, "echo", "gate-marker")

        with admin_client(url) as api:
            approval = wait_for_pending_approval(api, target.name, user.username)

            # Past the session loop's timer several times over, and past the
            # transport's, which allowed only a few seconds of slack on top.
            time.sleep(16)
            assert client.poll() is None, "the held session was dropped as idle"
            assert [
                a for a in api.get_session_approvals() if a.id == approval.id
            ], "the request was closed while it was still waiting"

            api.approve_session(
                approval.id,
                sdk.ApproveSessionRequest(scope=sdk.ApprovalScope.ONCE, target=approval.target),
            )

        assert b"gate-marker" in client.communicate(timeout=timeout)[0]

    def test_admin_can_close_a_session_waiting_for_approval(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        shared_wg: WarpgateProcess,
    ):
        # The close command arrives on the session-handle channel, which is
        # independent of the connection — so an administrator can get rid of a
        # held session without resolving it or waiting out the whole window.
        url, user, target = _held_ssh_target(processes, wg_c_ed25519_pubkey, shared_wg)
        client = _connect_held(processes, shared_wg, user, target)

        with admin_client(url) as api:
            approval = wait_for_pending_approval(api, target.name, user.username)
            api.close_session(approval.id)

        _assert_request_disappears(url, user, target)
        assert client.wait(timeout=10) != 0


def _held_ssh_target(processes, wg_c_ed25519_pubkey, shared_wg, require_approval=True):
    """A public-key user and an SSH target, gated by JIT admin approval by default."""
    ssh_port = processes.start_ssh_server(trusted_keys=[wg_c_ed25519_pubkey.read_text()])
    wait_port(ssh_port)

    url = f"https://localhost:{shared_wg.http_port}"
    with admin_client(url) as api:
        role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        # Public key rather than password: sshpass retries on its own, which
        # shows up as spurious failed-login attempts under a loaded suite.
        api.create_public_key_credential(
            user.id,
            sdk.NewPublicKeyCredential(
                label="Public Key",
                openssh_public_key=open("ssh-keys/id_ed25519.pub").read().strip(),
            ),
        )
        api.add_user_role(user.id, role.id)
        target = api.create_target(
            sdk.TargetDataRequest(
                name=f"ssh-{uuid4()}",
                require_approval=require_approval,
                ticket_requests_disabled=False,
                ticket_require_approval=False,
                options=sdk.TargetOptions(
                    sdk.TargetOptionsTargetSSHOptions(
                        kind="Ssh",
                        allow_insecure_algos=False,
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
    return url, user, target


def _connect_held(processes, shared_wg, user, target, *command, options=()):
    """Start ssh; it authenticates, then waits for the approval."""
    return processes.start_ssh_client(
        "-p",
        str(shared_wg.ssh_port),
        "-o",
        "IdentityFile=ssh-keys/id_ed25519",
        *options,
        f"{user.username}#{target.name}@localhost",
        *command,
        stderr=subprocess.PIPE,
    )


def _wait_for_control_socket(path, client, deadline=15):
    for _ in range(deadline * 10):
        if os.path.exists(path):
            return
        assert client.poll() is None, "the client exited before multiplexing"
        time.sleep(0.1)
    raise AssertionError("the multiplexing master never opened its control socket")


def _assert_request_disappears(url, user, target):
    """The request must clear on its own — no admin decision, and well inside
    the approval window."""
    with admin_client(url) as api:
        for _ in range(40):
            pending = [
                a
                for a in api.get_session_approvals()
                if a.target == target.name and a.username == user.username
            ]
            if not pending:
                return
            time.sleep(0.25)
    raise AssertionError("approval request outlived the session")
