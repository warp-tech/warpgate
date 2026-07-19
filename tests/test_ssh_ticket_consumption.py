"""A ticket is spent by authenticating with it, not by reaching a target.

Consumption happens after the administrator-approval gate so a denied session
doesn't burn a single-use ticket — which means a session that authenticates but
never opens a channel (`ssh -N`) has to be charged at teardown instead. Without
that, a one-use ticket is reusable without limit.
"""

import subprocess
import time
from pathlib import Path
from uuid import uuid4

from .api_client import admin_client, sdk
from .approval_util import wait_for_pending_approval
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port


def _ssh_target(processes, wg_c_ed25519_pubkey, shared_wg, require_approval=False):
    ssh_port = processes.start_ssh_server(
        trusted_keys=[wg_c_ed25519_pubkey.read_text()]
    )
    wait_port(ssh_port)

    url = f"https://localhost:{shared_wg.http_port}"
    with admin_client(url) as api:
        role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        api.add_user_role(user.id, role.id)
        target = api.create_target(
            sdk.TargetDataRequest(
                name=f"ssh-{uuid4()}",
                require_approval=require_approval,
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
    return url, user, target


def _single_use_ticket(url, user, target):
    """Returns (ticket_id, secret) for a ticket good for exactly one session."""
    with admin_client(url) as api:
        created = api.create_ticket(
            sdk.CreateTicketRequest(
                target_name=target.name,
                username=user.username,
                number_of_uses=1,
            )
        )
    return created.ticket.id, created.secret


def _uses_left(url, ticket_id):
    with admin_client(url) as api:
        for ticket in api.get_tickets():
            if ticket.id == ticket_id:
                return ticket.uses_left
    return None


class Test:
    def test_channel_less_session_spends_the_ticket(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        shared_wg: WarpgateProcess,
    ):
        # `ssh -N` authenticates and opens no channel, so it never reaches the
        # code that dials the target. The ticket must still be charged.
        url, user, target = _ssh_target(processes, wg_c_ed25519_pubkey, shared_wg)
        ticket_id, secret = _single_use_ticket(url, user, target)
        assert _uses_left(url, ticket_id) == 1

        wait_port(shared_wg.ssh_port)
        client = processes.start_ssh_client(
            "-N",
            f"ticket-{secret}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            "-o",
            "IdentityFile=/dev/null",
            stderr=subprocess.PIPE,
        )

        # Give the authentication time to land, then leave without ever
        # opening a channel.
        time.sleep(3)
        client.kill()
        client.wait(timeout=10)

        for _ in range(40):
            if _uses_left(url, ticket_id) == 0:
                break
            time.sleep(0.25)
        assert _uses_left(url, ticket_id) == 0, (
            "a ticket that authenticated a session must be spent"
        )

    def test_denied_session_does_not_spend_the_ticket(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        shared_wg: WarpgateProcess,
    ):
        # The reason consumption moved past the gate: an administrator saying
        # no must not cost the user their single-use ticket.
        url, user, target = _ssh_target(
            processes, wg_c_ed25519_pubkey, shared_wg, require_approval=True
        )
        ticket_id, secret = _single_use_ticket(url, user, target)

        wait_port(shared_wg.ssh_port)
        client = processes.start_ssh_client(
            f"ticket-{secret}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            "-o",
            "IdentityFile=/dev/null",
            "echo",
            "should-not-run",
            stderr=subprocess.PIPE,
        )

        with admin_client(url) as api:
            approval = wait_for_pending_approval(api, target.name, user.username)
            api.reject_session(approval.id)

        client.wait(timeout=30)
        assert _uses_left(url, ticket_id) == 1, "a denied session must not burn a ticket"
