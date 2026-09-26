import os
import time
from pathlib import Path
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port


def _uses_left(url, ticket_id):
    with admin_client(url) as api:
        for ticket in api.get_tickets():
            if ticket.id == ticket_id:
                return ticket.uses_left
    return None


class Test:
    def test(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
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
            api.add_user_role(user.id, role.id)
            ssh_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    require_approval=False,
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
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(
                                    kind="PublicKey"
                                )
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(ssh_target.id, role.id)

            secret = api.create_ticket(
                sdk.CreateTicketRequest(
                    target_name=ssh_target.name,
                    username=user.username,
                )
            ).secret

            ssh_client = processes.start_ssh_client(
                f"ticket-{secret}@localhost",
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
            assert ssh_client.communicate(timeout=timeout)[0] == b"/bin/sh\n"
            assert ssh_client.returncode == 0

    def test_publickey_offer_spends_ticket_exactly_once(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        # A standard SSH client sends an unsigned public-key offer first and
        # waits for PK_OK before sending the signed request. For a ticket
        # username the offer must be accepted without evaluating the ticket
        # (that would spend a use during the unauthenticated phase); only the
        # signed request that follows should authenticate and spend it, and
        # it must spend it exactly once.
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
            api.add_user_role(user.id, role.id)
            ssh_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    require_approval=False,
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
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(
                                    kind="PublicKey"
                                )
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(ssh_target.id, role.id)

            created = api.create_ticket(
                sdk.CreateTicketRequest(
                    target_name=ssh_target.name,
                    username=user.username,
                    number_of_uses=1,
                )
            )
            ticket_id, secret = created.ticket.id, created.secret
            assert _uses_left(url, ticket_id) == 1

            # Confirm the unsigned offer alone really doesn't spend the ticket
            # (this is what the final assertion below can't tell on its own,
            # since a successful login also goes through try_auth_lazy's
            # single-ticket-auth-per-session cache: if the offer path ever
            # spent it, the signed request would just hit that cache and this
            # test would still see uses_left == 0 at the end).
            #
            # Point -i directly at a bare *public* key file, with
            # IdentitiesOnly=yes and no agent available (SSH_AUTH_SOCK
            # unset). OpenSSH still loads the public half and sends the
            # unsigned offer for it ("Offering public key" under `ssh -v`),
            # and the ticket username makes Warpgate accept that offer
            # (PK_OK) without evaluating the ticket. But since ssh has
            # neither the matching private key locally nor an agent to sign
            # with, it cannot follow up with a signed request: the identity
            # is exhausted unsigned, no other method is offered, and the
            # overall login fails.
            offer_only_env = {**os.environ}
            offer_only_env.pop("SSH_AUTH_SOCK", None)
            offer_only_client = processes.start_ssh_client(
                f"ticket-{secret}@localhost",
                "-p",
                str(shared_wg.ssh_port),
                "-i",
                str(Path("ssh-keys/id_ed25519.pub")),
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "PreferredAuthentications=publickey",
                "ls",
                "/bin/sh",
                env=offer_only_env,
            )
            offer_only_client.communicate(timeout=timeout)
            assert offer_only_client.returncode != 0
            assert _uses_left(url, ticket_id) == 1, (
                "the unsigned public-key offer must not spend the ticket"
            )

            ssh_client = processes.start_ssh_client(
                f"ticket-{secret}@localhost",
                "-p",
                str(shared_wg.ssh_port),
                "-i",
                str(Path("ssh-keys/id_ed25519")),
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "PreferredAuthentications=publickey",
                "ls",
                "/bin/sh",
            )
            assert ssh_client.communicate(timeout=timeout)[0] == b"/bin/sh\n"
            assert ssh_client.returncode == 0

            for _ in range(40):
                if _uses_left(url, ticket_id) == 0:
                    break
                time.sleep(0.25)
            assert _uses_left(url, ticket_id) == 0, (
                "the signed request must spend the ticket exactly once;"
                " the unsigned offer must not spend it"
            )
