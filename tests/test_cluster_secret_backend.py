from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import ProcessManager, VaultInstance
from .test_secret_backend_vault import (
    _resolve_status,
    _stop_vault,
    _stop_wg,
    _vault_backend,
)
from .util import wait_port


class Test:
    def test_backend_created_on_one_node_is_used_by_another(
        self, processes: ProcessManager, timeout
    ):
        # Backends live in the shared database, so a node that never saw the
        # admin call still resolves references against it.
        ssh_port = processes.start_ssh_server(root_password="hunter2")
        wait_port(ssh_port)
        vault: VaultInstance = processes.start_vault()
        vault.kv_put("secret", "sshtarget", password="hunter2")

        node_a = processes.start_wg()
        wait_port(node_a.http_port, recv=False)
        node_b = processes.start_wg(share_with=node_a)
        wait_port(node_b.http_port, recv=False)
        wait_port(node_b.ssh_port, for_process=node_b.process)
        try:
            with admin_client(f"https://localhost:{node_a.http_port}") as api:
                api.create_secret_backend(
                    _vault_backend("vault-test", vault.addr, token=vault.root_token)
                )
                role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
                user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
                api.create_password_credential(
                    user.id, sdk.NewPasswordCredential(password="123")
                )
                api.add_user_role(user.id, role.id)
                target = api.create_target(
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
                                    sdk.SSHTargetAuthSshTargetPasswordAuth(
                                        kind="Password",
                                        password="vault://vault-test/secret/sshtarget#password",
                                    )
                                ),
                            )
                        ),
                    )
                )
                api.add_target_role(target.id, role.id)

            with admin_client(f"https://localhost:{node_b.http_port}") as api:
                assert [b.name for b in api.get_secret_backends()] == ["vault-test"]
                assert (
                    _resolve_status(api, "vault://vault-test/secret/sshtarget#password") == 204
                )

            ssh_client = processes.start_ssh_client(
                f"{user.username}:{target.name}@localhost",
                "-p",
                str(node_b.ssh_port),
                "-i",
                "/dev/null",
                "-o",
                "PreferredAuthentications=password",
                "echo",
                "hello",
                password="123",
            )
            output = ssh_client.communicate(timeout=timeout)[0]
            assert b"hello" in output
            assert ssh_client.returncode == 0
        finally:
            _stop_wg(node_b)
            _stop_wg(node_a)
            _stop_vault(vault)
