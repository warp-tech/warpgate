import os
import subprocess
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import WarpgateProcess, ProcessManager
from .util import wait_port, wait_mysql_port, mysql_client_ssl_opt, mysql_client_opts

# Resolves only inside the SSH server container (see `start_ssh_server`), so a
# database connection to it can only succeed through the jump host.
HOST_BEHIND_JUMP_HOST = "host.docker.internal"


def setup_user_and_jump_host(processes: ProcessManager, api, wg_c_ed25519_pubkey):
    ssh_port = processes.start_ssh_server(
        trusted_keys=[wg_c_ed25519_pubkey.read_text()]
    )
    wait_port(ssh_port)

    role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
    user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
    api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
    api.add_user_role(user.id, role.id)

    # Deliberately not granted to the role: like SSH jump hosts, only the
    # final target is authorized
    jump_host = api.create_target(
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
                        sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                    ),
                )
            ),
        )
    )
    return user, role, jump_host


def create_mysql_target(api, role, host, port, jump_host_id):
    target = api.create_target(
        sdk.TargetDataRequest(
            name=f"mysql-{uuid4()}",
            require_approval=False,
            ticket_requests_disabled=False,
            ticket_require_approval=False,
            options=sdk.TargetOptions(
                sdk.TargetOptionsTargetMySqlOptions(
                    kind="MySql",
                    host=host,
                    port=port,
                    username="root",
                    auth=sdk.DatabaseTargetAuth(
                        sdk.DatabaseTargetAuthDatabaseTargetPasswordAuth(
                            kind="Password",
                            password="123",
                        )
                    ),
                    tls=sdk.Tls(mode=sdk.TlsMode.PREFERRED, verify=False),
                    jump_host=jump_host_id,
                )
            ),
        )
    )
    api.add_target_role(target.id, role.id)
    return target


def run_mysql(processes: ProcessManager, wg: WarpgateProcess, user, target, timeout):
    client = processes.start(
        [
            "mysql",
            "--user",
            f"{user.username}#{target.name}",
            "-p123",
            "--host",
            "127.0.0.1",
            "--port",
            str(wg.mysql_port),
            *mysql_client_opts,
            mysql_client_ssl_opt,
            "db",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    output = client.communicate(b"select 'jump-host-marker';", timeout=timeout)[0]
    return client.returncode, output


class TestMySqlJumpHost:
    def test_connects_through_jump_host(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
        wg_c_ed25519_pubkey,
    ):
        db_port = processes.start_mysql_server()
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, role, jump_host = setup_user_and_jump_host(
                processes, api, wg_c_ed25519_pubkey
            )
            target = create_mysql_target(
                api, role, HOST_BEHIND_JUMP_HOST, db_port, jump_host.id
            )

        wait_mysql_port(db_port)
        wait_port(shared_wg.mysql_port, recv=False)

        returncode, output = run_mysql(processes, shared_wg, user, target, timeout)
        assert b"jump-host-marker" in output
        assert returncode == 0

    def test_unresolvable_jump_host_does_not_connect_directly(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
        wg_c_ed25519_pubkey,
    ):
        db_port = processes.start_mysql_server()
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, role, _ = setup_user_and_jump_host(
                processes, api, wg_c_ed25519_pubkey
            )
            # The database is directly reachable, but the jump host doesn't
            # exist: the connection must fail instead of skipping the jump host
            target = create_mysql_target(api, role, "localhost", db_port, str(uuid4()))

        wait_mysql_port(db_port)
        wait_port(shared_wg.mysql_port, recv=False)

        returncode, output = run_mysql(processes, shared_wg, user, target, timeout)
        assert b"jump-host-marker" not in output
        assert returncode != 0


class TestPostgresJumpHost:
    def test_connects_through_jump_host(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
        wg_c_ed25519_pubkey,
    ):
        db_port = processes.start_postgres_server()
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, role, jump_host = setup_user_and_jump_host(
                processes, api, wg_c_ed25519_pubkey
            )
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"postgres-{uuid4()}",
                    require_approval=False,
                    ticket_requests_disabled=False,
                    ticket_require_approval=False,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetPostgresOptions(
                            kind="Postgres",
                            protocol_version=sdk.PostgresProtocolVersion.ENUM_3_DOT_2,
                            host=HOST_BEHIND_JUMP_HOST,
                            port=db_port,
                            username="user",
                            auth=sdk.DatabaseTargetAuth(
                                sdk.DatabaseTargetAuthDatabaseTargetPasswordAuth(
                                    kind="Password",
                                    password="123",
                                )
                            ),
                            tls=sdk.Tls(mode=sdk.TlsMode.PREFERRED, verify=False),
                            jump_host=jump_host.id,
                        )
                    ),
                )
            )
            api.add_target_role(target.id, role.id)

        wait_port(db_port, recv=False)
        wait_port(shared_wg.postgres_port, recv=False)

        client = processes.start(
            [
                "psql",
                "--user",
                f"{user.username}#{target.name}",
                "--host",
                "127.0.0.1",
                "--port",
                str(shared_wg.postgres_port),
                "db",
            ],
            env={"PGPASSWORD": "123", **os.environ},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        output = client.communicate(b"select 'jump-host-marker';\n", timeout=timeout)[0]
        assert b"jump-host-marker" in output
        assert client.returncode == 0
