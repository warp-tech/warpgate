import os
import subprocess
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import WarpgateProcess, ProcessManager
from .util import wait_port, wait_mysql_port, mysql_client_ssl_opt, mysql_client_opts


def _setup(api, options):
    role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
    user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
    api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
    api.add_user_role(user.id, role.id)
    target = api.create_target(
        sdk.TargetDataRequest(
            name=f"db-{uuid4()}",
            require_approval=False,
            ticket_requests_disabled=False,
            ticket_require_approval=False,
            options=sdk.TargetOptions(options),
        )
    )
    api.add_target_role(target.id, role.id)
    return user, target


PASSWORD_AUTH = sdk.DatabaseTargetAuth(
    sdk.DatabaseTargetAuthDatabaseTargetPasswordAuth(kind="Password", password="123")
)
# TLS wanted but not available: the connection falls back to plaintext and
# the stored password must then not be sent in a recoverable form
PREFERRED = sdk.Tls(mode=sdk.TlsMode.PREFERRED, verify=False)


class TestPostgres:
    def test(self, processes: ProcessManager, timeout, shared_wg: WarpgateProcess):
        db_port = processes.start_postgres_server(host_auth_method="password")
        with admin_client(f"https://localhost:{shared_wg.http_port}") as api:
            user, target = _setup(
                api,
                sdk.TargetOptionsTargetPostgresOptions(
                    kind="Postgres",
                    protocol_version=sdk.PostgresProtocolVersion.ENUM_3_DOT_2,
                    host="localhost",
                    port=db_port,
                    username="user",
                    auth=PASSWORD_AUTH,
                    tls=PREFERRED,
                ),
            )

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
        client.communicate(b"\\dt\n", timeout=timeout)
        assert client.returncode != 0


class TestMySql:
    def test(self, processes: ProcessManager, timeout, shared_wg: WarpgateProcess):
        db_port = processes.start_mysql_server("--tls-version=")
        with admin_client(f"https://localhost:{shared_wg.http_port}") as api:
            user, target = _setup(
                api,
                sdk.TargetOptionsTargetMySqlOptions(
                    kind="MySql",
                    host="localhost",
                    port=db_port,
                    username="root",
                    auth=PASSWORD_AUTH,
                    tls=PREFERRED,
                ),
            )

        wait_mysql_port(db_port)
        wait_port(shared_wg.mysql_port, recv=False)

        client = processes.start(
            [
                "mysql",
                "--user",
                f"{user.username}#{target.name}",
                "-p123",
                "--host",
                "127.0.0.1",
                "--port",
                str(shared_wg.mysql_port),
                *mysql_client_opts,
                mysql_client_ssl_opt,
                "db",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        client.communicate(b"show schemas;", timeout=timeout)
        assert client.returncode != 0
