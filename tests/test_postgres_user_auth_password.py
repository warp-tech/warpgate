import os
import subprocess
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import WarpgateProcess, ProcessManager
from .util import wait_port


class Test:
    def test(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        db_port = processes.start_postgres_server()
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id)
            target = api.create_target(sdk.TargetDataRequest(
                name=f"postgres-{uuid4()}",
                options=sdk.TargetOptions(sdk.TargetOptionsTargetPostgresOptions(
                    kind="Postgres",
                    host="localhost",
                    port=db_port,
                    username="user",
                    password="123",
                    tls=sdk.Tls(
                        mode=sdk.TlsMode.PREFERRED,
                        verify=False,
                    ),
                )),
            ))
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
        assert b"tbl" in client.communicate(b"\\dt\n", timeout=timeout)[0]
        assert client.returncode == 0

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
            env={"PGPASSWORD": "wrong", **os.environ},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        client.communicate(b"\\dt\n", timeout=timeout)
        assert client.returncode != 0
