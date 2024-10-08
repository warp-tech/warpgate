import os
import subprocess
from uuid import uuid4

from .api_client import (
    api_admin_session,
    api_create_target,
    api_create_user,
    api_create_role,
    api_add_role_to_user,
    api_add_role_to_target,
)
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
        with api_admin_session(url) as session:
            role = api_create_role(url, session, {"name": f"role-{uuid4()}"})
            user = api_create_user(
                url,
                session,
                {
                    "username": f"user-{uuid4()}",
                    "credentials": [
                        {
                            "kind": "Password",
                            "hash": "123",
                        },
                    ],
                },
            )
            api_add_role_to_user(url, session, user["id"], role["id"])
            target = api_create_target(
                url,
                session,
                {
                    "name": f"posgresq-{uuid4()}",
                    "options": {
                        "kind": "Postgres",
                        "host": "localhost",
                        "port": db_port,
                        "username": "user",
                        "password": "123",
                        "tls": {
                            "mode": "Preferred",
                            "verify": False,
                        },
                    },
                },
            )
            api_add_role_to_target(url, session, target["id"], role["id"])

        wait_port(db_port, recv=False)
        wait_port(shared_wg.postgres_port, recv=False)

        client = processes.start(
            [
                "psql",
                "--user",
                f"{user['username']}#{target['name']}",
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
                f"{user['username']}#{target['name']}",
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
