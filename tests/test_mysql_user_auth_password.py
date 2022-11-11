import subprocess
import time
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
from .util import wait_port, wait_mysql_port, mysql_client_ssl_opt, mysql_client_opts


class Test:
    def test(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        db_port = processes.start_mysql_server()
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
                    "name": f"mysql-{uuid4()}",
                    "options": {
                        "kind": "MySql",
                        "host": "localhost",
                        "port": db_port,
                        "username": "root",
                        "password": "123",
                        "tls": {
                            "mode": "Disabled",
                            "verify": False,
                        },
                    },
                },
            )
            api_add_role_to_target(url, session, target["id"], role["id"])

        wait_mysql_port(db_port)
        wait_port(shared_wg.mysql_port, recv=False)

        time.sleep(5)
        client = processes.start(
            [
                "mysql",
                "--user",
                f"{user['username']}#{target['name']}",
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
        assert b"\ndb\n" in client.communicate(b"show schemas;", timeout=timeout)[0]
        assert client.returncode == 0

        client = processes.start(
            [
                "mysql",
                "--user",
                f"{user['username']}#{target['name']}",
                "-pwrong",
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
