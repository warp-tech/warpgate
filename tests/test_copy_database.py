import os
import signal
import subprocess
from pathlib import Path
from uuid import uuid4

import requests

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess, binary_path, cargo_root
from .util import wait_port


def _copy_database(config_path: Path, target_url: str) -> subprocess.CompletedProcess:
    """Runs `warpgate copy-database` against an existing config and waits for it."""
    return subprocess.run(
        [
            os.path.join(cargo_root, binary_path),
            "--config",
            str(config_path),
            "copy-database",
            target_url,
        ],
        cwd=cargo_root,
        env={
            **os.environ,
            "LLVM_PROFILE_FILE": f"{cargo_root}/target/llvm-cov-target/warpgate-%m.profraw",
            "WARPGATE_UNDER_TEST": "1",
            "RUST_LOG": "info",
        },
        capture_output=True,
        text=True,
        timeout=120,
    )


def _stop(node: WarpgateProcess):
    """Graceful shutdown, the way an operator would stop Warpgate before copying
    its database out from under it."""
    node.process.send_signal(signal.SIGINT)
    node.process.wait(timeout=30)


class TestCopyDatabase:
    def test_sqlite_to_postgres(
        self, processes: ProcessManager, timeout, echo_server_port
    ):
        wg = processes.start_wg()
        wait_port(wg.http_port, for_process=wg.process, recv=False, timeout=timeout)

        # Populate the SQLite instance with something of every shape the copy
        # has to carry: a user with a credential, a role, a target, and all
        # three kinds of role assignment.
        url = f"https://localhost:{wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
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
            admin_role = api.get_admin_roles()[0]
            api.add_user_admin_role(user.id, admin_role.id)

        _stop(wg)

        db_port = processes.start_postgres_server()
        postgres_url = f"postgres://user:123@localhost:{db_port}/db"

        copy = _copy_database(wg.config_path, postgres_url)
        assert copy.returncode == 0, f"copy-database failed:\n{copy.stderr}"

        # Same data directory and certificates, now pointed at PostgreSQL.
        copied = processes.start_wg(
            share_with=wg, config_patch={"database_url": postgres_url}
        )
        wait_port(
            copied.http_port, for_process=copied.process, recv=False, timeout=timeout
        )

        copied_url = f"https://localhost:{copied.http_port}"
        with admin_client(copied_url) as api:
            assert user.username in [u.username for u in api.get_users()]
            assert target.name in [t.name for t in api.get_targets()]
            assert role.name in [r.name for r in api.get_user_roles(user.id)]
            assert role.id in [r.id for r in api.get_target_roles(target.id)]
            assert admin_role.id in [r.id for r in api.get_user_admin_roles(user.id)]

        # The credential came across intact and still authenticates.
        session = requests.Session()
        session.verify = False
        response = session.post(
            f"{copied_url}/@warpgate/api/auth/login",
            json={"username": user.username, "password": "123"},
        )
        assert response.status_code // 100 == 2

        # And the copied database takes writes - role assignments in particular,
        # which used to depend on sequence state travelling with the rows.
        with admin_client(copied_url) as api:
            second_role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            api.add_user_role(user.id, second_role.id)
            assert second_role.name in [r.name for r in api.get_user_roles(user.id)]

        # Copying onto a database that already holds Warpgate data is refused
        # rather than merged into or overwritten.
        again = _copy_database(wg.config_path, postgres_url)
        assert again.returncode != 0
        assert "already contains" in again.stderr + again.stdout
