import subprocess
from uuid import uuid4

from .api_client import admin_client, sdk
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
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id)

            targets = []
            # Separate targets to cover both the plaintext-over-TLS and the
            # RSA-encrypted caching_sha2_password full authentication paths
            for tls_mode in (sdk.TlsMode.PREFERRED, sdk.TlsMode.DISABLED):
                target = api.create_target(
                    sdk.TargetDataRequest(
                        name=f"mysql-{uuid4()}",
                        options=sdk.TargetOptions(
                            sdk.TargetOptionsTargetMySqlOptions(
                                kind="MySql",
                                host="localhost",
                                port=db_port,
                                username="root",
                                auth=sdk.DatabaseTargetAuth(
                                    sdk.DatabaseTargetAuthDatabaseTargetPasswordAuth(
                                        kind="Password",
                                        password="123",
                                    )
                                ),
                                tls=sdk.Tls(
                                    mode=tls_mode,
                                    verify=False,
                                ),
                            )
                        ),
                    )
                )
                api.add_target_role(target.id, role.id)
                targets.append(target)

        wait_mysql_port(db_port)
        wait_port(shared_wg.mysql_port, recv=False)

        for target in targets:
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
            # The empty-string first column produces a row packet starting
            # with 0x00; the following query proves the result-set framing
            # doesn't mistake it for an OK packet and desync the session
            output = client.communicate(
                b"select '', 'marker1';\nshow schemas;\nselect 'marker2';",
                timeout=timeout,
            )[0]
            assert b"marker1" in output
            assert b"\ndb\n" in output
            assert b"marker2" in output
            assert client.returncode == 0

            client = processes.start(
                [
                    "mysql",
                    "--user",
                    f"{user.username}#{target.name}",
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
