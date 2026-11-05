import ssl
from uuid import uuid4

import oracledb
import pytest

from .api_client import admin_client, sdk
from .conftest import WarpgateProcess, ProcessManager
from .util import wait_port

# The service of the pluggable database in the target container. Warpgate picks
# the target by it, so only one Oracle target may use it.
SERVICE_NAME = "FREEPDB1"


class Test:
    def test(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        db_port = processes.start_oracle_server()
        wait_port(db_port, recv=False)
        # The Oracle login verifier is derived when a password credential is
        # created, and only while the Oracle listener is enabled.
        wait_port(shared_wg.oracle_port, recv=False)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id)
            user_without_role = api.create_user(
                sdk.CreateUserRequest(username=f"user-{uuid4()}")
            )
            api.create_password_credential(
                user_without_role.id, sdk.NewPasswordCredential(password="123")
            )
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"oracle-{uuid4()}",
                    require_approval=False,
                    ticket_requests_disabled=False,
                    ticket_require_approval=False,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetOracleOptions(
                            kind="Oracle",
                            host="localhost",
                            port=db_port,
                            username="wguser",
                            auth=sdk.DatabaseTargetAuth(
                                sdk.DatabaseTargetAuthDatabaseTargetPasswordAuth(
                                    kind="Password",
                                    password="123",
                                )
                            ),
                            tls=sdk.Tls(
                                mode=sdk.TlsMode.DISABLED,
                                verify=False,
                            ),
                            service_name=SERVICE_NAME,
                        )
                    ),
                )
            )
            api.add_target_role(target.id, role.id)

        dsn = f"localhost:{shared_wg.oracle_port}/{SERVICE_NAME}"

        # Plain TCP
        with oracledb.connect(
            user=user.username,
            password="123",
            dsn=dsn,
            tcp_connect_timeout=timeout,
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute("select user from dual")
                assert cursor.fetchone() == ("WGUSER",)

        # TCPS on the same port, without verifying Warpgate's certificate
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        with oracledb.connect(
            user=user.username,
            password="123",
            host="localhost",
            port=shared_wg.oracle_port,
            service_name=SERVICE_NAME,
            protocol="tcps",
            ssl_context=ssl_context,
            ssl_server_dn_match=False,
            tcp_connect_timeout=timeout,
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute("select user from dual")
                assert cursor.fetchone() == ("WGUSER",)

        # Wrong password
        with pytest.raises(oracledb.DatabaseError):
            oracledb.connect(
                user=user.username,
                password="wrong",
                dsn=dsn,
                tcp_connect_timeout=timeout,
            )

        # Valid credentials, but no role granting access to the target
        with pytest.raises(oracledb.DatabaseError):
            oracledb.connect(
                user=user_without_role.username,
                password="123",
                dsn=dsn,
                tcp_connect_timeout=timeout,
            )
