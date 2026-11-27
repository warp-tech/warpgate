import subprocess
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import (
    REDIS_AUTH_PASSWORD,
    REDIS_AUTH_USERNAME,
    WarpgateProcess,
    ProcessManager,
)
from .util import wait_port


class Test:
    def test(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        plain_port = processes.start_redis_server()
        auth_port = processes.start_redis_server(require_auth=True)
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id)

            targets = []

            # A target whose backend has no auth of its own.
            plain_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"redis-{uuid4()}",
                    require_approval=False,
                    ticket_requests_disabled=False,
                    ticket_require_approval=False,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetRedisOptions(
                            kind="Redis",
                            host="localhost",
                            port=plain_port,
                            tls=sdk.Tls(mode=sdk.TlsMode.DISABLED, verify=False),
                        )
                    ),
                )
            )
            api.add_target_role(plain_target.id, role.id)
            targets.append(plain_target)

            # A target whose backend requires its own ACL username+password -
            # exercises Warpgate authenticating *to the target*, on top of the
            # client authenticating to Warpgate above.
            auth_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"redis-auth-{uuid4()}",
                    require_approval=False,
                    ticket_requests_disabled=False,
                    ticket_require_approval=False,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetRedisOptions(
                            kind="Redis",
                            host="localhost",
                            port=auth_port,
                            username=REDIS_AUTH_USERNAME,
                            auth=sdk.RedisTargetAuth(
                                sdk.RedisTargetAuthDatabaseTargetPasswordAuth(
                                    kind="Password",
                                    password=REDIS_AUTH_PASSWORD,
                                )
                            ),
                            tls=sdk.Tls(mode=sdk.TlsMode.DISABLED, verify=False),
                        )
                    ),
                )
            )
            api.add_target_role(auth_target.id, role.id)
            targets.append(auth_target)

        wait_port(plain_port, recv=False)
        wait_port(auth_port, recv=False)
        wait_port(shared_wg.redis_port, recv=False)

        for target in targets:
            # Warpgate allows exactly one AUTH per connection (success or
            # failure both end the session), so each attempt below needs its
            # own fresh `redis-cli` process rather than reusing one.
            client = processes.start(
                ["redis-cli", "-p", str(shared_wg.redis_port)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )
            output = client.communicate(
                f"AUTH {user.username}#{target.name} 123\nPING\nSET marker hello-from-warpgate\nGET marker\n".encode(),
                timeout=timeout,
            )[0]
            assert b"PONG" in output
            assert b"hello-from-warpgate" in output

            client = processes.start(
                ["redis-cli", "-p", str(shared_wg.redis_port)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )
            output = client.communicate(
                f"AUTH {user.username}#{target.name} wrong\n".encode(),
                timeout=timeout,
            )[0]
            assert b"WRONGPASS" in output

        client = processes.start(
            ["redis-cli", "-p", str(shared_wg.redis_port)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        output = client.communicate(
            f"AUTH {user.username}#no-such-target 123\n".encode(),
            timeout=timeout,
        )[0]
        assert b"WRONGPASS" in output
