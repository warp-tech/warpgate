import base64
import hashlib
import json
import os
import signal
import subprocess
import time
from uuid import uuid4

import requests

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .util import (
    mysql_client_opts,
    mysql_client_ssl_opt,
    open_wg_sqlite_db,
    wait_mysql_port,
    wait_port,
)

# The password the test MySQL image accepts for root.
TARGET_PASSWORD = "123"
ENVELOPE_PREFIX = "wgenc:v1:"


def _key():
    return base64.b64encode(os.urandom(32)).decode()


def _fp(key):
    """The 8-hex-char fingerprint this key's envelopes carry."""
    return hashlib.sha256(base64.b64decode(key)).hexdigest()[:8]


def _stop_node(wg):
    """Graceful stop - deregisters the node from the cluster immediately."""
    wg.process.send_signal(signal.SIGINT)
    wg.process.wait(timeout=10)


def _key_state(config_path):
    """(current, retiring) key fingerprints of the cluster state machine."""
    with open_wg_sqlite_db(config_path) as db:
        return db.execute(
            "SELECT encryption_key_fp, retiring_key_fp FROM parameters"
        ).fetchone()


def _config_warnings(wg):
    """`config_warnings` from the gateway's /info, which the admin SDK doesn't cover."""
    response = requests.get(
        f"https://localhost:{wg.http_port}/@warpgate/api/info",
        headers={"X-Warpgate-Token": "token-value"},
        verify=False,
    )
    response.raise_for_status()
    return response.json().get("config_warnings") or []


def _stored_password(config_path, target_name):
    """The MySQL target password exactly as it sits in the database."""
    with open_wg_sqlite_db(config_path) as db:
        row = db.execute(
            "SELECT options FROM targets WHERE name = ?", (target_name,)
        ).fetchone()
    assert row is not None, f"target {target_name} is not in the database"
    return json.loads(row[0])["mysql"]["auth"]["password"]


def _snapshot_passwords(config_path):
    """The MySQL target password of every stored session snapshot."""
    with open_wg_sqlite_db(config_path) as db:
        rows = db.execute(
            "SELECT target_snapshot FROM target_sessions WHERE target_snapshot IS NOT NULL"
        ).fetchall()
    return [json.loads(row[0])["mysql"]["auth"]["password"] for row in rows]


def _provision(api, db_port):
    """A MySQL target Warpgate authenticates to with a password, plus a user for it."""
    role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
    user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
    api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
    api.add_user_role(user.id, role.id)
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
                            password=TARGET_PASSWORD,
                        )
                    ),
                    tls=sdk.Tls(mode=sdk.TlsMode.PREFERRED, verify=False),
                )
            ),
        )
    )
    api.add_target_role(target.id, role.id)
    return user, target


def _query(processes, wg, user, target, timeout):
    """(returncode, stdout) of a query run through Warpgate to the target."""
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
    output = client.communicate(b"select 'marker';", timeout=timeout)[0]
    return client.returncode, output


class Test:
    def test_target_password_is_encrypted_at_rest(
        self,
        processes: ProcessManager,
        timeout,
    ):
        db_port = processes.start_mysql_server()
        wg = processes.start_wg(env={"WARPGATE_ENCRYPTION_KEY": _key()})
        wait_port(wg.http_port, for_process=wg.process, recv=False)
        wait_mysql_port(db_port)
        wait_port(wg.mysql_port, recv=False)

        with admin_client(f"https://localhost:{wg.http_port}") as api:
            user, target = _provision(api, db_port)

            # The admin API must hand back the envelope: with a key configured, the
            # plaintext credential never crosses the API boundary.
            served = api.get_target(target.id).to_json()
            assert ENVELOPE_PREFIX in served

        assert _stored_password(wg.config_path, target.name).startswith(ENVELOPE_PREFIX)

        # ...and Warpgate can still authenticate to the target with it.
        returncode, output = _query(processes, wg, user, target, timeout)
        assert returncode == 0
        assert b"marker" in output

        # The session snapshot keeps the target for display but sheds its
        # credential - not even the envelope is copied out of the targets table.
        passwords = _snapshot_passwords(wg.config_path)
        assert passwords
        assert all(password == "" for password in passwords)

    def test_backfill_encrypts_existing_rows(
        self,
        processes: ProcessManager,
        timeout,
    ):
        db_port = processes.start_mysql_server()
        plain = processes.start_wg()
        wait_port(plain.http_port, for_process=plain.process, recv=False)
        wait_mysql_port(db_port)

        with admin_client(f"https://localhost:{plain.http_port}") as api:
            user, target = _provision(api, db_port)

        # No key configured: the credential is stored exactly as it was supplied.
        assert _stored_password(plain.config_path, target.name) == TARGET_PASSWORD

        # The keyless node must leave first: while it is registered, a keyed
        # node defers encryption rather than write envelopes a peer cannot read.
        _stop_node(plain)

        # A node that has a key converts the existing rows as it starts.
        encrypting = processes.start_wg(
            share_with=plain, env={"WARPGATE_ENCRYPTION_KEY": _key()}
        )
        wait_port(encrypting.http_port, for_process=encrypting.process, recv=False)
        wait_port(encrypting.mysql_port, recv=False)

        assert _stored_password(plain.config_path, target.name).startswith(
            ENVELOPE_PREFIX
        )

        returncode, output = _query(processes, encrypting, user, target, timeout)
        assert returncode == 0
        assert b"marker" in output

    def test_key_rotation_reencrypts_everything(
        self,
        processes: ProcessManager,
        timeout,
    ):
        db_port = processes.start_mysql_server()
        k1, k2 = _key(), _key()

        wg = processes.start_wg(env={"WARPGATE_ENCRYPTION_KEY": k1})
        wait_port(wg.http_port, for_process=wg.process, recv=False)
        wait_mysql_port(db_port)
        wait_port(wg.mysql_port, recv=False)

        with admin_client(f"https://localhost:{wg.http_port}") as api:
            user, target = _provision(api, db_port)

        assert _stored_password(wg.config_path, target.name).startswith(
            f"{ENVELOPE_PREFIX}{_fp(k1)}:"
        )
        assert _key_state(wg.config_path) == (_fp(k1), None)

        _stop_node(wg)
        rotated = processes.start_wg(
            share_with=wg,
            env={
                "WARPGATE_ENCRYPTION_KEY": k2,
                "WARPGATE_ENCRYPTION_KEY_OLD": k1,
            },
        )
        wait_port(rotated.http_port, for_process=rotated.process, recv=False)
        wait_port(rotated.mysql_port, recv=False)

        # Everything re-enciphered under the new key, rotation marked complete.
        assert _stored_password(wg.config_path, target.name).startswith(
            f"{ENVELOPE_PREFIX}{_fp(k2)}:"
        )
        assert _key_state(wg.config_path) == (_fp(k2), None)

        returncode, output = _query(processes, rotated, user, target, timeout)
        assert returncode == 0
        assert b"marker" in output

    def test_rotation_waits_for_every_live_node(
        self,
        processes: ProcessManager,
        timeout,
    ):
        db_port = processes.start_mysql_server()
        k1, k2 = _key(), _key()

        node1 = processes.start_wg(env={"WARPGATE_ENCRYPTION_KEY": k1})
        wait_port(node1.http_port, for_process=node1.process, recv=False)
        wait_mysql_port(db_port)
        wait_port(node1.mysql_port, recv=False)

        with admin_client(f"https://localhost:{node1.http_port}") as api:
            user, target = _provision(api, db_port)

        node2 = processes.start_wg(
            share_with=node1,
            env={
                "WARPGATE_ENCRYPTION_KEY": k2,
                "WARPGATE_ENCRYPTION_KEY_OLD": k1,
            },
        )
        wait_port(node2.http_port, for_process=node2.process, recv=False)
        wait_port(node2.mysql_port, recv=False)

        # The new key is committed as the cluster key, but rewriting must wait:
        # node1 cannot read it yet.
        assert _key_state(node1.config_path) == (_fp(k2), _fp(k1))
        assert _stored_password(node1.config_path, target.name).startswith(
            f"{ENVELOPE_PREFIX}{_fp(k1)}:"
        )

        # ...and the old-key node keeps serving in the meantime.
        returncode, output = _query(processes, node1, user, target, timeout)
        assert returncode == 0
        assert b"marker" in output

        _stop_node(node1)
        with open_wg_sqlite_db(node1.config_path) as db:
            # The graceful stop must deregister node1, or the rest of this test
            # would only pass by waiting out the heartbeat timeout.
            assert db.execute("SELECT count(*) FROM nodes").fetchone()[0] == 1

        # node2's deferred pass picks the rotation up within its retry interval.
        deadline = time.time() + 60
        while time.time() < deadline:
            if _key_state(node1.config_path) == (_fp(k2), None) and _stored_password(
                node1.config_path, target.name
            ).startswith(f"{ENVELOPE_PREFIX}{_fp(k2)}:"):
                break
            time.sleep(2)
        else:
            raise AssertionError("rotation did not complete after the old node left")

        returncode, output = _query(processes, node2, user, target, timeout)
        assert returncode == 0
        assert b"marker" in output

    def test_a_node_with_the_wrong_key_starts_and_reports_the_problem(
        self,
        processes: ProcessManager,
        timeout,
    ):
        db_port = processes.start_mysql_server()
        wg = processes.start_wg(env={"WARPGATE_ENCRYPTION_KEY": _key()})
        wait_port(wg.http_port, for_process=wg.process, recv=False)
        wait_mysql_port(db_port)
        wait_port(wg.mysql_port, recv=False)

        with admin_client(f"https://localhost:{wg.http_port}") as api:
            user, target = _provision(api, db_port)

        # Same database, a different key. Startup must still succeed, so that a
        # mislaid key is not a self-inflicted outage of the whole gateway.
        stranded = processes.start_wg(
            share_with=wg, env={"WARPGATE_ENCRYPTION_KEY": _key()}
        )
        wait_port(stranded.http_port, for_process=stranded.process, recv=False)
        wait_port(stranded.mysql_port, recv=False)

        warnings = _config_warnings(stranded)
        assert any("WARPGATE_ENCRYPTION_KEY" in w for w in warnings), warnings

        # The credential is unusable on that node...
        returncode, _ = _query(processes, stranded, user, target, timeout)
        assert returncode != 0

        # ...but it was not destroyed, and the node that has the key still works.
        assert _stored_password(wg.config_path, target.name).startswith(ENVELOPE_PREFIX)
        returncode, output = _query(processes, wg, user, target, timeout)
        assert returncode == 0
        assert b"marker" in output
