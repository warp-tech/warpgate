import logging
import os
import requests
import socket
import sqlite3
import subprocess
import threading
import time

import yaml


last_port = 1234

mysql_client_ssl_opt = "--ssl"
mysql_client_opts = []
if "GITHUB_ACTION" in os.environ:
    # Github uses MySQL instead of MariaDB
    mysql_client_ssl_opt = "--ssl-mode=REQUIRED"
    mysql_client_opts = ["--enable-cleartext-plugin"]


def alloc_port():
    """The next port nothing is listening on.

    It used to be `last_port += 1` with no check, so it handed out whatever
    number came next whether or not something already held it. Anything on the
    machine could own that port — another suite, a leftover process, an
    ephemeral port the kernel had just handed to a stub — and the caller only
    found out when its own `bind` raised `Address already in use`, some way
    further into a test that then failed for a reason unrelated to what it was
    testing. That was worth roughly one failure per run of the hostile-target
    suite.

    Probed the way the callers bind — dual-stack on `::`, `SO_REUSEADDR` — so a
    port that passes here is one they can take.
    """
    global last_port
    for _ in range(200):
        last_port += 1
        probe = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        try:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            probe.bind(("::", last_port))
        except OSError:
            continue
        finally:
            probe.close()
        return last_port
    raise RuntimeError(f"no free port found above {last_port - 200}")


def _wait_timeout(fn, msg, timeout=60):
    t = threading.Thread(target=fn, daemon=True)
    t.start()
    t.join(timeout=timeout)
    if t.is_alive():
        raise Exception(msg)


def wait_port(port, recv=True, timeout=60, for_process: subprocess.Popen = None, connect_timeout=5, read_timeout=5):
    logging.debug(f"Waiting for port {port}")

    def wait():
        while True:
            try:
                s = socket.create_connection(("localhost", port), timeout=connect_timeout)
                if recv:
                    s.settimeout(read_timeout)
                    if not s.recv(100):
                        raise Exception("Port is open but not responding")
                s.close()
                logging.debug(f"Port {port} is up")
                return
            except socket.error:
                if for_process:
                    try:
                        for_process.wait(timeout=0.1)
                        raise Exception("Process exited while waiting for port")
                    except subprocess.TimeoutExpired:
                        continue
                else:
                    time.sleep(0.1)

    _wait_timeout(wait, f"Port {port} is not up", timeout=timeout)


def wait_mysql_port(port):
    logging.debug(f"Waiting for MySQL port {port}")

    def wait():
        while True:
            try:
                subprocess.check_call(
                    f'mysql --user=root --password=123 --host=127.0.0.1 --port={port} --execute="show schemas;"',
                    shell=True,
                )
                logging.debug(f"Port {port} is up")
                break
            except subprocess.CalledProcessError:
                time.sleep(1)
                continue

    t = threading.Thread(target=wait, daemon=True)
    t.start()
    t.join(timeout=60)
    if t.is_alive():
        raise Exception(f"Port {port} is not up")


def open_wg_sqlite_db(config_path):
    """A read connection to a node's sqlite database. A sqlite: URL names a
    directory (relative to the config dir) that holds db.sqlite3."""
    config = yaml.safe_load(config_path.open())
    db_url = config["database_url"]
    assert db_url.startswith("sqlite:")
    db_file = config_path.parent / db_url.removeprefix("sqlite:") / "db.sqlite3"
    # busy timeout: the nodes write to the same file concurrently
    return sqlite3.connect(db_file, timeout=5)


def create_ticket(url, username, target_name):
    session = requests.Session()
    session.verify = False
    response = session.post(
        f"{url}/@warpgate/api/auth/login",
        json={
            "username": "admin",
            "password": "123",
        },
    )
    assert response.status_code // 100 == 2
    response = session.post(
        f"{url}/@warpgate/admin/api/tickets",
        json={
            "username": username,
            "target_name": target_name,
        },
    )
    assert response.status_code == 201
    return response.json()["secret"]
