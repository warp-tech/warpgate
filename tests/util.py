import logging
import os
import requests
import socket
import subprocess
import threading
import time


last_port = 1234

mysql_client_ssl_opt = "--ssl"
mysql_client_opts = []
if "GITHUB_ACTION" in os.environ:
    # Github uses MySQL instead of MariaDB
    mysql_client_ssl_opt = "--ssl-mode=REQUIRED"
    mysql_client_opts = ["--enable-cleartext-plugin"]


def alloc_port():
    global last_port
    last_port += 1
    return last_port


def _wait_timeout(fn, msg, timeout=120):
    t = threading.Thread(target=fn, daemon=True)
    t.start()
    t.join(timeout=timeout)
    if t.is_alive():
        raise Exception(msg)


def wait_port(port, recv=True, timeout=120, for_process: subprocess.Popen = None):
    logging.debug(f"Waiting for port {port}")

    data = b""

    def wait():
        nonlocal data
        while True:
            try:
                s = socket.create_connection(("localhost", port), timeout=5)
                if recv:
                    s.settimeout(5)
                    while True:
                        try:
                            data = s.recv(100)
                            if data:
                                break
                        except socket.timeout:
                            break
                else:
                    data = b""
                s.close()
                logging.debug(f"Port {port} is up")
                return data
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
    return data


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
