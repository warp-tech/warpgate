import logging
import socket
import threading
import time


last_port = 1234


def alloc_port():
    global last_port
    last_port += 1
    return last_port


def wait_port(port, recv=True):
    logging.debug(f'Waiting for port {port}')

    data = b''

    def wait():
        nonlocal data
        while True:
            try:
                s = socket.create_connection(('localhost', port), timeout=5)
                if recv:
                    data = s.recv(100)
                else:
                    data = b''
                s.close()
                logging.debug(f'Port {port} is up')
                return data
            except socket.error:
                time.sleep(0.1)
                continue

    t = threading.Thread(target=wait, daemon=True)
    t.start()
    t.join(timeout=5)
    if t.is_alive():
        raise Exception(f'Port {port} is not up')
    return data
