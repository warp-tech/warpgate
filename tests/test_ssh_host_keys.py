from .conftest import ProcessManager
from .test_ssh_proto import setup_user_and_target
from .util import wait_port


class Test:
    def test_generated_host_keys_serve_ssh(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
    ):
        # A node set up with no host key files to import generates its own
        # into the database, and the SSH listener has to come up on them.
        wg = processes.start_wg(import_host_keys=False)
        wait_port(wg.http_port, recv=False)
        wait_port(wg.ssh_port)
        user, target = setup_user_and_target(processes, wg, wg_c_ed25519_pubkey)

        client = processes.start_ssh_client(
            f"{user.username}:{target.name}@localhost",
            "-p",
            str(wg.ssh_port),
            "-o",
            "IdentityFile=ssh-keys/id_ed25519",
            "echo",
            "host-keys-ok",
        )
        assert client.communicate(timeout=timeout)[0] == b"host-keys-ok\n"
        assert client.returncode == 0
