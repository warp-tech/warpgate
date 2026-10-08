import base64
import json
import socket
import ssl
import tempfile
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .test_ssh_proto import common_args, setup_user_and_target
from .util import open_wg_sqlite_db, read_until, wait_port

CLUSTER_SNI = "warpgate-cluster.internal"


def _instance_ca(config_path):
    """The instance CA (cert PEM, key PEM) as a database reader sees it."""
    with open_wg_sqlite_db(config_path) as db:
        row = db.execute(
            "SELECT ca_certificate_pem, ca_private_key_pem FROM parameters"
        ).fetchone()
    assert row and row[0] and row[1], "instance CA missing"
    return row[0], row[1]


def _mint_peer_lookalike(ca_cert_pem, ca_key_pem):
    """A certificate shaped like a node identity, for a key no node has
    published. Signed by the real instance CA when a database reader can get
    at its key; when the key is enveloped (an encryption key is configured,
    e.g. via a `.env` dotenv picks up) the lookalike is self-signed, which the
    pin check must reject just the same."""
    key = ec.generate_private_key(ec.SECP384R1())
    if ca_key_pem.startswith("wgenc:"):
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rogue")])
        signer = key
    else:
        issuer = x509.load_pem_x509_certificate(ca_cert_pem.encode()).subject
        signer = serialization.load_pem_private_key(ca_key_pem.encode(), password=None)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CLUSTER_SNI)]))
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(CLUSTER_SNI)]), False)
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            False,
        )
        .sign(signer, hashes.SHA384())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def _peer_request(port, client_cert, identity, timeout):
    """Talks to the node the way a peer would (cluster SNI, optional client
    cert, forwarded identity header). Returns the HTTP status, or None when
    the node refused the connection at or right after the TLS handshake."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if client_cert:
        cert_pem, key_pem = client_cert
        with tempfile.NamedTemporaryFile(suffix=".pem") as f:
            f.write(cert_pem + key_pem)
            f.flush()
            ctx.load_cert_chain(f.name)
    request = (
        "GET /@warpgate/admin/api/sessions HTTP/1.1\r\n"
        f"Host: {CLUSTER_SNI}\r\n"
        f"X-Warpgate-Cluster-Node: {uuid4()}\r\n"
        f"X-Warpgate-Cluster-Identity: {identity}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as tcp:
            with ctx.wrap_socket(tcp, server_hostname=CLUSTER_SNI) as tls:
                tls.sendall(request)
                head = tls.recv(64)
    except (ssl.SSLError, ConnectionError, TimeoutError):
        return None
    if not head.startswith(b"HTTP/1.1 "):
        return None
    return int(head.split(b" ")[1])


def _find_in_progress_terminal_recording_id(api):
    for session in sorted(
        api.get_sessions().items, key=lambda s: s.started, reverse=True
    ):
        for rec in api.get_session_recordings(session.id):
            if rec.kind == sdk.RecordingKind.TERMINAL and rec.ended is None:
                return rec.id
    return None


class Test:
    def test_cross_node_recording_proxy(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
    ):
        # Two nodes on one database (which also carries the auto-generated
        # cluster token). Node A owns the session and alone holds the
        # in-progress recording file; node B must proxy live reads to A.
        node_a = processes.start_wg(config_patch={"recordings": {"enable": True}})
        wait_port(node_a.http_port, recv=False)
        node_b = processes.start_wg(share_with=node_a)
        wait_port(node_b.http_port, recv=False)

        url_b = f"https://localhost:{node_b.http_port}"

        user, ssh_target = setup_user_and_target(processes, node_a, wg_c_ed25519_pubkey)

        # A session on node A that emits a marker and then stays open, so the
        # recording is still in progress when we read it from node B.
        marker = f"cluster-{uuid4().hex}"
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(node_a.ssh_port),
            "-tt",
            *common_args,
            f"echo {marker}; sleep 30",
            password="123",
        )
        output = read_until(
            ssh_client.stdout, marker.encode(), time.monotonic() + timeout
        )
        assert marker.encode() in output, "marker never appeared in session output"

        # The recording lives in the shared DB; find it while still in progress.
        recording_id = None
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and recording_id is None:
            with admin_client(url_b) as api:
                recording_id = _find_in_progress_terminal_recording_id(api)
            if recording_id is None:
                time.sleep(0.5)
        assert recording_id is not None, "no in-progress terminal recording found"

        # Fetch the in-progress recording FROM NODE B. B holds no file for it, so a
        # 200 carrying the marker proves B proxied the read to node A.
        resp = requests.get(
            f"{url_b}/@warpgate/admin/api/recordings/{recording_id}/data",
            headers={"X-Warpgate-Token": "token-value"},
            verify=False,
            timeout=timeout,
        )
        assert resp.status_code == 200, f"cross-node fetch failed: {resp.status_code}"
        recorded = b""
        for line in resp.text.splitlines():
            if not line:
                continue
            item = json.loads(line)
            if "data" in item:
                recorded += base64.b64decode(item["data"])
        assert marker.encode() in recorded, "proxied recording is missing the marker"

        # Peer forwarding runs the request as the user named in the identity
        # header, so a peer is only ever trusted on a connection that proved a
        # node's pinned TLS key. Everything a database reader can get at - the
        # instance CA included - must not be enough to pose as a peer.
        with admin_client(url_b) as api:
            admin_user_id = next(u.id for u in api.get_users() if u.username == "admin")
        ca_cert_pem, ca_key_pem = _instance_ca(node_a.config_path)
        lookalike = _mint_peer_lookalike(ca_cert_pem, ca_key_pem)
        assert (
            _peer_request(node_b.http_port, lookalike, admin_user_id, timeout) is None
        ), "a CA-signed but unpinned certificate must not reach the admin API"
        assert (
            _peer_request(node_b.http_port, None, admin_user_id, timeout) is None
        ), "the cluster SNI must demand a client certificate"
        admin = requests.get(
            f"{url_b}/@warpgate/admin/api/sessions",
            headers={"X-Warpgate-Token": "token-value"},
            verify=False,
            timeout=timeout,
        )
        assert (
            admin.status_code == 200
        ), f"admin token should reach /sessions: {admin.status_code}"
