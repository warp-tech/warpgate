"""A stand-in for Vault's SSH secrets engine.

Signs with a throwaway CA through ``ssh-keygen``, so the certificate tests need
neither a Vault server nor a cluster. Every knob here exists to reproduce a
failure Warpgate has to survive, and every recorded request exists so a test can
assert on what Warpgate actually asked for.
"""

import json
import ssl
import subprocess
import tempfile
import threading
import time
from base64 import b64decode, urlsafe_b64decode, urlsafe_b64encode
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

MOUNT = "ssh-client-signer"


def jwt(claims: dict) -> str:
    """A JWT-shaped token. Unsigned — the stub checks shape and claims, which is
    what catches a payload built wrong, not cryptographic validity."""

    def segment(raw: bytes) -> str:
        return urlsafe_b64encode(raw).rstrip(b"=").decode()

    return ".".join(
        [
            segment(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()),
            segment(json.dumps(claims).encode()),
            segment(b"stub-signature"),
        ]
    )


def jwt_claims(token: str) -> dict:
    payload = token.split(".")[1]
    return json.loads(urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def is_jwt(token) -> bool:
    parts = (token or "").split(".")
    if len(parts) != 3 or not all(parts):
        return False
    try:
        jwt_claims(token)
    except Exception:
        return False
    return True


SERVICE_ACCOUNT_JWT = jwt(
    {"iss": "kubernetes/serviceaccount", "sub": "system:serviceaccount:warpgate:warpgate"}
)


def reject_login(method, body):
    """Checks what the real auth method checks, in the same order it does.

    A stub that accepts anything turns every login test into an assertion
    about the stub instead of about the payload Warpgate built.
    """
    if method == "kubernetes":
        if not body.get("role"):
            return "missing role"
        if not is_jwt(body.get("jwt")):
            return "jwt is not a JWT"
        return None

    if method == "approle":
        if not body.get("role_id") or not body.get("secret_id"):
            return "missing role_id or secret_id"
        return None

    if method == "aws":
        return reject_aws_login(body)

    if method == "azure":
        for field in ("subscription_id", "resource_group_name", "vm_name"):
            if not body.get(field):
                return f"missing {field}"
        if "vmss_name" in body and not body["vmss_name"]:
            return "vmss_name present but empty"
        if not is_jwt(body.get("jwt")):
            return "jwt is not a JWT"
        return None

    if method == "gcp":
        role = body.get("role")
        if not role:
            return "missing role"
        if not is_jwt(body.get("jwt")):
            return "jwt is not a JWT"
        # Vault rejects a token minted for a different audience, which is
        # what stops a token issued for one role being replayed at another.
        if jwt_claims(body["jwt"]).get("aud") != f"vault/{role}":
            return "jwt audience is not bound to the role"
        return None

    return f"unknown auth method {method}"

def reject_aws_login(body):
    """Vault replays this request against STS, so it has to be a signed
    GetCallerIdentity call and not merely four non-empty fields."""
    if body.get("iam_http_request_method") != "POST":
        return "iam_http_request_method must be POST"
    try:
        url = b64decode(body.get("iam_request_url", "")).decode()
        signed_body = b64decode(body.get("iam_request_body", "")).decode()
        headers = json.loads(b64decode(body.get("iam_request_headers", "")))
    except Exception as e:
        return f"undecodable IAM payload: {e}"

    host = urlsplit(url).hostname or ""
    if host != "sts.amazonaws.com" and not (
        host.startswith("sts.") and host.endswith(".amazonaws.com")
    ):
        return f"not an STS endpoint: {host}"
    if parse_qs(signed_body).get("Action") != ["GetCallerIdentity"]:
        return f"not a GetCallerIdentity call: {signed_body}"

    authorization = next(
        (v for k, v in headers.items() if k.lower() == "authorization"), ""
    )
    if not authorization.startswith("AWS4-HMAC-SHA256"):
        return "missing SigV4 Authorization header"
    return None


class Recorder:
    """Records every request it receives and nothing else. Used to prove that a
    redirect from the issuer never reaches its target."""

    def __init__(self):
        self.requests = []
        handler = self

        class _RecordingHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self._record()

            def do_POST(self):
                self._record()

            def _record(self):
                handler.requests.append((self.path, dict(self.headers)))
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._server.shutdown()
        self._thread.join(timeout=5)
        self._server.server_close()

    @property
    def url(self):
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        """The cloud metadata services Warpgate reads its identity from."""
        stub = self.server.stub
        path = self.path.split("?")[0]
        stub.requests.append(self.path)
        stub.metadata_requests.append(self.path)

        query = parse_qs(urlsplit(self.path).query)

        if path == "/metadata/identity/oauth2/token":
            resource = query.get("resource", [""])[0]
            self._reply(200, {"access_token": jwt({"aud": resource, "oid": "oid-1"})})
        elif path == "/metadata/instance/compute":
            self._reply(200, {
                "subscriptionId": "sub-1",
                "resourceGroupName": "rg-1",
                "name": "vm-1",
                "vmScaleSetName": "",
            })
        elif path.endswith("/service-accounts/default/identity"):
            audience = query.get("audience", [""])[0]
            self._send_text(200, jwt({"aud": audience, "sub": "gce-instance"}) + "\n")
        else:
            self._reply(404, {"errors": [f"no handler for {path}"]})

    def _send_text(self, status, body):
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self):
        stub = self.server.stub
        stub.requests.append(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")

        if self.path == "/v1/sys/wrapping/unwrap":
            token = self.headers.get("X-Vault-Token", "")
            if not token:
                self._reply(400, {"errors": ["missing wrapping token"]})
                return
            stub.unwraps.append(token)
            # A wrapping token can be redeemed exactly once. Modelling that is
            # the difference between a test that proves the secret ID survives
            # more than one login and one that never asks.
            if token in stub.spent_wrapping_tokens:
                self._reply(400, {"errors": ["wrapping token is not valid or does not exist"]})
                return
            stub.spent_wrapping_tokens.add(token)
            self._reply(200, {"data": {"secret_id": "unwrapped-secret-id"}})
            return

        if self.path.startswith("/v1/auth/") and self.path.endswith("/login"):
            method = self.path.split("/")[3]
            rejection = reject_login(method, body)
            if rejection:
                self._reply(400, {"errors": [rejection]})
                return

            stub.logins.append({"method": method, **body})

            # Vault is not instantaneous, and how many sessions can be inside a
            # single login at once is the thing some tests are about.
            time.sleep(stub.login_delay)

            stub.valid_token = f"stub-token-{len(stub.logins)}"
            self._reply(
                200,
                {
                    "auth": {
                        "client_token": stub.valid_token,
                        "lease_duration": stub.lease_duration,
                    }
                },
            )
            return

        if self.path.startswith(f"/v1/{MOUNT}/sign/"):
            self._sign(stub, self.path.rsplit("/", 1)[-1], body)
            return

        self._reply(404, {"errors": [f"no handler for {self.path}"]})


    def _sign(self, stub, role, body):
        presented = self.headers.get("X-Vault-Token")
        stub.signs.append({"role": role, "token": presented, **body})

        if stub.sign_redirect_to is not None:
            self.send_response(307)
            self.send_header("Location", stub.sign_redirect_to)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if stub.sign_error_body is not None:
            self._send_raw(500, stub.sign_error_body)
            return

        if stub.sign_status is not None:
            self._reply(stub.sign_status, {"errors": ["stub refuses to sign"]})
            return

        # Mirrors Vault rejecting a token that was revoked, or that predates a
        # restart, before its lease was due to expire. Only checked once a test
        # asks for it, so a token cached by an earlier test cannot leak into an
        # unrelated one.
        if not stub.accept_any_token and presented != stub.valid_token:
            self._reply(403, {"errors": ["permission denied", "invalid token"]})
            return

        if stub.sign_data is not None:
            self._reply(200, {"data": stub.sign_data})
            return

        if stub.signed_key is not None:
            self._reply(200, {"data": {"signed_key": stub.signed_key}})
            return

        certificate = stub.issue(
            public_key=stub.sign_public_key or body["public_key"],
            principals=(
                stub.principals if stub.principals is not None else body["valid_principals"]
            ),
            key_id=stub.sign_key_id if stub.sign_key_id is not None else body.get("key_id", ""),
        )
        self._reply(200, {"data": {"signed_key": certificate}})

    def _reply(self, status, payload):
        self._send_raw(status, json.dumps(payload).encode(), "application/json")

    def _send_raw(self, status, encoded: bytes, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        try:
            self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionResetError):
            # Warpgate hangs up on a body larger than it will accept, which is
            # exactly what one of the tests here is checking for.
            pass

    def log_message(self, *args):
        pass


class StubVault:
    def __init__(self, directory: Path):
        directory.mkdir(parents=True, exist_ok=True)
        self.directory = directory
        self.ca_key = directory / "ca"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-f", str(self.ca_key), "-N", ""],
            check=True,
        )
        # TLS, because Warpgate refuses a Vault address that is not HTTPS — a
        # secret crosses this connection on every login, and the refusal is the
        # point rather than an inconvenience to work around in tests.
        #
        # A CA and a leaf it signs, not one self-signed certificate doing both
        # jobs. `openssl req -x509` produces `CA:TRUE`, and rustls refuses that
        # as a server certificate — `CaUsedAsEndEntity`. macOS's verifier
        # accepts it, so the shortcut passed here and failed on Linux in CI.
        self.tls_ca = directory / "vault-ca.pem"
        ca_key = directory / "vault-ca.key"
        self.tls_cert = directory / "vault-tls.pem"
        self.tls_key = directory / "vault-tls.key"
        csr = directory / "vault-tls.csr"
        ext = directory / "vault-tls.ext"
        ext.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "extendedKeyUsage=serverAuth\n"
            "subjectAltName=IP:127.0.0.1\n"
        )
        run = lambda args: subprocess.run(args, check=True, capture_output=True)
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(ca_key), "-out", str(self.tls_ca),
             "-days", "1", "-subj", "/CN=warpgate-test-ca"])
        run(["openssl", "req", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(self.tls_key), "-out", str(csr),
             "-subj", "/CN=127.0.0.1"])
        run(["openssl", "x509", "-req", "-in", str(csr),
             "-CA", str(self.tls_ca), "-CAkey", str(ca_key), "-CAcreateserial",
             "-out", str(self.tls_cert), "-days", "1",
             "-extfile", str(ext)])

        # A second listener, in plain HTTP, for the cloud metadata endpoints.
        # Those are not Vault: a real one answers on a link-local address over
        # HTTP, and Warpgate reads them with a separate client. Serving them
        # over TLS here would have tested a shape that does not exist.
        self._metadata_server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._metadata_server.stub = self
        self._metadata_thread = threading.Thread(
            target=self._metadata_server.serve_forever, daemon=True
        )

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._server.stub = self
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.tls_cert), str(self.tls_key))
        self._server.socket = context.wrap_socket(self._server.socket, server_side=True)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self.logins = []
        self.signs = []
        self.requests = []
        self.metadata_requests = []
        self.unwraps = []
        self.spent_wrapping_tokens = set()
        self.valid_token = None
        self.reset()

    def reset(self):
        """Restores the defaults a happy-path test expects."""
        self.lease_duration = 3600
        self.login_delay = 0
        self.accept_any_token = True
        self.sign_status = None
        self.sign_error_body = None
        self.sign_redirect_to = None
        self.signed_key = None
        self.sign_data = None
        self.sign_public_key = None
        self.principals = None
        self.validity = "-30s:+2m"
        self.cert_type = "user"
        self.sign_options = []
        self.sign_key_id = None
        self.logins.clear()
        self.signs.clear()
        self.requests.clear()
        self.metadata_requests.clear()
        self.unwraps.clear()
        self.spent_wrapping_tokens.clear()

    def start(self):
        self._thread.start()
        self._metadata_thread.start()

    def stop(self):
        self._server.shutdown()
        self._thread.join(timeout=5)
        self._server.server_close()
        self._metadata_server.shutdown()
        self._metadata_thread.join(timeout=5)
        self._metadata_server.server_close()

    @property
    def url(self):
        host, port = self._server.server_address[:2]
        return f"https://{host}:{port}"

    @property
    def metadata_url(self):
        """Plain HTTP, as a cloud metadata service actually answers."""
        host, port = self._metadata_server.server_address[:2]
        return f"http://{host}:{port}"

    @property
    def ca_bundle(self) -> str:
        """The CA, for `vault.ca_bundle` — not the leaf the server presents."""
        return str(self.tls_ca)

    @property
    def ca_public_key(self) -> str:
        return Path(f"{self.ca_key}.pub").read_text().strip()

    def issue(self, public_key: str, principals: str, key_id: str) -> str:
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "key.pub"
            key.write_text(public_key)
            # ssh-keygen decides itself which of `sign_options` are critical
            # options and which are extensions, exactly as a Vault role's
            # default_critical_options and default_extensions end up doing.
            #
            # `clear` first, then only what the test asked for. Left to itself
            # ssh-keygen grants all five standard extensions — including
            # permit-port-forwarding and permit-agent-forwarding — which no
            # sensible Vault role does: the usual `default_extensions` is
            # `{"permit-pty": ""}`. The stub was quietly issuing more privilege
            # than the thing it stands in for, so a target with the default
            # extension allow-list would have refused every certificate in this
            # suite, and any test about forwarding would have been meaningless.
            options = ["-O", "clear", "-O", "permit-pty"]
            options += [arg for option in self.sign_options for arg in ("-O", option)]
            subprocess.run(
                [
                    "ssh-keygen", "-q",
                    "-s", str(self.ca_key),
                    "-I", key_id,
                    "-n", principals,
                    "-V", self.validity,
                    *(["-h"] if self.cert_type == "host" else []),
                    *options,
                    str(key),
                ],
                check=True,
            )
            return (Path(directory) / "key-cert.pub").read_text()

    def unrelated_public_key(self) -> str:
        """A public key Warpgate does not hold the private half of."""
        path = self.directory / "unrelated"
        if not path.exists():
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-f", str(path), "-N", ""],
                check=True,
            )
        return Path(f"{path}.pub").read_text().strip()

    def invalidate_token(self):
        """Makes the cached token stop working, as a Vault restart would."""
        self.accept_any_token = False
        self.valid_token = "rotated-away"
