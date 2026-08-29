"""A real Vault (or OpenBao) server, for the tests the stub cannot honestly make.

`stub_vault.py` is fast and can be made to misbehave on demand, but it only knows
what we told it. Every behaviour it models is a claim about the real server, and
two of those claims have already been wrong: that a wrapping token can be
redeemed twice, and that a `lease_duration` of zero means expiry. This module
exists so each such claim is pinned by one test against the thing itself.

The read surface deliberately matches the stub's — `url`, `ca_public_key`,
`signs`, `logins` — so an assertion can be written once and pointed at either.
`signs` and `logins` come from Vault's own audit device, which records the
request as the *server* received it rather than as our stub chose to remember it.
"""

import json
import ssl
import tempfile
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from .util import alloc_port

VAULT_IMAGE = "hashicorp/vault:1.20"
# Pinned, not `latest`. This harness is the gate that says the stub tells the
# truth about a real server; a floating tag means the thing it was checked
# against is not the thing it checks against tomorrow.
OPENBAO_IMAGE = "openbao/openbao:2.5.0"

# The versions the contract suite runs against by default: one current release
# of each server. `WARPGATE_VAULT_MATRIX=full` widens it to the older releases
# an operator may still be running, which is where a behaviour change upstream
# would show up — pinning to one version means never noticing one.
MATRIX = {
    "quick": [VAULT_IMAGE, OPENBAO_IMAGE],
    "full": [
        "hashicorp/vault:1.15",
        "hashicorp/vault:1.18",
        VAULT_IMAGE,
        "openbao/openbao:2.4",
        OPENBAO_IMAGE,
    ],
}


def matrix() -> list[str]:
    import os

    return MATRIX.get(os.environ.get("WARPGATE_VAULT_MATRIX", "quick"), MATRIX["quick"])


MOUNT = "ssh-client-signer"
ROLE = "warpgate"
ROOT_TOKEN = "test-root-token"
FIXED_ROLE_ID = "warpgate-test-role-id"
AUDIT_PATH = "/tmp/audit.log"


class RealVault:
    """A dev-mode server with the SSH secrets engine and AppRole ready to use.

    Dev mode keeps everything in memory and unseals itself, which is what makes
    it usable per-test; it is also why nothing here is a model for production.
    """

    def __init__(self, image: str = VAULT_IMAGE, config_dir: Path | None = None):
        self.image = image
        self.is_openbao = "openbao" in image
        self.port = alloc_port()
        self.container = f"warpgate-e2e-vault-{uuid.uuid4().hex[:8]}"
        self.config_dir = config_dir
        self._tls_dir: Path | None = None
        self._ca_path: Path | None = None
        self.role_id: str | None = None
        self.secret_id: str | None = None

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.port}"

    @property
    def ca_bundle(self) -> str:
        """The certificate the dev server generated, for `vault.ca_bundle`.

        Dev mode serves plain HTTP unless asked otherwise, and Warpgate refuses
        a plaintext Vault address — a credential crosses this connection. So the
        server is started with `-dev-tls` and its self-signed certificate copied
        out of the container for the client to trust.
        """
        return str(self._ca_path)

    def ensure_image(self):
        """Fails, rather than skips, when the image cannot be had.

        Skipping was the wrong instinct: this suite is the gate that says the
        stub tells the truth about a real server, so a run where neither real
        server was reached must not be able to report success. A registry
        outage should stop the build and say so.
        """
        present = subprocess.run(
            ["docker", "image", "inspect", self.image], capture_output=True, check=False
        )
        if present.returncode == 0:
            return
        pull = subprocess.run(
            ["docker", "pull", self.image], capture_output=True, check=False
        )
        if pull.returncode != 0:
            raise Exception(
                f"cannot obtain {self.image}, so the contract suite would prove "
                f"nothing: {pull.stderr.decode()[-300:]}"
            )

    def _make_tls(self):
        """A CA and a leaf for the server, generated here rather than by it.

        `-dev-tls` mints a fresh certificate on every start, so a restart would
        present an identity the client has never trusted — and the restart test
        exists to watch the gateway recover from exactly that restart. Ours
        survives, because it is ours.
        """
        if self._tls_dir is not None:
            return
        self._tls_dir = Path(tempfile.mkdtemp(prefix="warpgate-vault-tls-"))
        self._tls_dir.chmod(0o755)
        ca_key = self._tls_dir / "ca.key"
        self._ca_path = self._tls_dir / "ca.pem"
        ext = self._tls_dir / "leaf.ext"
        ext.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "extendedKeyUsage=serverAuth\n"
            "subjectAltName=IP:127.0.0.1\n"
        )
        run = lambda a: subprocess.run(a, check=True, capture_output=True)
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(ca_key), "-out", str(self._ca_path),
             "-days", "1", "-subj", "/CN=warpgate-contract-ca",
             # OpenSSL 3 refuses a CA that never claimed the right to sign
             # certificates, so state it. curl on macOS accepts the cert
             # without this and Python does not, which makes the omission
             # look like a container that failed to start.
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
        run(["openssl", "req", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(self._tls_dir / "server.key"),
             "-out", str(self._tls_dir / "server.csr"),
             "-subj", "/CN=127.0.0.1"])
        run(["openssl", "x509", "-req", "-in", str(self._tls_dir / "server.csr"),
             "-CA", str(self._ca_path), "-CAkey", str(ca_key), "-CAcreateserial",
             "-out", str(self._tls_dir / "server.pem"), "-days", "1",
             "-extfile", str(ext)])
        for f in self._tls_dir.iterdir():
            f.chmod(0o644)
        (self._tls_dir / "tls.hcl").write_text(
            'listener "tcp" {\n'
            '  address = "0.0.0.0:8200"\n'
            '  tls_cert_file = "/warpgate-tls/server.pem"\n'
            '  tls_key_file = "/warpgate-tls/server.key"\n'
            "}\n"
        )

    def start(self):
        self.ensure_image()
        self._make_tls()
        token_env = "BAO_DEV_ROOT_TOKEN_ID" if self.is_openbao else "VAULT_DEV_ROOT_TOKEN_ID"
        listen_env = (
            "BAO_DEV_LISTEN_ADDRESS" if self.is_openbao else "VAULT_DEV_LISTEN_ADDRESS"
        )
        command = [
            "docker", "run", "--rm", "-d",
            "--name", self.container,
            "--cap-add", "IPC_LOCK",
            "-p", f"{self.port}:8200",
            "-e", f"{token_env}={ROOT_TOKEN}",
            # Dev mode binds its own plaintext listener. Moved off 8200 so the
            # TLS listener below can have the port the tests talk to; leaving
            # both on it fails with `address already in use` before the server
            # ever listens.
            "-e", f"{listen_env}=127.0.0.1:8300",
            "-v", f"{self._tls_dir}:/warpgate-tls",
        ]

        # OpenBao refuses `sys/audit/*` over the API — "use declarative,
        # config-based audit device management instead" — so the device has to
        # be declared in a config file the server is started with. Vault takes
        # it either way, and the API call keeps that path exercised too.
        if self.is_openbao:
            if self.config_dir is None:
                raise Exception("OpenBao needs a config_dir for its audit device")
            self.config_dir.mkdir(parents=True, exist_ok=True)
            # `type` and `path` are both required, and the device's own settings
            # go in `options` — a bare `file_path` is silently ignored with only
            # a warning in the log, which looks exactly like a working audit
            # device that never writes anything.
            (self.config_dir / "audit.hcl").write_text(
                'audit "file" {\n'
                '  type = "file"\n'
                '  path = "file/"\n'
                "  options = {\n"
                f'    file_path = "{AUDIT_PATH}"\n'
                '    log_raw = "true"\n'
                "  }\n"
                "}\n"
            )
            self.config_dir.chmod(0o755)
            command += ["-v", f"{self.config_dir}:/openbao/testconfig"]
            command += [
                self.image, "server", "-dev",
                "-config=/warpgate-tls/tls.hcl",
                "-config=/openbao/testconfig",
            ]
        else:
            command += [self.image, "server", "-dev", "-config=/warpgate-tls/tls.hcl"]

        subprocess.run(command, check=True, capture_output=True)
        self._wait_until_up()
        self._configure()

    def stop(self):
        subprocess.run(
            ["docker", "rm", "-f", self.container], capture_output=True, check=False
        )

    def _wait_until_up(self, timeout=60):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                self._api("GET", "sys/health", token=None)
                return
            except Exception:
                time.sleep(0.5)
        raise Exception(f"{self.image} did not come up on {self.url}")

    def _api(self, method: str, path: str, payload=None, token=ROOT_TOKEN):
        request = urllib.request.Request(
            f"{self.url}/v1/{path}",
            method=method,
            data=json.dumps(payload).encode() if payload is not None else None,
        )
        if token:
            request.add_header("X-Vault-Token", token)
        if payload is not None:
            request.add_header("Content-Type", "application/json")
        # The dev server's certificate is self-signed, so this trusts it
        # explicitly rather than turning verification off — the same
        # certificate Warpgate is given through `ca_bundle`.
        context = ssl.create_default_context(cafile=str(self._ca_path))
        with urllib.request.urlopen(request, timeout=10, context=context) as response:
            body = response.read()
            return json.loads(body) if body else {}

    def _configure(self):
        # Raw, so the audit log shows the payload Warpgate actually sent rather
        # than an HMAC of it. Acceptable only because this server lives for the
        # duration of one test and holds nothing real. OpenBao has already taken
        # its device from the config file it was started with.
        if not self.is_openbao:
            self._api(
                "PUT",
                "sys/audit/file",
                {
                    "type": "file",
                    "options": {"file_path": AUDIT_PATH, "log_raw": "true"},
                },
            )

        self._api("POST", "sys/mounts/" + MOUNT, {"type": "ssh"})
        self._api("POST", f"{MOUNT}/config/ca", {"generate_signing_key": True})
        self._api(
            "POST",
            f"{MOUNT}/roles/{ROLE}",
            {
                "key_type": "ca",
                "algorithm_signer": "default",
                "allow_user_certificates": True,
                # Never `*`: the role is the coarse gate that stands even if
                # Warpgate is wrong about who may reach what.
                "allowed_users": "root,deploy",
                "allow_user_key_ids": True,
                "default_extensions": {"permit-pty": ""},
                "ttl": "2m",
                "max_ttl": "5m",
            },
        )

        # The policy is the point of the exercise, not scaffolding: Warpgate is
        # meant to hold an identity that can ask for certificates and nothing
        # else. An auth method cannot issue a root token anyway — the server
        # refuses with "auth methods cannot create root tokens" — so a test that
        # reached for one would not be testing the deployment anybody runs.
        self._api(
            "PUT",
            "sys/policies/acl/warpgate",
            {
                "policy": (
                    f'path "{MOUNT}/sign/*" {{ capabilities = ["create", "update"] }}\n'
                    'path "sys/wrapping/unwrap" { capabilities = ["update"] }\n'
                )
            },
        )

        self._api("POST", "sys/auth/approle", {"type": "approle"})
        self._api(
            "POST",
            "auth/approle/role/warpgate",
            {"token_policies": "warpgate", "secret_id_num_uses": 0, "token_ttl": "10m"},
        )
        # Pinned rather than read back, so that a server which has been
        # restarted comes up answering to the same `role_id` the running
        # Warpgate was configured with. Otherwise a restart test only proves
        # that a stale configuration fails, which nobody doubted.
        self._api(
            "POST", "auth/approle/role/warpgate/role-id", {"role_id": FIXED_ROLE_ID}
        )
        self.role_id = FIXED_ROLE_ID
        self.secret_id = self._api(
            "POST", "auth/approle/role/warpgate/secret-id", {}
        )["data"]["secret_id"]

    def wrapped_secret_id(self, ttl="5m") -> str:
        """A response-wrapped secret ID, redeemable exactly once."""
        request = urllib.request.Request(
            f"{self.url}/v1/auth/approle/role/warpgate/secret-id",
            method="POST",
            data=b"{}",
        )
        request.add_header("X-Vault-Token", ROOT_TOKEN)
        request.add_header("X-Vault-Wrap-TTL", ttl)
        request.add_header("Content-Type", "application/json")
        # The dev server's certificate is self-signed, so this trusts it
        # explicitly rather than turning verification off — the same
        # certificate Warpgate is given through `ca_bundle`.
        context = ssl.create_default_context(cafile=str(self._ca_path))
        with urllib.request.urlopen(request, timeout=10, context=context) as response:
            return json.load(response)["wrap_info"]["token"]

    @property
    def ca_public_key(self) -> str:
        request = urllib.request.Request(f"{self.url}/v1/{MOUNT}/public_key")
        # The dev server's certificate is self-signed, so this trusts it
        # explicitly rather than turning verification off — the same
        # certificate Warpgate is given through `ca_bundle`.
        context = ssl.create_default_context(cafile=str(self._ca_path))
        with urllib.request.urlopen(request, timeout=10, context=context) as response:
            return response.read().decode().strip()

    def write_secret_id(self, path: Path, wrapped=False) -> Path:
        path.write_text(
            f"unwrap:{self.wrapped_secret_id()}" if wrapped else str(self.secret_id)
        )
        return path

    # --- the same read surface the stub offers -----------------------------

    def _audit(self) -> list[dict]:
        result = subprocess.run(
            ["docker", "exec", self.container, "cat", AUDIT_PATH],
            capture_output=True,
            check=False,
        )
        entries = []
        for line in result.stdout.decode(errors="replace").splitlines():
            try:
                entries.append(json.loads(line))
            except ValueError:
                continue
        return entries

    def _requests_to(self, suffix: str) -> list[dict]:
        """What Warpgate *sent*. Useful for asserting the payload it builds —
        and useless for asserting what the server decided, which is a distinct
        question that `_responses_from` answers."""
        seen = []
        for entry in self._audit():
            if entry.get("type") != "request":
                continue
            path = entry.get("request", {}).get("path", "")
            if path.endswith(suffix) or suffix in path:
                seen.append(entry["request"].get("data") or {})
        return seen

    def _responses_from(self, suffix: str) -> list[dict]:
        """What the server *returned*.

        The distinction is not academic: a test asserting that the certificate
        names the requested principals was reading the request, so it re-checked
        Warpgate's own message and would have passed no matter what came back.
        """
        seen = []
        for entry in self._audit():
            if entry.get("type") != "response":
                continue
            path = entry.get("request", {}).get("path", "")
            if path.endswith(suffix) or suffix in path:
                seen.append((entry.get("response") or {}).get("data") or {})
        return seen

    @property
    def signs(self) -> list[dict]:
        return self._requests_to(f"{MOUNT}/sign/")

    @property
    def issued(self) -> list[dict]:
        """The certificates the server actually handed back.

        Only the ones carrying a `signed_key`. The audit device records a
        response for a refusal too, so counting every response answered "did the
        server reply", not "did it issue" — and a test asserting that a role
        refuses a principal outside its `allowed_users` passed on the refusal
        being recorded, which is the same shape as the request-versus-response
        confusion this property was added to fix.
        """
        return [
            data
            for data in self._responses_from(f"{MOUNT}/sign/")
            if data.get("signed_key")
        ]

    @property
    def logins(self) -> list[dict]:
        return self._requests_to("auth/approle/login")

    @property
    def unwraps(self) -> list[dict]:
        return self._requests_to("sys/wrapping/unwrap")
