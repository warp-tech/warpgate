import base64
import json
import time
from uuid import uuid4

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .test_http_common import *  # noqa
from .test_http_user_auth_oidc import _do_oidc_login, _start_wg_with_oidc
from .util import alloc_port

BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_int(value: str) -> int:
    return int.from_bytes(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)), "big")


def _sign_rs256(jwk: dict, claims: dict) -> str:
    public = rsa.RSAPublicNumbers(_b64url_int(jwk["e"]), _b64url_int(jwk["n"]))
    key = rsa.RSAPrivateNumbers(
        p=_b64url_int(jwk["p"]),
        q=_b64url_int(jwk["q"]),
        d=_b64url_int(jwk["d"]),
        dmp1=_b64url_int(jwk["dp"]),
        dmq1=_b64url_int(jwk["dq"]),
        iqmp=_b64url_int(jwk["qi"]),
        public_numbers=public,
    ).private_key()
    header = {"alg": "RS256", "kid": jwk["kid"], "typ": "logout+jwt"}
    signing_input = (
        _b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps(claims).encode())
    )
    signature = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return signing_input + "." + _b64url(signature)


def _logout_claims(oidc_port, **overrides):
    claims = {
        "iss": f"http://localhost:{oidc_port}",
        "aud": "warpgate-test",
        "iat": int(time.time()),
        "jti": str(uuid4()),
        "sub": "1",
        "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
    }
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


def _username(wg_url, session):
    return session.get(f"{wg_url}/@warpgate/api/info").json()["username"]


def _setup_sso_user(wg_url):
    with admin_client(wg_url) as api:
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        api.create_sso_credential(
            user.id,
            sdk.NewSsoCredential(email="sam.tailor@gmail.com", provider="test-oidc"),
        )
    return user


class TestHTTPUserAuthOIDCBackchannelLogout:
    def test_backchannel_logout(self, processes: ProcessManager):
        wg_http_port = alloc_port()
        oidc_port = processes.start_oidc_server(wg_http_port)
        wg = _start_wg_with_oidc(processes, wg_http_port, oidc_port)
        wg_url = f"https://127.0.0.1:{wg.http_port}"
        endpoint = f"{wg_url}/@warpgate/api/sso/providers/test-oidc/backchannel-logout"
        jwk = processes.oidc_signing_key(oidc_port)
        user = _setup_sso_user(wg_url)

        first, _ = _do_oidc_login(wg_url, oidc_port)
        second, _ = _do_oidc_login(wg_url, oidc_port)
        assert _username(wg_url, first) == user.username
        assert _username(wg_url, second) == user.username

        def post(claims):
            return requests.post(
                endpoint, data={"logout_token": _sign_rs256(jwk, claims)}, verify=False
            )

        # Not logout tokens for us, or not logout tokens at all
        assert post(_logout_claims(oidc_port, aud="someone-else")).status_code == 400
        assert post(_logout_claims(oidc_port, events=None)).status_code == 400
        assert post(_logout_claims(oidc_port, iat=int(time.time()) - 3600)).status_code == 400
        assert post(_logout_claims(oidc_port, sub=None)).status_code == 400
        assert (
            requests.post(
                endpoint, data={"logout_token": "not-a-jwt"}, verify=False
            ).status_code
            == 400
        )

        # Another subject, or the right subject in a session we don't have
        assert post(_logout_claims(oidc_port, sub="2")).status_code == 200
        assert post(_logout_claims(oidc_port, sid="unknown")).status_code == 200
        assert _username(wg_url, first) == user.username
        assert _username(wg_url, second) == user.username

        # The subject's every session
        assert post(_logout_claims(oidc_port)).status_code == 200
        assert _username(wg_url, first) is None
        assert _username(wg_url, second) is None

        with admin_client(wg_url) as api:
            assert not api.get_sessions(active_only=True, username=user.username).items

    def test_local_logout_disabled(self, processes: ProcessManager):
        wg_http_port = alloc_port()
        oidc_port = processes.start_oidc_server(wg_http_port)
        wg = _start_wg_with_oidc(
            processes, wg_http_port, oidc_port, disable_local_logout=True
        )
        wg_url = f"https://127.0.0.1:{wg.http_port}"
        user = _setup_sso_user(wg_url)

        session, _ = _do_oidc_login(wg_url, oidc_port)
        assert session.get(f"{wg_url}/@warpgate/api/info").json()["local_logout_disabled"]
        assert session.post(f"{wg_url}/@warpgate/api/auth/logout").status_code == 403
        assert _username(wg_url, session) == user.username

        response = session.get(f"{wg_url}/@warpgate/api/sso/logout")
        assert response.status_code == 200
        assert response.json()["url"].startswith(f"http://localhost:{oidc_port}/")
        assert _username(wg_url, session) is None
