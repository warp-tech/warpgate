import requests
import pyotp


from .util import wait_port


class TestHTTPUserAuthOTP:
    def test_auth_otp_success(
        self,
        http_common_wg_port,
        otp_key_base32,
    ):
        wait_port(http_common_wg_port, recv=False)
        session = requests.Session()
        session.verify = False
        url = f'https://localhost:{http_common_wg_port}'

        totp = pyotp.TOTP(otp_key_base32)

        response = session.post(
            f'{url}/@warpgate/api/auth/login',
            json={
                'username': 'userwithotp',
                'password': '123',
            },
        )
        assert response.status_code // 100 != 2

        response = session.get(
            f'{url}/some/path?a=b&warpgate-target=echo&c=d', allow_redirects=False
        )
        assert response.status_code // 100 != 2

        response = session.post(
            f'{url}/@warpgate/api/auth/otp',
            json={
                'otp': totp.now(),
            },
        )
        assert response.status_code // 100 == 2

        response = session.get(
            f'{url}/some/path?a=b&warpgate-target=echo&c=d', allow_redirects=False
        )
        assert response.status_code // 100 == 2
        assert response.json()['path'] == '/some/path'

    def test_auth_otp_fail(
        self,
        http_common_wg_port,
    ):
        wait_port(http_common_wg_port, recv=False)
        session = requests.Session()
        session.verify = False
        url = f'https://localhost:{http_common_wg_port}'

        response = session.post(
            f'{url}/@warpgate/api/auth/login',
            json={
                'username': 'userwithotp',
                'password': '123',
            },
        )
        assert response.status_code // 100 != 2

        response = session.post(
            f'{url}/@warpgate/api/auth/otp',
            json={
                'otp': '00000000',
            },
        )
        assert response.status_code // 100 != 2

        response = session.get(
            f'{url}/some/path?a=b&warpgate-target=echo&c=d', allow_redirects=False
        )
        assert response.status_code // 100 != 2
