import requests
from contextlib import contextmanager


@contextmanager
def api_admin_session(url):
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
    yield session


def assert_response(response, code):
    if response.status_code != code:
        print(response.text)
    assert response.status_code == code


def api_list_users(url, session):
    response = session.get(
        f"{url}/@warpgate/admin/api/users",
    )
    assert_response(response, 200)
    return response.json()


def api_create_target(url, session, config):
    response = session.post(
        f"{url}/@warpgate/admin/api/targets",
        json=config,
    )
    assert_response(response, 201)
    return response.json()


def api_create_role(url, session, config):
    response = session.post(
        f"{url}/@warpgate/admin/api/roles",
        json=config,
    )
    assert_response(response, 201)
    return response.json()


def api_create_user(url, session, config):
    response = session.post(
        f"{url}/@warpgate/admin/api/users",
        json=config,
    )
    assert_response(response, 201)
    return response.json()


def api_add_role_to_target(url, session, target_id, role_id):
    response = session.post(
        f"{url}/@warpgate/admin/api/targets/{target_id}/roles/{role_id}",
    )
    assert_response(response, 201)


def api_add_role_to_user(url, session, user_id, role_id):
    response = session.post(
        f"{url}/@warpgate/admin/api/users/{user_id}/roles/{role_id}",
    )
    assert_response(response, 201)


def api_create_ticket(url, session, username, target_name):
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
