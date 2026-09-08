"""Kubernetes tickets route without a target selector or additional credentials."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import time
import subprocess
from uuid import uuid4

import pytest
import requests
import yaml

from .api_client import admin_client, sdk
from .util import alloc_port, wait_port


def create_target(api, port):
    return api.create_target(sdk.TargetDataRequest(
        name=f"k8s-ticket-{uuid4()}",
        options=sdk.TargetOptions(sdk.TargetOptionsTargetKubernetesOptions(
            kind="Kubernetes",
            cluster_url=f"http://127.0.0.1:{port}",
            tls=sdk.Tls(mode=sdk.TlsMode.DISABLED, verify=False),
            auth=sdk.KubernetesTargetAuth(
                sdk.KubernetesTargetAuthKubernetesTargetTokenAuth(
                    kind="Token", token="upstream-token",
                ),
            ),
        )),
    ))


@pytest.fixture
def ticket_setup(shared_wg, echo_server_port):
    with admin_client(f"https://localhost:{shared_wg.http_port}") as api:
        # No roles, password, API token or certificate: only the ticket grants access.
        user = api.create_user(sdk.CreateUserRequest(username=f"ticket-{uuid4()}"))
        target = create_target(api, echo_server_port)
        yield api, user, target


def create_ticket(setup, **kwargs):
    api, user, target = setup
    return api.create_ticket(sdk.CreateTicketRequest(
        username=user.username, target_name=target.name, **kwargs,
    ))


def request(wg, secret, path="/api", **kwargs):
    return requests.get(
        f"https://localhost:{wg.kubernetes_port}{path}",
        headers={"Authorization": f"Bearer ticket-{secret}"},
        verify=False, timeout=10, **kwargs,
    )


def uses_left(setup, ticket):
    return next(t.uses_left for t in setup[0].get_tickets() if t.id == ticket.ticket.id)


def test_ticket_selects_target_and_shares_one_use(shared_wg, ticket_setup):
    ticket = create_ticket(ticket_setup, number_of_uses=1)
    paths = ["/", "/api", "/apis", "/version", "/api/v1/pods?limit=1"] * 3
    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(lambda path: request(shared_wg, ticket.secret, path), paths))
    for response, path in zip(responses, paths):
        assert response.status_code == 200, response.text
        assert response.json()["path"] == path.split("?")[0]
        headers = {k.lower(): v for k, v in response.json()["headers"]}
        assert headers["authorization"] == "Bearer upstream-token"
    assert responses[4].json()["args"] == {"limit": "1"}
    assert uses_left(ticket_setup, ticket) == 0
    sessions = ticket_setup[0].get_sessions(username=ticket_setup[1].username).items
    recorded = [
        target_session for session in sessions
        for target_session in session.target_sessions
        if target_session.ticket_id == ticket.ticket.id
    ]
    assert len(recorded) == 1
    assert recorded[0].target_id == ticket_setup[2].id

    # URL components and query parameters cannot override the ticket's target.
    response = request(shared_wg, ticket.secret, "/admin/api?warpgate-target=admin")
    assert response.status_code == 200
    assert response.json()["path"] == "/admin/api"

    # Another ticket for the same user/target/IP must open its own session.
    exhausted = create_ticket(ticket_setup, number_of_uses=0)
    assert request(shared_wg, exhausted.secret).status_code == 401
    second = create_ticket(ticket_setup, number_of_uses=1)
    assert request(shared_wg, second.secret).status_code == 200
    assert uses_left(ticket_setup, second) == 0


def test_ticket_revocation_applies_to_cached_session(shared_wg, ticket_setup):
    ticket = create_ticket(ticket_setup)
    assert request(shared_wg, ticket.secret).status_code == 200
    assert uses_left(ticket_setup, ticket) is None
    ticket_setup[0].delete_ticket(ticket.ticket.id)
    assert request(shared_wg, ticket.secret).status_code == 401


def test_kubectl_with_targetless_ticket_kubeconfig(shared_wg, ticket_setup, tmp_path):
    ticket = create_ticket(ticket_setup, number_of_uses=1)
    config = tmp_path / "warpgate-kubeconfig.yaml"
    config.write_text(yaml.safe_dump({
        "apiVersion": "v1", "kind": "Config",
        "clusters": [{"name": "warpgate", "cluster": {
            "server": f"https://localhost:{shared_wg.kubernetes_port}",
            "insecure-skip-tls-verify": True,
        }}],
        "users": [{"name": "ticket", "user": {"token": f"ticket-{ticket.secret}"}}],
        "contexts": [{"name": "ticket", "context": {"cluster": "warpgate", "user": "ticket"}}],
        "current-context": "ticket",
    }))
    result = subprocess.run(
        ["kubectl", "--kubeconfig", str(config), "get", "--raw=/version"],
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr
    import json
    assert json.loads(result.stdout)["path"] == "/version"
    assert uses_left(ticket_setup, ticket) == 0


def test_normal_api_token_cannot_join_ticket_session(shared_wg, ticket_setup):
    api, user, target = ticket_setup
    ticket = create_ticket(ticket_setup)
    assert request(shared_wg, ticket.secret).status_code == 200
    api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
    with requests.Session() as session:
        session.verify = False
        url = f"https://localhost:{shared_wg.http_port}/@warpgate/api"
        login = session.post(f"{url}/auth/login", json={
            "username": user.username, "password": "123",
        }, timeout=10)
        login.raise_for_status()
        token_response = session.post(f"{url}/profile/api-tokens", json={
            "label": "kubernetes-ticket-isolation",
            "expiry": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        }, timeout=10)
        token_response.raise_for_status()
        headers = {"Authorization": f"Bearer {token_response.json()['secret']}"}

    def normal_request(path):
        return requests.get(
            f"https://localhost:{shared_wg.kubernetes_port}{path}",
            headers=headers, verify=False, timeout=10,
        )

    # Same identity and IP as the ticket, but no role grants normal access.
    assert normal_request(f"/{target.name}/api").status_code == 403
    role = api.create_role(sdk.RoleDataRequest(name=f"k8s-role-{uuid4()}"))
    api.add_user_role(user.id, role.id)
    api.add_target_role(target.id, role.id)
    response = normal_request(f"/{target.name}/api/v1/pods")
    assert response.status_code == 200, response.text
    assert response.json()["path"] == "/api/v1/pods"
    assert normal_request("/api").status_code == 404


def test_ticket_expiry_applies_to_cached_session(shared_wg, ticket_setup):
    expiry = datetime.now(timezone.utc) + timedelta(seconds=3)
    ticket = create_ticket(ticket_setup, expiry=expiry)
    assert request(shared_wg, ticket.secret).status_code == 200
    time.sleep(max(0, (expiry - datetime.now(timezone.utc)).total_seconds()) + 0.1)
    assert request(shared_wg, ticket.secret).status_code == 401


def test_ticket_rechecks_user_ip_restrictions(shared_wg, ticket_setup):
    api, user, _ = ticket_setup
    ticket = create_ticket(ticket_setup)
    assert request(shared_wg, ticket.secret).status_code == 200
    api.update_user(user.id, sdk.UserDataRequest(
        username=user.username, allowed_ip_ranges=["192.0.2.0/24"],
    ))
    assert request(shared_wg, ticket.secret).status_code == 401


def test_non_kubernetes_ticket_is_not_spent(shared_wg, ticket_setup):
    api, user, _ = ticket_setup
    target = api.create_target(sdk.TargetDataRequest(
        name=f"http-ticket-{uuid4()}",
        options=sdk.TargetOptions(sdk.TargetOptionsTargetHTTPOptions(
            kind="Http", url="http://127.0.0.1:1",
            tls=sdk.Tls(mode=sdk.TlsMode.DISABLED, verify=False),
        )),
    ))
    ticket = create_ticket((api, user, target), number_of_uses=1)
    assert request(shared_wg, ticket.secret).status_code == 401
    assert uses_left(ticket_setup, ticket) == 1


def test_ticket_session_lifetime_is_enforced(processes, echo_server_port):
    wg = processes.start_wg(config_patch={"kubernetes": {"session_max_age": "1s"}})
    wait_port(wg.kubernetes_port, for_process=wg.process, recv=False)
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    with admin_client(f"https://localhost:{wg.http_port}") as api:
        user = api.create_user(sdk.CreateUserRequest(username=f"ticket-{uuid4()}"))
        setup = api, user, create_target(api, echo_server_port)
        ticket = create_ticket(setup, number_of_uses=2)
        assert request(wg, ticket.secret).status_code == 200
        assert uses_left(setup, ticket) == 1
        time.sleep(1.1)
        assert request(wg, ticket.secret).status_code == 200
        assert uses_left(setup, ticket) == 0
        time.sleep(1.1)
        assert request(wg, ticket.secret).status_code == 401


def test_single_use_is_atomic_across_nodes(processes, shared_wg, ticket_setup):
    peer = processes.start_wg(share_with=shared_wg)
    wait_port(peer.kubernetes_port, for_process=peer.process, recv=False)
    ticket = create_ticket(ticket_setup, number_of_uses=1)
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda wg: request(wg, ticket.secret), [shared_wg, peer]))
    assert sorted(r.status_code for r in responses) == [200, 401]
    assert uses_left(ticket_setup, ticket) == 0


@pytest.mark.asyncio
async def test_ticket_websocket_uses_same_session(shared_wg, ticket_setup):
    import aiohttp
    from aiohttp import web

    async def upstream(req):
        assert req.headers["Authorization"] == "Bearer upstream-token"
        if req.path == "/api":
            return web.json_response({})
        ws = web.WebSocketResponse(protocols=["v4.channel.k8s.io"])
        await ws.prepare(req)
        async for message in ws:
            await ws.send_str(message.data)
        return ws

    app = web.Application()
    app.router.add_get("/{path:.*}", upstream)
    runner = web.AppRunner(app)
    await runner.setup()
    port = alloc_port()
    await web.TCPSite(runner, "127.0.0.1", port).start()
    try:
        api, user, _ = ticket_setup
        setup = api, user, create_target(api, port)
        ticket = create_ticket(setup, number_of_uses=1)
        async with aiohttp.ClientSession(headers={
            "Authorization": f"Bearer ticket-{ticket.secret}",
        }) as session:
            url = f"https://localhost:{shared_wg.kubernetes_port}"
            async with session.get(f"{url}/api", ssl=False) as response:
                assert response.status == 200
            async with session.ws_connect(
                f"{url}/socket", ssl=False, protocols=["v4.channel.k8s.io"],
            ) as ws:
                await ws.send_str("ticket websocket")
                assert (await ws.receive(timeout=5)).data == "ticket websocket"
        assert uses_left(setup, ticket) == 0
    finally:
        await runner.cleanup()
