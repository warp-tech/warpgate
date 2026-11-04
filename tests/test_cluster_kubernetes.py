"""Kubernetes session sharing across cluster nodes."""

from concurrent.futures import ThreadPoolExecutor
import time
from uuid import uuid4

import pytest
import requests

from .api_client import admin_client, sdk
from .test_cluster_failover import (
    _expire_heartbeat,
    _hard_kill,
    _live_session_node,
    _session_ended,
)
from .test_kubernetes_user_auth_ticket import (
    create_api_token,
    create_target,
    create_ticket,
    login,
    uses_left,
)
from .util import wait_port

# Nodes correlate requests by client IP, which behind a load balancer comes
# from X-Forwarded-For.
CLIENT_IP = "203.0.113.7"


@pytest.fixture
def nodes(processes):
    node = processes.start_wg(config_patch={"http": {"trust_x_forwarded_headers": True}})
    wait_port(node.http_port, for_process=node.process, recv=False)
    wait_port(node.kubernetes_port, for_process=node.process, recv=False)
    peer = processes.start_wg(share_with=node)
    wait_port(peer.http_port, for_process=peer.process, recv=False)
    wait_port(peer.kubernetes_port, for_process=peer.process, recv=False)
    return node, peer


def kubernetes_request(wg, bearer, path="/api", timeout=60):
    return requests.get(
        f"https://localhost:{wg.kubernetes_port}{path}",
        headers={"Authorization": f"Bearer {bearer}", "X-Forwarded-For": CLIENT_IP},
        verify=False,
        timeout=timeout,
    )


def ticket_request(wg, ticket):
    return kubernetes_request(wg, f"ticket-{ticket.secret}")


def token_request(wg, token, target, timeout=60):
    return kubernetes_request(wg, token, f"/{target.name}/api", timeout=timeout)


def user_with_access(api, target, **user_fields):
    user = api.create_user(sdk.CreateUserRequest(username=f"k8s-cluster-{uuid4()}"))
    if user_fields:
        api.update_user(user.id, sdk.UserDataRequest(username=user.username, **user_fields))
    role = api.create_role(sdk.RoleDataRequest(name=f"k8s-role-{uuid4()}"))
    api.add_user_role(user.id, role.id)
    api.add_target_role(target.id, role.id)
    return user


def kubernetes_sessions(api, user):
    return [
        s for s in api.get_sessions(username=user.username).items
        if s.protocol == "Kubernetes"
    ]


def pending_kubernetes_approvals(session, wg):
    response = session.get(
        f"https://localhost:{wg.http_port}/@warpgate/api/auth/web-auth-requests",
        timeout=10,
    )
    response.raise_for_status()
    return [r for r in response.json() if r["protocol"] == "Kubernetes"]


def poll(fn, deadline_s=15):
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        value = fn()
        if value:
            return value
        time.sleep(0.25)
    return fn()


def one_session(api, user):
    """Waits for claim-race losers to discard their provisional sessions."""
    sessions = poll(lambda: len(kubernetes_sessions(api, user)) == 1 and kubernetes_sessions(api, user))
    assert sessions, kubernetes_sessions(api, user)
    return sessions[0]


def test_a_single_use_ticket_serves_both_nodes(nodes, echo_server_port):
    node, peer = nodes
    with admin_client(f"https://localhost:{node.http_port}") as api:
        user = api.create_user(sdk.CreateUserRequest(username=f"ticket-{uuid4()}"))
        setup = api, user, create_target(api, echo_server_port)
        ticket = create_ticket(setup, number_of_uses=1)

        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(lambda wg: ticket_request(wg, ticket), [node, peer]))
        assert [r.status_code for r in responses] == [200, 200], [r.text for r in responses]
        assert uses_left(setup, ticket) == 0
        session = one_session(api, user)
        assert [t.ticket_id for t in session.target_sessions] == [ticket.ticket.id]


def test_requests_on_both_nodes_share_one_session(nodes, echo_server_port):
    node, peer = nodes
    with admin_client(f"https://localhost:{node.http_port}") as api:
        target = create_target(api, echo_server_port)
        user = user_with_access(api, target)
        with login(node, api, user) as session:
            token = create_api_token(session, node)

        spread = [node, peer] * 5
        with ThreadPoolExecutor(max_workers=4) as pool:
            responses = list(pool.map(lambda wg: token_request(wg, token, target), spread))
        assert [r.status_code for r in responses] == [200] * len(spread), [r.text for r in responses]
        assert len(one_session(api, user).target_sessions) == 1


def user_needing_web_approval(api, target):
    return user_with_access(
        api,
        target,
        credential_policy=sdk.UserRequireCredentialsPolicy(
            kubernetes=[sdk.CredentialKind.WEBUSERAPPROVAL],
        ),
    )


def approve(session, wg, approval_id):
    decide(session, wg, approval_id, "approve", {"scope": "Once"})


def reject(session, wg, approval_id):
    decide(session, wg, approval_id, "reject", None)


def decide(session, wg, approval_id, decision, body):
    response = session.post(
        f"https://localhost:{wg.http_port}/@warpgate/api/auth/state/{approval_id}/{decision}",
        json=body,
        timeout=10,
    )
    assert response.status_code == 200, response.text


def test_one_web_approval_admits_requests_on_both_nodes(nodes, echo_server_port):
    node, peer = nodes
    with admin_client(f"https://localhost:{node.http_port}") as api:
        target = create_target(api, echo_server_port)
        user = user_needing_web_approval(api, target)

        # Approve from the node that isn't holding the request.
        with login(peer, api, user) as session, ThreadPoolExecutor(max_workers=2) as pool:
            token = create_api_token(session, peer)

            on_opener = pool.submit(token_request, node, token, target)
            pending = poll(lambda: pending_kubernetes_approvals(session, peer))
            assert len(pending) == 1, pending

            # Must not raise a second approval.
            on_peer = pool.submit(token_request, peer, token, target)
            time.sleep(1)
            assert len(pending_kubernetes_approvals(session, peer)) == 1
            assert not on_opener.done() and not on_peer.done()

            approve(session, peer, pending[0]["id"])
            assert on_opener.result().status_code == 200
            assert on_peer.result().status_code == 200

        one_session(api, user)


def test_a_rejected_approval_refuses_requests_on_both_nodes(nodes, echo_server_port):
    node, peer = nodes
    with admin_client(f"https://localhost:{node.http_port}") as api:
        target = create_target(api, echo_server_port)
        user = user_needing_web_approval(api, target)

        with login(peer, api, user) as session, ThreadPoolExecutor(max_workers=2) as pool:
            token = create_api_token(session, peer)

            on_opener = pool.submit(token_request, node, token, target)
            (pending,) = poll(lambda: pending_kubernetes_approvals(session, peer))
            on_peer = pool.submit(token_request, peer, token, target)
            time.sleep(1)
            assert not on_peer.done()

            reject(session, peer, pending["id"])
            assert on_opener.result().status_code == 401
            assert on_peer.result().status_code == 401

            # The rejection only applies to that attempt.
            retried = pool.submit(token_request, peer, token, target)
            fresh = poll(lambda: [
                r for r in pending_kubernetes_approvals(session, peer) if r["id"] != pending["id"]
            ])
            assert fresh, "the retry never raised its own approval"
            approve(session, peer, fresh[0]["id"])
            assert retried.result().status_code == 200


def test_a_session_whose_owner_died_stops_serving_on_the_joined_node(nodes, echo_server_port):
    node, peer = nodes
    with admin_client(f"https://localhost:{peer.http_port}") as api:
        user = api.create_user(sdk.CreateUserRequest(username=f"ticket-{uuid4()}"))
        setup = api, user, create_target(api, echo_server_port)
        ticket = create_ticket(setup, number_of_uses=1)
        assert ticket_request(node, ticket).status_code == 200
        assert ticket_request(peer, ticket).status_code == 200
        one_session(api, user)
        # Raw DB ids for the sqlite helpers.
        session_id, node_id = _live_session_node(peer.config_path)

        _hard_kill(node)
        _expire_heartbeat(peer.config_path, node_id)
        # Reaper interval (15s), plus margin.
        assert poll(lambda: _session_ended(peer.config_path, session_id), deadline_s=30), \
            "dead node's session was not marked ended"

        # The peer only had a view of the dead node's session, and the ticket
        # is spent.
        assert ticket_request(peer, ticket).status_code == 401
        assert uses_left(setup, ticket) == 0


def test_an_abandoned_approval_does_not_hold_up_the_other_node(nodes, echo_server_port):
    node, peer = nodes
    with admin_client(f"https://localhost:{node.http_port}") as api:
        target = create_target(api, echo_server_port)
        user = user_needing_web_approval(api, target)

        with login(peer, api, user) as session, ThreadPoolExecutor(max_workers=2) as pool:
            token = create_api_token(session, peer)

            # Client times out while the approval is pending.
            abandoned = pool.submit(token_request, node, token, target, timeout=3)
            (first,) = poll(lambda: pending_kubernetes_approvals(session, peer))
            with pytest.raises(requests.exceptions.ReadTimeout):
                abandoned.result()

            # The peer must start a fresh attempt, not wait on the dead one.
            retried = pool.submit(token_request, peer, token, target)
            fresh = poll(lambda: [
                r for r in pending_kubernetes_approvals(session, peer) if r["id"] != first["id"]
            ])
            assert fresh, "the retry never raised its own approval"
            approve(session, peer, fresh[0]["id"])
            assert retried.result().status_code == 200


def test_closing_a_shared_session_ends_it_on_both_nodes(nodes, echo_server_port):
    node, peer = nodes
    # Close from the joining node, not the owner.
    with admin_client(f"https://localhost:{peer.http_port}") as api:
        user = api.create_user(sdk.CreateUserRequest(username=f"ticket-{uuid4()}"))
        setup = api, user, create_target(api, echo_server_port)
        ticket = create_ticket(setup, number_of_uses=1)
        assert ticket_request(node, ticket).status_code == 200
        assert ticket_request(peer, ticket).status_code == 200

        api.close_session(one_session(api, user).id)

        # Reopening would need a second ticket use.
        assert ticket_request(node, ticket).status_code == 401
        assert ticket_request(peer, ticket).status_code == 401
        assert uses_left(setup, ticket) == 0
