"""End-to-end evidence for what `WarpgateError` puts in an HTTP response body.

The unit tests in `warpgate-common/src/error.rs` exercise `as_response()`
directly. These go one level out and prove the same property where it is
actually reachable: a real warpgate process, a real HTTP client, and two
paths a real caller takes -- one of them without authenticating at all.

Every test here asserts the detail reached the *log*, keyed by the
correlation id the client was given. Without that half a test would pass
just as happily if the endpoint had never run, or if the fix had discarded
the error instead of relocating it.
"""

import re
import sqlite3
import subprocess
import time
from pathlib import Path

import requests
import urllib3
import yaml

from .conftest import ProcessManager
from .util import alloc_port, wait_port

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Distinctive enough that finding either string in a response body can only
# mean it came from the admin-configured whitelist.
WHITELIST = ["sso-internal.corp.example", "idp-backup.corp.example"]

# Not on the whitelist. An anonymous caller picks this value themselves: the
# `Host` header is theirs to set, and warpgate reads it directly whenever
# `trust_x_forwarded_headers` is off, which is the default.
SPOOFED_HOST = "attacker.example"

ADMIN_TOKEN_HEADER = {"X-Warpgate-Token": "token-value"}

REFERENCE = re.compile(
    r"^Internal Server Error \(reference: "
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\)$"
)


def _start_wg_with_log(processes: ProcessManager, tmp_path: Path, config_patch: dict):
    """Start warpgate with its own log captured to a file.

    Returned as a path rather than a pipe because both tests read the log
    *after* the request they are about, and a pipe nobody drains would
    deadlock the process once its buffer filled.
    """
    log_path = tmp_path / "warpgate.log"
    log_file = log_path.open("w")
    wg = processes.start_wg(
        config_patch=config_patch,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    return wg, log_path


def _log_after(log_path: Path, deadline: float = 5.0) -> str:
    """Read the log, giving warpgate a moment to flush the line we want.

    The request has already returned by the time this is called, but the
    `tracing` write happens on warpgate's side of the socket and can trail
    the response.
    """
    end = time.time() + deadline
    text = ""
    while time.time() < end:
        text = log_path.read_text(errors="replace")
        if "Request failed with an internal error" in text:
            break
        time.sleep(0.2)
    return text


def _sqlite_path(wg) -> Path:
    """Resolve the running instance's SQLite file from its own config."""
    config = yaml.safe_load(wg.config_path.open())
    url = config["database_url"]
    assert url.startswith("sqlite:"), f"test assumes SQLite, got {url!r}"
    # `sqlite:` may be followed by an absolute path or one relative to the
    # data directory; `sqlite://` is the same thing with an empty authority.
    raw = url[len("sqlite:"):].split("?", 1)[0]
    if raw.startswith("//"):
        raw = raw[2:]
    path = Path(raw)
    if not path.is_absolute():
        path = wg.config_path.parent / path
    # The URL names the directory warpgate keeps the database in, not the
    # file: alongside it sit the WAL and shared-memory files.
    if path.is_dir():
        path = path / "db.sqlite3"
    assert path.exists(), f"no database at {path}"
    return path


def test_the_configured_whitelist_never_reaches_an_anonymous_caller(
    processes: ProcessManager, tmp_path: Path
):
    """The one path in this family an unauthenticated visitor can reach.

    `return_url_domain: host_header` is what makes warpgate consult the
    request's own `Host` header, and so what puts the whitelist on this code
    path at all -- in `external_host` mode no whitelist is ever passed. The
    caller supplies a host that is not on the list and warpgate has to refuse;
    the question this test asks is what it says while refusing.
    """
    sso_provider = {
        "name": "corp-idp",
        "label": "Corp IdP",
        "provider": {
            "type": "custom",
            "client_id": "warpgate-test",
            "client_secret": "warpgate-test-secret",
            # Never contacted: the whitelist check refuses before warpgate
            # builds an SSO client, which is exactly why an anonymous caller
            # reaches it.
            "issuer_url": f"http://localhost:{alloc_port()}",
            "scopes": ["openid", "email", "profile"],
        },
        "return_url_domain": "host_header",
        "return_domain_whitelist": WHITELIST,
    }
    wg, log_path = _start_wg_with_log(
        processes, tmp_path, {"sso_providers": [sso_provider]}
    )

    response = requests.get(
        f"https://localhost:{wg.http_port}/@warpgate/api/sso/providers/corp-idp/start",
        headers={"Host": SPOOFED_HOST},
        verify=False,
        timeout=10,
        allow_redirects=False,
    )
    body = response.text

    for domain in WHITELIST:
        assert domain not in body, (
            f"an anonymous caller was told the configured whitelist: {body!r}"
        )
    assert "whitelist" not in body.lower(), (
        f"the refusal described the check it failed: {body!r}"
    )
    assert SPOOFED_HOST not in body, f"the request was reflected back: {body!r}"

    match = REFERENCE.match(body.strip())
    assert match, f"no correlation id to hand an operator: {body!r}"

    # The other half. Without it this test would also pass if the request had
    # never reached the whitelist check, or if the fix had simply dropped the
    # error on the floor.
    log = _log_after(log_path)
    correlation_id = match.group(1)
    line = next(
        (line for line in log.splitlines() if correlation_id in line),
        None,
    )
    assert line is not None, (
        f"correlation id {correlation_id} appears in no log line -- "
        "the caller was handed a reference an operator cannot look up"
    )
    for domain in WHITELIST:
        assert domain in line, (
            f"the whitelist did not survive into the log either: {line!r}"
        )


def test_an_anonymous_caller_gets_no_database_error_from_the_info_endpoint(
    processes: ProcessManager, tmp_path: Path
):
    """The second door, and the one that needed a second pair of eyes.

    `WarpgateError::as_response()` only runs for an error that reaches poem
    *as* a `WarpgateError`. `GET /@warpgate/api/info` reaches its database
    through `.context("loading LDAP servers")`, which turns a `sea_orm::DbErr`
    into an `anyhow::Error` and then into a plain `poem::Error` -- whose own
    `Display` renders an anyhow source with `{err:#}`, the entire causal
    chain. No credential of any kind is needed: this is the endpoint the
    single-page app calls before anyone logs in.
    """
    wg, log_path = _start_wg_with_log(processes, tmp_path, {})
    url = f"https://localhost:{wg.http_port}/@warpgate/api/info"

    healthy = requests.get(url, verify=False, timeout=10)
    assert healthy.status_code == 200, (
        f"the endpoint was already broken before the test touched it: "
        f"{healthy.status_code} {healthy.text!r}"
    )

    database = _sqlite_path(wg)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE ldap_servers")

    # No cookie, no token, no client certificate.
    response = requests.get(url, verify=False, timeout=10)
    body = response.text

    assert response.status_code == 500, (
        f"dropping the table did not fail the query: "
        f"{response.status_code} {body!r}"
    )
    for fragment in ("no such table", "ldap_servers", "LDAP", "Query Error", "sqlx"):
        assert fragment not in body, (
            f"the database's own words reached an anonymous caller "
            f"({fragment!r}): {body!r}"
        )

    match = REFERENCE.match(body.strip())
    assert match, f"no correlation id to hand an operator: {body!r}"

    log = _log_after(log_path)
    correlation_id = match.group(1)
    line = next((line for line in log.splitlines() if correlation_id in line), None)
    assert line is not None, (
        f"correlation id {correlation_id} appears in no log line -- "
        "the caller was handed a reference an operator cannot look up"
    )
    assert "ldap_servers" in line, (
        f"the database error did not survive into the log either: {line!r}"
    )


def test_the_same_endpoint_still_says_what_it_can_say(
    processes: ProcessManager, tmp_path: Path
):
    """The other direction, from the same handler and the same status code.

    Removing `external_host` from the config makes this endpoint fail with
    `ExternalHostUnknown` instead of `ExternalHostNotWhitelisted`. Both are
    Warpgate-authored, both are a 500 from one line of one handler -- and only
    one of them names something the caller has no business learning. Whatever
    tells them apart has to be the variant, because nothing else here differs.

    Unlike the two tests above this one passes on both sides of the change, by
    construction: caller-authored variants render identically before and
    after. It is not evidence the fix works. It is what fails if someone
    "fixes" this again by muting everything.
    """
    sso_provider = {
        "name": "corp-idp",
        "label": "Corp IdP",
        "provider": {
            "type": "custom",
            "client_id": "warpgate-test",
            "client_secret": "warpgate-test-secret",
            "issuer_url": f"http://localhost:{alloc_port()}",
            "scopes": ["openid", "email", "profile"],
        },
        # Left at the default (`external_host`), so the handler resolves the
        # URL from config rather than from the request -- and there is now no
        # `external_host` in the config to resolve.
        "return_domain_whitelist": WHITELIST,
    }
    wg, _log_path = _start_wg_with_log(
        processes,
        tmp_path,
        {"sso_providers": [sso_provider], "external_host": None},
    )

    response = requests.get(
        f"https://localhost:{wg.http_port}/@warpgate/api/sso/providers/corp-idp/start",
        verify=False,
        timeout=10,
        allow_redirects=False,
    )
    body = response.text

    assert response.status_code == 500, (
        f"expected the same status as the leaking case: "
        f"{response.status_code} {body!r}"
    )
    assert "external_host" in body, (
        f"the caller was not told what to configure: {body!r}"
    )
    assert "is not set" in body, f"the refusal lost its meaning: {body!r}"
    assert not REFERENCE.match(body.strip()), (
        f"a message written for the caller was flattened away: {body!r}"
    )
    # And it did not quietly leak the whitelist by another route.
    for domain in WHITELIST:
        assert domain not in body, f"the whitelist reached the caller: {body!r}"


def test_a_database_failure_does_not_hand_its_sql_to_the_client(
    processes: ProcessManager, tmp_path: Path
):
    """The archetypal case: a `sea_orm::DbErr` surfacing through a handler.

    The failure is induced rather than waited for, but the path is the real
    one -- an ordinary admin request whose query fails underneath it, which is
    what a corrupted, migrated-past or partially-restored database looks like
    from inside a handler.
    """
    wg, log_path = _start_wg_with_log(processes, tmp_path, {})
    url = f"https://localhost:{wg.http_port}/@warpgate/admin/api/targets"

    healthy = requests.get(
        url, headers=ADMIN_TOKEN_HEADER, verify=False, timeout=10
    )
    assert healthy.status_code == 200, (
        f"the endpoint was already broken before the test touched it: "
        f"{healthy.status_code} {healthy.text!r}"
    )

    database = _sqlite_path(wg)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE targets")

    response = requests.get(
        url, headers=ADMIN_TOKEN_HEADER, verify=False, timeout=10
    )
    body = response.text

    assert response.status_code == 500, (
        f"dropping the table did not fail the query: "
        f"{response.status_code} {body!r}"
    )
    for fragment in ("no such table", "targets", "SELECT", "sqlx", "sea_orm"):
        assert fragment not in body, (
            f"the database's own words reached the client ({fragment!r}): {body!r}"
        )

    match = REFERENCE.match(body.strip())
    assert match, f"no correlation id to hand an operator: {body!r}"

    log = _log_after(log_path)
    correlation_id = match.group(1)
    line = next(
        (line for line in log.splitlines() if correlation_id in line),
        None,
    )
    assert line is not None, (
        f"correlation id {correlation_id} appears in no log line -- "
        "the caller was handed a reference an operator cannot look up"
    )
    assert "no such table" in line, (
        f"the database error did not survive into the log either: {line!r}"
    )
