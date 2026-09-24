"""Regression tests for the per-test process/container cleanup fixture in
conftest.py (`_stop_test_processes`).

That fixture is meant to stop only what a test starts for itself, leaving
children (and k3s containers) started by higher-scoped fixtures -- like the
session-scoped `processes`/`shared_wg` -- alone. These tests check both
halves directly against `ProcessManager`, without starting anything as heavy
as a real warpgate process, SSH server, or k3s container.

Pytest collects and runs the tests in a file in the order they're defined
(no ordering plugin is installed here), so `test_b_...` below can check what
`test_a_...` left running, and `test_a_...` can check what a session-scoped
fixture leaves running across both.
"""

import subprocess

import pytest

from . import conftest
from .conftest import ProcessManager

# Set by `test_a_...`, read by `test_b_...` (see the module docstring).
_test_owned_process: subprocess.Popen | None = None


@pytest.fixture(scope="session")
def _session_owned_child(processes: ProcessManager):
    """Stands in for a real session-scoped fixture (e.g. `shared_wg`):
    started once, before any test's cleanup mark is taken, so it must survive
    every individual test's teardown."""
    return processes.start(["sleep", "60"])


def test_a_a_child_started_in_a_test_is_stopped_when_the_test_ends(
    processes: ProcessManager, _session_owned_child: subprocess.Popen
):
    global _test_owned_process
    # Started inside the test body, i.e. after `_stop_test_processes` has
    # already taken its mark -- this is what the fixture should stop.
    _test_owned_process = processes.start(["sleep", "60"])
    assert _test_owned_process.poll() is None, "the child should still be running"

    # The session fixture's child was started before the mark and must still
    # be up too, for test_b to check it survives.
    assert _session_owned_child.poll() is None


def test_b_a_test_owned_child_is_gone_but_a_session_owned_one_survives(
    _session_owned_child: subprocess.Popen,
):
    assert _test_owned_process is not None, "test_a did not run first"
    assert _test_owned_process.poll() is not None, (
        "a child started inside a test must be stopped once that test ends"
    )
    assert _session_owned_child.poll() is None, (
        "a child started by a session-scoped fixture must survive into later tests"
    )


def test_k3s_container_bookkeeping_is_trimmed_by_stop_since(
    processes: ProcessManager, monkeypatch: pytest.MonkeyPatch
):
    """`stop_since` must roll back the k3s container list to the mark the
    same way it rolls back `children`. Exercised directly against the
    bookkeeping with `docker rm` stubbed out -- no container is actually
    started or removed."""
    removed_names = []
    monkeypatch.setattr(
        conftest.subprocess,
        "run",
        lambda args, **kwargs: removed_names.append(args[-1])
        or subprocess.CompletedProcess(args, 0),
    )

    mark = processes.mark()
    processes._k3s_containers.append("fake-k3s-container-for-test")
    assert "fake-k3s-container-for-test" in processes._k3s_containers

    processes.stop_since(mark)

    assert "fake-k3s-container-for-test" not in processes._k3s_containers
    assert removed_names == ["fake-k3s-container-for-test"]
