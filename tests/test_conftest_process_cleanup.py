"""Per-test cleanup stops new children and preserves shared resources."""

import subprocess

import pytest

from . import conftest
from .conftest import Context, ProcessManager


def test_cleanup_stops_new_children_and_preserves_shared_children(tmp_path, timeout):
    manager = ProcessManager(Context(tmp_path), timeout)
    try:
        shared_child = manager.start(["sleep", "60"])
        cleanup = conftest._stop_test_processes.__wrapped__(manager)
        next(cleanup)
        test_child = manager.start(["sleep", "60"])
        assert test_child.poll() is None

        with pytest.raises(StopIteration):
            next(cleanup)

        assert test_child.poll() is not None
        assert shared_child.poll() is None
        assert [child.process for child in manager.children] == [shared_child]
    finally:
        manager.stop()


def test_k3s_container_bookkeeping_is_trimmed_by_stop_since(
    tmp_path, timeout, monkeypatch: pytest.MonkeyPatch
):
    manager = ProcessManager(Context(tmp_path), timeout)
    removed_names = []

    def remove_container(args, **kwargs):
        removed_names.append(args[-1])
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(conftest.subprocess, "run", remove_container)
    manager._k3s_containers.append("shared-container")
    mark = manager.mark()
    manager._k3s_containers.append("test-container")

    manager.stop_since(mark)

    assert manager._k3s_containers == ["shared-container"]
    assert removed_names == ["test-container"]
