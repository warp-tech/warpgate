"""Per-test cleanup stops new children and preserves shared resources."""

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

