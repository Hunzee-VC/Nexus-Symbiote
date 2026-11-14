"""The scaling helper measures the work it is given, not the garbage collector."""

from __future__ import annotations

import gc

import pytest

from tests.support import scaling_ratio


def test_the_collector_is_off_while_a_run_is_timed_and_restored_afterwards():
    seen = []

    def run(scale):
        seen.append(gc.isenabled())

    assert gc.isenabled()
    scaling_ratio(run)
    assert seen and not any(seen)
    assert gc.isenabled()


def test_a_run_that_raises_leaves_the_collector_as_it_was():
    def run(scale):
        raise RuntimeError("stop")

    with pytest.raises(RuntimeError):
        scaling_ratio(run)
    assert gc.isenabled()


def test_a_collector_that_was_off_stays_off():
    gc.disable()
    try:
        scaling_ratio(lambda scale: None)
        assert not gc.isenabled()
    finally:
        gc.enable()


def test_linear_work_reads_as_linear_beside_a_large_heap_of_tracked_objects():
    held = [[index] for index in range(400_000)]

    def run(scale):
        return [[index] for index in range(60_000 * scale)]

    assert scaling_ratio(run) < 8
    assert len(held) == 400_000
