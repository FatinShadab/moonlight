"""Tests for harmless process decoy execution and automatic cleanup."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from fixtures import harmless_process_decoy


def test_decoy_idler_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []
    monkeypatch.setattr(
        time,
        "sleep",
        lambda s: slept.append(s),
    )

    exit_code = harmless_process_decoy.run_process_decoy(tmp_path, "idler", seconds=2.0)
    assert exit_code == 0
    assert slept == [2.0]
    # Verify temporary directory is completely cleaned up
    assert list(tmp_path.iterdir()) == []


def test_decoy_temp_writer_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        time,
        "sleep",
        lambda _: None,
    )

    written = harmless_process_decoy.run_process_decoy(
        tmp_path, "temp_writer", seconds=1.0, max_bytes=8192
    )
    assert written == 8192
    # Verify temporary directory is completely cleaned up
    assert list(tmp_path.iterdir()) == []


def test_decoy_renamed_copy_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        time,
        "sleep",
        lambda _: None,
    )

    result = harmless_process_decoy.run_process_decoy(
        tmp_path, "renamed_copy", seconds=1.0
    )
    assert result == 1
    # Verify temporary directory is completely cleaned up
    assert list(tmp_path.iterdir()) == []


def test_decoy_bounds_safety_ceilings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    slept: list[float] = []
    monkeypatch.setattr(
        time,
        "sleep",
        lambda s: slept.append(s),
    )

    # Requesting 99999 seconds should be clamped to MAX_DURATION_SECONDS (60.0)
    harmless_process_decoy.run_process_decoy(tmp_path, "idler", seconds=99999.0)
    assert slept == [harmless_process_decoy.MAX_DURATION_SECONDS]
    assert list(tmp_path.iterdir()) == []


def test_decoy_exception_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_sleep(_: float) -> None:
        raise RuntimeError("Simulated failure")

    monkeypatch.setattr(
        time,
        "sleep",
        fail_sleep,
    )

    with pytest.raises(RuntimeError, match="Simulated failure"):
        harmless_process_decoy.run_process_decoy(tmp_path, "idler", seconds=1.0)
    # Temporary directory must be cleaned up even on exception
    assert list(tmp_path.iterdir()) == []
