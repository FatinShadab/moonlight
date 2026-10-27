"""Small, in-process safety checks for the disk-link decoy."""

from __future__ import annotations

import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest
from fixtures import disk_link_decoy


@pytest.fixture(autouse=True)
def ample_space(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        shutil,
        "disk_usage",
        lambda _folder: SimpleNamespace(free=disk_link_decoy.MIN_FREE_BYTES),
    )


@pytest.mark.parametrize("mode", ["hold", "reopen"])
def test_byte_cap_and_cleanup(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], mode: disk_link_decoy.Mode
) -> None:
    written = disk_link_decoy.run_decoy(tmp_path, mode, 64 * 1024, 1.0)

    assert written == 64 * 1024
    assert list(tmp_path.iterdir()) == []
    folder, pid = capsys.readouterr().out.splitlines()
    assert Path(folder).parent == tmp_path
    assert pid.isdecimal()


@pytest.mark.parametrize("mode", ["hold", "reopen"])
def test_time_cap_and_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: disk_link_decoy.Mode
) -> None:
    clock = [0.0]

    def sleep(seconds: float) -> None:
        clock[0] += seconds

    monkeypatch.setattr(
        disk_link_decoy,
        "time",
        SimpleNamespace(monotonic=lambda: clock[0], sleep=sleep),
    )

    written = disk_link_decoy.run_decoy(
        tmp_path, mode, 4 * len(disk_link_decoy.CHUNK), 0.2
    )

    assert written == len(disk_link_decoy.CHUNK)
    assert clock[0] == 0.2
    assert list(tmp_path.iterdir()) == []


def test_low_space_refuses_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        shutil,
        "disk_usage",
        lambda _folder: SimpleNamespace(free=disk_link_decoy.MIN_FREE_BYTES - 1),
    )

    with pytest.raises(SystemExit, match="at least 1 GiB free"):
        disk_link_decoy.run_decoy(tmp_path, "hold", 64 * 1024, 1.0)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("error", [KeyboardInterrupt, RuntimeError])
def test_exception_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: type[BaseException]
) -> None:
    def interrupt(_seconds: float) -> None:
        raise error

    monkeypatch.setattr(
        disk_link_decoy,
        "time",
        SimpleNamespace(monotonic=lambda: 0.0, sleep=interrupt),
    )

    with pytest.raises(error):
        disk_link_decoy.run_decoy(tmp_path, "hold", 2 * len(disk_link_decoy.CHUNK), 1.0)
    assert list(tmp_path.iterdir()) == []
