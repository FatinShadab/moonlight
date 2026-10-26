"""Hashing OS boundaries use inert bytes, never a target executable."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock, Mock

import pytest

from moonlight.collectors.common import CollectionFailure
from moonlight.collectors.hash_worker import hash_file, main
from moonlight.collectors.hashing import (
    FileHash,
    FileStamp,
    HashAccess,
    HashLimits,
    HashReply,
    WorkerHashAccess,
    collect_hash,
)
from moonlight.collectors.subprocesses import CommandRunner, SubprocessRunner


@pytest.fixture
def file_hash() -> FileHash:
    return FileHash(
        sha256=hashlib.sha256(b"abc").hexdigest(),
        stamp=FileStamp(size_bytes=3, modified_ns=10, device=1, inode=2),
    )


def fake_stat(size: int = 3, modified: int = 1) -> os.stat_result:
    return cast(
        os.stat_result,
        Mock(
            spec=os.stat_result,
            st_mode=stat.S_IFREG | 0o444,
            st_ino=2,
            st_dev=1,
            st_size=size,
            st_mtime_ns=modified * 1000000000,
        ),
    )


def stream_mock(chunks: list[bytes]) -> MagicMock:
    stream = MagicMock()
    stream.__enter__.return_value = stream
    stream.read.side_effect = chunks
    stream.fileno.return_value = 123
    return stream


def test_streams_in_chunks_and_closes() -> None:
    stream = stream_mock([b"ab", b"c", b""])
    opened = Mock(return_value=stream)
    result = hash_file(
        "untrusted.exe",
        HashLimits(chunk_bytes=2),
        open_file=opened,
        stat_file=Mock(return_value=fake_stat()),
    )
    assert result.sha256 == hashlib.sha256(b"abc").hexdigest()
    assert all(call.args == (2,) for call in stream.read.call_args_list)
    opened.assert_called_once_with("untrusted.exe")
    stream.__exit__.assert_called_once()


def test_oversize_skips_read() -> None:
    stream = stream_mock([])
    with pytest.raises(CollectionFailure, match="size_limit_exceeded"):
        hash_file(
            "large",
            HashLimits(max_bytes=2),
            open_file=Mock(return_value=stream),
            stat_file=Mock(return_value=fake_stat()),
        )
    stream.read.assert_not_called()


def test_growth_is_bounded_by_actual_bytes() -> None:
    stream = stream_mock([b"abc", b"d"])
    with pytest.raises(CollectionFailure, match="size_limit_exceeded"):
        hash_file(
            "growing",
            HashLimits(max_bytes=3, chunk_bytes=3),
            open_file=Mock(return_value=stream),
            stat_file=Mock(return_value=fake_stat()),
        )
    assert stream.read.call_args_list[-1].args == (1,)


@pytest.mark.parametrize("after", [fake_stat(modified=2), fake_stat(size=4)])
def test_changed_file_is_discarded(after: os.stat_result) -> None:
    stream = stream_mock([b"abc", b""])
    with pytest.raises(CollectionFailure, match="file_changed_during_hash"):
        hash_file(
            "changed",
            HashLimits(),
            open_file=Mock(return_value=stream),
            stat_file=Mock(side_effect=[fake_stat(), after]),
        )


@pytest.mark.parametrize(
    ("error", "availability", "reason"),
    [
        (PermissionError(), "unavailable", "access_denied"),
        (FileNotFoundError(), "unavailable", "file_or_tool_not_found"),
        (subprocess.TimeoutExpired(["python"], 1), "unavailable", "timeout"),
        (TimeoutError(), "unavailable", "timeout"),
        (OSError(), "error", "os_or_collector_error"),
        (ValueError(), "error", "os_or_collector_error"),
    ],
)
def test_worker_failure_becomes_evidence(
    error: Exception, availability: str, reason: str
) -> None:
    runner = Mock(spec=CommandRunner)
    runner.run.side_effect = error
    item = collect_hash("42:1.0", "app.exe", access=WorkerHashAccess(runner))
    assert item.availability == availability
    assert item.reason == reason
    assert item.value is None


def test_worker_arguments_and_timeout(file_hash: FileHash) -> None:
    runner = Mock(spec=CommandRunner)
    runner.run.return_value = HashReply(result=file_hash).model_dump_json().encode()
    path = "C:/Example/$(untrusted); 'file'.exe"
    item = collect_hash(
        "42:1.0",
        path,
        access=WorkerHashAccess(runner),
        limits=HashLimits(timeout_seconds=0.25),
    )
    assert item.availability == "observed"
    assert item.value == file_hash.model_dump(mode="json")
    args = runner.run.call_args.args[0]
    assert args[-1] == path
    assert args[1:3] == ["-m", "moonlight.collectors.hash_worker"]
    assert runner.run.call_args.kwargs == {"timeout": 0.25}


def test_worker_normalized_failure_and_invalid_reply() -> None:
    runner = Mock(spec=CommandRunner)
    runner.run.return_value = (
        HashReply(reason="access_denied").model_dump_json().encode()
    )
    assert (
        collect_hash("42:1.0", "app.exe", access=WorkerHashAccess(runner)).reason
        == "access_denied"
    )
    runner.run.return_value = b"not JSON"
    assert (
        collect_hash("42:1.0", "app.exe", access=WorkerHashAccess(runner)).availability
        == "error"
    )


def test_missing_path_does_not_spawn() -> None:
    access = Mock(spec=HashAccess)
    assert (
        collect_hash("42:1.0", None, access=access).reason
        == "executable_path_unavailable"
    )
    access.hash.assert_not_called()


def test_subprocess_adapter_is_shell_free(monkeypatch: pytest.MonkeyPatch) -> None:
    run = Mock(return_value=subprocess.CompletedProcess(["helper"], 0, b"result", b""))
    monkeypatch.setattr(subprocess, "run", run)
    assert SubprocessRunner().run(["helper", "$(untrusted)"], timeout=0.5) == b"result"
    assert run.call_args.args == (["helper", "$(untrusted)"],)
    assert run.call_args.kwargs["shell"] is False
    assert run.call_args.kwargs["timeout"] == 0.5
    assert run.call_args.kwargs["check"] is True


def test_real_worker_on_inert_fixture(tmp_path: Path) -> None:
    path = tmp_path / "inert bytes.exe"
    path.write_bytes(b"abc")
    result = WorkerHashAccess().hash(str(path), HashLimits())
    assert result.sha256 == hashlib.sha256(b"abc").hexdigest()


def test_worker_main_encodes_os_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "moonlight.collectors.hash_worker.hash_file",
        Mock(side_effect=PermissionError()),
    )
    assert main(["10", "2", "app.exe"]) == 0
    assert (
        HashReply.model_validate_json(capsys.readouterr().out).reason == "access_denied"
    )
