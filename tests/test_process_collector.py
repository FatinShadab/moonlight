"""Synthetic process queries: success, races, and expected OS failures."""

from __future__ import annotations

import socket
from collections import namedtuple
from unittest.mock import Mock

import psutil
import pytest

from moonlight.collectors.process import (
    PROCESS_KINDS,
    CollectionError,
    PsutilAccess,
    collect_process,
)
from moonlight.core.evidence import EvidenceBundle, EvidenceKind

PROCESS_CLASS = psutil.Process


@pytest.fixture
def process(monkeypatch: pytest.MonkeyPatch) -> Mock:
    process = Mock(spec=psutil.Process)
    process.pid = 42
    process.create_time.return_value = 1700000000.125
    process.is_running.return_value = True
    process.exe.return_value = "C:/Example/app.exe"
    process.ppid.return_value = 0
    process.cmdline.return_value = ["app.exe", "--label", "$(untrusted); 'text'"]
    process.username.return_value = "EXAMPLE/test"
    Connection = namedtuple("Connection", "family type laddr raddr status")
    process.net_connections.return_value = [
        Connection(
            socket.AF_INET,
            socket.SOCK_STREAM,
            ("127.0.0.1", 1000),
            ("127.0.0.1", 2000),
            "ESTABLISHED",
        ),
        Connection(socket.AF_INET6, socket.SOCK_DGRAM, ("::1", 3000), (), "NONE"),
    ]
    Counters = namedtuple("Counters", "read_count write_count read_bytes write_bytes")
    process.io_counters.return_value = Counters(1, 2, 3, 4)
    monkeypatch.setattr(psutil, "Process", Mock(return_value=process))
    return process


def test_success_and_stable_identity(process: Mock) -> None:
    bundle = collect_process(42)
    assert isinstance(bundle, EvidenceBundle)
    assert bundle.subject_id == "42:1700000000.125"
    assert len(bundle.items) == 7
    assert all(item.availability == "observed" for item in bundle.items)
    values = {item.kind: item.value for item in bundle.items}
    assert values[EvidenceKind.EXECUTABLE_PATH] == "C:/Example/app.exe"
    assert values[EvidenceKind.PARENT_CHAIN] == []
    assert values[EvidenceKind.COMMAND_LINE] == process.cmdline.return_value
    assert values[EvidenceKind.USER] == "EXAMPLE/test"
    assert values[EvidenceKind.START_TIME] == {
        "epoch_seconds": 1700000000.125,
        "utc": "2023-11-14T22:13:20.125000+00:00",
    }
    assert values[EvidenceKind.IO_COUNTERS] == {
        "read_count": 1,
        "write_count": 2,
        "read_bytes": 3,
        "write_bytes": 4,
    }
    assert values[EvidenceKind.NETWORK_ACTIVITY] == [
        {
            "family": 2,
            "type": 1,
            "local": ["127.0.0.1", 1000],
            "remote": ["127.0.0.1", 2000],
            "status": "ESTABLISHED",
        },
        {
            "family": 23,
            "type": 2,
            "local": ["::1", 3000],
            "remote": [],
            "status": "NONE",
        },
    ]
    repeated = collect_process(42)
    assert isinstance(repeated, EvidenceBundle)
    assert [item.id for item in repeated.items] == [item.id for item in bundle.items]
    process.create_time.return_value += 1
    reused = collect_process(42)
    assert isinstance(reused, EvidenceBundle)
    assert reused.subject_id != bundle.subject_id
    assert reused.items[0].id != bundle.items[0].id


@pytest.mark.parametrize("kind", PROCESS_KINDS)
@pytest.mark.parametrize(
    ("error", "reason", "availability"),
    [
        (psutil.AccessDenied(42), "access_denied", "unavailable"),
        (psutil.NoSuchProcess(42), "process_exited_or_pid_reused", "unavailable"),
        (psutil.TimeoutExpired(1, pid=42), "timeout", "unavailable"),
        (TimeoutError(), "timeout", "unavailable"),
        (OSError(), "os_or_collector_error", "error"),
    ],
)
def test_each_field_failure_is_evidence(
    kind: EvidenceKind, error: Exception, reason: str, availability: str
) -> None:
    access = Mock(spec=PsutilAccess)
    access.creation_time.return_value = 1700000000.125
    access.read.side_effect = lambda pid, created, requested: (
        _raise(error) if requested == kind else "permitted"
    )
    bundle = collect_process(42, access)
    assert isinstance(bundle, EvidenceBundle)
    for item in bundle.items:
        if item.kind == kind:
            assert item.availability == availability
            assert item.reason == reason
            assert item.value is None
        else:
            assert item.availability == "observed"


def _raise(error: Exception) -> None:
    raise error


@pytest.mark.parametrize(
    "error", [psutil.AccessDenied(42), psutil.NoSuchProcess(42), TimeoutError()]
)
def test_identity_failure_returns_structured_error(error: Exception) -> None:
    access = Mock(spec=PsutilAccess)
    access.creation_time.side_effect = error
    result = collect_process(42, access)
    assert isinstance(result, CollectionError)
    assert result.error == "process_identity_unavailable"
    assert result.reason
    access.read.assert_not_called()


def test_pid_reused_during_read_discards_value(process: Mock) -> None:
    process.is_running.side_effect = [True, False] + [False] * 6
    bundle = collect_process(42)
    assert isinstance(bundle, EvidenceBundle)
    assert all(item.availability == "unavailable" for item in bundle.items)
    assert all(item.value is None for item in bundle.items)


def test_full_parent_chain(process: Mock, monkeypatch: pytest.MonkeyPatch) -> None:
    parent = Mock(spec=PROCESS_CLASS)
    parent.pid = 4
    parent.create_time.return_value = 1600000000.0
    parent.is_running.return_value = True
    parent.name.return_value = "parent.exe"
    parent.exe.return_value = "C:/Example/parent.exe"
    parent.ppid.return_value = 0
    process.ppid.return_value = 4
    process.parent.return_value = parent
    monkeypatch.setattr(
        psutil,
        "Process",
        Mock(side_effect=lambda pid: process if pid == 42 else parent),
    )
    value = PsutilAccess().read(42, 1700000000.125, EvidenceKind.PARENT_CHAIN)
    assert value == [
        {
            "pid": 4,
            "created": 1600000000.0,
            "name": "parent.exe",
            "path": "C:/Example/parent.exe",
        }
    ]


def test_missing_parent_is_unavailable(process: Mock) -> None:
    process.ppid.return_value = 4
    process.parent.return_value = None
    bundle = collect_process(42)
    assert isinstance(bundle, EvidenceBundle)
    item = next(item for item in bundle.items if item.kind == EvidenceKind.PARENT_CHAIN)
    assert item.availability == "unavailable"


@pytest.mark.parametrize("created", [float("nan"), float("inf"), -1.0])
def test_invalid_creation_time_cannot_form_identity(created: float) -> None:
    access = Mock(spec=PsutilAccess)
    access.creation_time.return_value = created
    assert isinstance(collect_process(42, access), CollectionError)
