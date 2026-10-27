"""Read-only process metadata through a small injectable OS boundary."""

from __future__ import annotations

import math
from datetime import UTC, datetime
from functools import partial
from typing import Protocol

import psutil
from pydantic import BaseModel, JsonValue

from moonlight.collectors.common import OS_ERRORS, evidence, failure_for
from moonlight.core.evidence import Availability, EvidenceBundle, EvidenceKind

PROCESS_KINDS = (
    EvidenceKind.EXECUTABLE_PATH,
    EvidenceKind.PARENT_CHAIN,
    EvidenceKind.COMMAND_LINE,
    EvidenceKind.START_TIME,
    EvidenceKind.USER,
    EvidenceKind.NETWORK_ACTIVITY,
    EvidenceKind.IO_COUNTERS,
)


class CollectionError(BaseModel):
    """No bundle can be attributed when process identity cannot be read."""

    pid: int
    availability: Availability
    reason: str
    error: str = "process_identity_unavailable"


class ProcessAccess(Protocol):
    """Only read operations; implementations never control target processes."""

    def creation_time(self, pid: int) -> float: ...

    def read(self, pid: int, created: float, kind: EvidenceKind) -> JsonValue: ...


def _guard(process: psutil.Process, created: float) -> None:
    # A fresh handle avoids psutil's cached creation time on the original handle.
    if psutil.Process(process.pid).create_time() != created or not process.is_running():
        raise psutil.NoSuchProcess(process.pid)


def _parents(process: psutil.Process) -> JsonValue:
    parents: list[JsonValue] = []
    seen = {process.pid}
    child_created = process.create_time()
    for _ in range(128):
        parent_pid = process.ppid()
        if parent_pid == 0:
            return parents
        parent = process.parent()
        if parent is None:
            raise psutil.NoSuchProcess(parent_pid)
        created = parent.create_time()
        if parent.pid in seen or created > child_created:
            raise psutil.NoSuchProcess(parent.pid)
        _guard(parent, created)
        entry: JsonValue = {
            "pid": parent.pid,
            "created": created,
            "name": parent.name(),
            "path": parent.exe(),
        }
        _guard(parent, created)
        parents.append(entry)
        seen.add(parent.pid)
        process, child_created = parent, created
    raise ValueError("parent chain exceeds traversal limit")


class PsutilAccess:
    """psutil adapter; all target operations are queries."""

    def creation_time(self, pid: int) -> float:
        return psutil.Process(pid).create_time()

    def read(self, pid: int, created: float, kind: EvidenceKind) -> JsonValue:
        process = psutil.Process(pid)
        _guard(process, created)
        value: JsonValue
        if kind == EvidenceKind.EXECUTABLE_PATH:
            path = process.exe()
            if not path:
                raise FileNotFoundError("no executable path")
            value = path
        elif kind == EvidenceKind.PARENT_CHAIN:
            value = _parents(process)
        elif kind == EvidenceKind.COMMAND_LINE:
            value = list(process.cmdline())
        elif kind == EvidenceKind.START_TIME:
            value = {
                "epoch_seconds": created,
                "utc": datetime.fromtimestamp(created, UTC).isoformat(),
            }
        elif kind == EvidenceKind.USER:
            value = process.username()
        elif kind == EvidenceKind.NETWORK_ACTIVITY:
            value = [
                {
                    "family": int(connection.family),
                    "type": int(connection.type),
                    "local": list(connection.laddr),
                    "remote": list(connection.raddr),
                    "status": connection.status,
                }
                for connection in process.net_connections(kind="inet")
            ]
        elif kind == EvidenceKind.IO_COUNTERS:
            counters = process.io_counters()
            value = {key: int(count) for key, count in counters._asdict().items()}
        else:
            raise ValueError("unsupported process evidence kind")
        _guard(process, created)
        return value


def collect_process(
    pid: int, access: ProcessAccess | None = None
) -> EvidenceBundle | CollectionError:
    """Collect independent fields; one denied field cannot hide other evidence."""
    access = access if access is not None else PsutilAccess()
    try:
        if pid < 0:
            raise ValueError("negative pid")
        created = access.creation_time(pid)
        if not math.isfinite(created) or created < 0:
            raise ValueError("invalid creation time")
    except OS_ERRORS as error:
        failure = failure_for(error)
        return CollectionError(
            pid=pid, availability=failure.availability, reason=failure.reason
        )
    subject_id = f"{pid}:{created!r}"
    return EvidenceBundle(
        subject_type="process",
        subject_id=subject_id,
        items=tuple(
            evidence(
                subject_id,
                "process_collector",
                kind,
                partial(access.read, pid, created, kind),
            )
            for kind in PROCESS_KINDS
        ),
    )
