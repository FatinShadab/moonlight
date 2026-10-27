"""Shared conversion of OS failures into explicit, citable evidence."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from datetime import UTC, datetime

import psutil
from pydantic import JsonValue

from moonlight.core.evidence import (
    Availability,
    EvidenceItem,
    EvidenceKind,
    make_evidence_id,
)


class CollectionFailure(Exception):
    """An expected collection failure, safe to serialize without OS input."""

    def __init__(self, reason: str, availability: Availability = "unavailable") -> None:
        super().__init__(reason)
        self.reason = reason
        self.availability = availability


OS_ERRORS = (
    CollectionFailure,
    psutil.Error,
    OSError,
    subprocess.SubprocessError,
    ValueError,
    # psutil's Windows extension can report native query failures this way.
    RuntimeError,
)


def failure_for(error: Exception) -> CollectionFailure:
    """Use fixed reasons; exception strings can contain sensitive OS data."""
    if isinstance(error, CollectionFailure):
        return error
    if isinstance(error, (psutil.AccessDenied, PermissionError)):
        return CollectionFailure("access_denied")
    if isinstance(error, psutil.NoSuchProcess):
        return CollectionFailure("process_exited_or_pid_reused")
    if isinstance(
        error, (TimeoutError, psutil.TimeoutExpired, subprocess.TimeoutExpired)
    ):
        return CollectionFailure("timeout")
    if isinstance(error, FileNotFoundError):
        return CollectionFailure("file_or_tool_not_found")
    return CollectionFailure("os_or_collector_error", "error")


def evidence(
    subject_id: str,
    source: str,
    kind: EvidenceKind,
    operation: Callable[[], JsonValue],
) -> EvidenceItem:
    """Observe one field, retaining expected failures as evidence items."""
    availability: Availability = "observed"
    reason: str | None = None
    value: JsonValue = None
    try:
        value = operation()
    except OS_ERRORS as error:
        failure = failure_for(error)
        availability, reason = failure.availability, failure.reason
    return EvidenceItem(
        id=make_evidence_id("process", subject_id, source, kind),
        source=source,
        kind=kind,
        value=value,
        availability=availability,
        reason=reason,
        timestamp=datetime.now(UTC),
    )
