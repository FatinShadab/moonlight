"""Bounded executable hashing; never loads or executes the target binary."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from moonlight.collectors.common import CollectionFailure, evidence
from moonlight.collectors.subprocesses import CommandRunner, SubprocessRunner
from moonlight.core.evidence import EvidenceItem, EvidenceKind


@dataclass(frozen=True)
class HashLimits:
    max_bytes: int = 256 * 1024 * 1024
    chunk_bytes: int = 1024 * 1024
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        if min(self.max_bytes, self.chunk_bytes, self.timeout_seconds) <= 0:
            raise ValueError("hash limits must be positive")


class FileStamp(BaseModel):
    """Metadata used to detect ordinary file replacement or modification."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    size_bytes: int = Field(ge=0)
    modified_ns: int
    device: int
    inode: int

    @classmethod
    def from_stat(cls, result: os.stat_result) -> FileStamp:
        return cls(
            size_bytes=result.st_size,
            modified_ns=result.st_mtime_ns,
            device=result.st_dev,
            inode=result.st_ino,
        )


class FileHash(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stamp: FileStamp


class HashReply(BaseModel):
    """Small validated message from the helper, including normalized failures."""

    model_config = ConfigDict(extra="forbid")
    result: FileHash | None = None
    reason: str | None = None
    availability: Literal["unavailable", "error"] = "unavailable"


class HashAccess(Protocol):
    def hash(self, path: str, limits: HashLimits) -> FileHash: ...


class WorkerHashAccess:
    """A helper process puts a hard timeout around open, stat and read calls."""

    def __init__(
        self,
        runner: CommandRunner | None = None,
        *,
        worker_module: str = "moonlight.collectors.hash_worker",
    ) -> None:
        self.runner = runner if runner is not None else SubprocessRunner()
        self.worker_module = worker_module

    def hash(self, path: str, limits: HashLimits) -> FileHash:
        reply = HashReply.model_validate_json(
            self.runner.run(
                [
                    sys.executable,
                    "-m",
                    self.worker_module,
                    str(limits.max_bytes),
                    str(limits.chunk_bytes),
                    path,
                ],
                timeout=limits.timeout_seconds,
            )
        )
        if reply.result is None:
            raise CollectionFailure(
                reply.reason or "invalid_hash_worker_reply", reply.availability
            )
        return reply.result


def collect_hash(
    subject_id: str,
    path: str | None,
    *,
    access: HashAccess | None = None,
    limits: HashLimits | None = None,
) -> EvidenceItem:
    """Return the hash or an explicit missing/error item for this process."""
    access = access if access is not None else WorkerHashAccess()
    limits = limits if limits is not None else HashLimits()

    def read() -> JsonValue:
        if not path:
            raise CollectionFailure("executable_path_unavailable")
        return access.hash(path, limits).model_dump(mode="json")

    return evidence(subject_id, "hash_collector", EvidenceKind.SHA256, read)
