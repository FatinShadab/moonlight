"""Storage reports reuse P1 evidence and keep paths in redaction-ready fields."""

from __future__ import annotations

import hashlib
import os
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict

from moonlight.core.evidence import EvidenceBundle


def normalized_path(path: str) -> str:
    if path.startswith("\\\\.\\") or path.lower().startswith("\\\\?\\globalroot"):
        raise ValueError("device paths are not supported")
    if path.startswith("\\\\?\\UNC\\"):
        path = "\\\\" + path[8:]
    elif path.startswith("\\\\?\\"):
        path = path[4:]
    return os.path.normcase(os.path.abspath(path))


def path_id(path: str) -> str:
    return (
        "storage-"
        + hashlib.sha256(normalized_path(path).encode("utf-8")).hexdigest()[:32]
    )


class PathReference(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    root_id: str
    relative_path: str


class SelectedRoot(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    root_id: str
    path: str


StorageCategory = Literal["clearly_safe", "review_first", "do_not_touch"]


class StorageClassification(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    subject_id: str
    path: PathReference
    category: StorageCategory
    reason: str
    evidence_ids: tuple[str, ...]


class StorageReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    timestamp: AwareDatetime
    roots: tuple[SelectedRoot, ...]
    bundles: tuple[EvidenceBundle, ...]
    classifications: tuple[StorageClassification, ...] = ()
    snapshot_saved: bool = False
    snapshot_reason: str | None = None
    hash_candidates: int = 0
    files_hashed: int = 0
