"""Assemble process and executable observations without rules or AI calls."""

from __future__ import annotations

from moonlight.collectors.hashing import (
    FileHash,
    HashAccess,
    HashLimits,
    collect_hash,
)
from moonlight.collectors.process import CollectionError, ProcessAccess, collect_process
from moonlight.collectors.signature import SignatureCollector
from moonlight.core.evidence import EvidenceBundle, EvidenceKind


def collect_evidence(
    pid: int,
    *,
    process_access: ProcessAccess | None = None,
    hash_access: HashAccess | None = None,
    hash_limits: HashLimits | None = None,
    signature_collector: SignatureCollector | None = None,
) -> EvidenceBundle | CollectionError:
    """Collect one PID; absence of identity is a structured top-level error."""
    process = collect_process(pid, process_access)
    if isinstance(process, CollectionError):
        return process
    path_item = next(
        item for item in process.items if item.kind == EvidenceKind.EXECUTABLE_PATH
    )
    path = (
        path_item.value
        if path_item.availability == "observed" and isinstance(path_item.value, str)
        else None
    )
    hashed = collect_hash(
        process.subject_id, path, access=hash_access, limits=hash_limits
    )
    file_hash = (
        FileHash.model_validate(hashed.value)
        if hashed.availability == "observed"
        else None
    )
    signatures = (
        signature_collector if signature_collector is not None else SignatureCollector()
    )
    signature = signatures.collect(process.subject_id, path, file_hash)
    return EvidenceBundle(
        subject_type="process",
        subject_id=process.subject_id,
        items=(*process.items, hashed, signature),
    )
