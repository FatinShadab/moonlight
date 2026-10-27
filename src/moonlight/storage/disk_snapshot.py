"""Capture selected processes and roots without writing a snapshot destination."""

from __future__ import annotations

from moonlight.collectors.process import CollectionError, collect_process
from moonlight.core.evidence import EvidenceBundle
from moonlight.storage.attribution_models import DiskSnapshot
from moonlight.storage.scanner import ScanLimits, StorageScanner


def capture_disk_snapshot(roots: list[str], pids: list[int]) -> DiskSnapshot:
    """Only selected PIDs are sampled; enumeration of all processes is not implied."""
    # Duplicate hashes do not support attribution and can delay process samples.
    storage = StorageScanner(limits=ScanLimits(max_hash_files=0)).scan(roots)
    processes: list[EvidenceBundle] = []
    errors: list[CollectionError] = []
    for pid in sorted(set(pids)):
        result = collect_process(pid, include_open_files=True)
        if isinstance(result, CollectionError):
            errors.append(result)
        else:
            processes.append(result)
    return DiskSnapshot(
        storage=storage, processes=tuple(processes), collection_errors=tuple(errors)
    )
