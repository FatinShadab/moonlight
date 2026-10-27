"""Local storage scan, snapshot and rule composition; no action implementation."""

from __future__ import annotations

from datetime import datetime

from moonlight.rules.storage import StorageLocations, classify_storage
from moonlight.storage.locations import discover_locations
from moonlight.storage.models import StorageReport
from moonlight.storage.scanner import StorageScanner, selected_roots
from moonlight.storage.snapshots import SQLiteSnapshotStore


def investigate_storage(
    roots: list[str],
    snapshot_path: str,
    *,
    scanner: StorageScanner | None = None,
    locations: StorageLocations | None = None,
    timestamp: datetime | None = None,
) -> StorageReport:
    store = SQLiteSnapshotStore(snapshot_path)
    store.validate_destination(selected_roots(roots))
    scanner = scanner if scanner is not None else StorageScanner()
    report = scanner.scan(roots, timestamp=timestamp)
    report = store.compare_and_save(report)
    locations = locations if locations is not None else discover_locations()
    return classify_storage(report, locations)
