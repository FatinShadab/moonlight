"""Local SQLite folder snapshots; never write within a selected scan root."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path
from typing import Protocol

from pydantic import JsonValue

from moonlight.collectors.common import OS_ERRORS, CollectionFailure
from moonlight.core.evidence import (
    Availability,
    EvidenceBundle,
    EvidenceItem,
    EvidenceKind,
    bounded_evidence_item,
    make_evidence_id,
)
from moonlight.storage.filesystem import LocalFileSystem
from moonlight.storage.models import SelectedRoot, StorageReport, normalized_path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS storage_scans (
    id INTEGER PRIMARY KEY,
    root_id TEXT NOT NULL,
    timestamp TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS storage_scan_root ON storage_scans(root_id, id);
CREATE TABLE IF NOT EXISTS folder_sizes (
    scan_id INTEGER NOT NULL REFERENCES storage_scans(id),
    subject_id TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    complete INTEGER NOT NULL CHECK(complete IN (0, 1)),
    PRIMARY KEY(scan_id, subject_id)
);
"""


class SnapshotStore(Protocol):
    def compare_and_save(self, report: StorageReport) -> StorageReport: ...


def _folder_item(bundle: EvidenceBundle) -> EvidenceItem | None:
    return next(
        (item for item in bundle.items if item.kind == EvidenceKind.FOLDER_SIZE), None
    )


def _growth(
    bundle: EvidenceBundle,
    timestamp: datetime,
    *,
    previous: tuple[str, int, bool] | None = None,
    failure: str | None = None,
) -> EvidenceItem:
    folder = _folder_item(bundle)
    assert folder is not None and isinstance(folder.value, dict)
    path = folder.value["path"]
    reason = failure
    value: dict[str, JsonValue] = {
        "path": path,
        "delta_bytes": None,
        "bytes_per_second": None,
    }
    if reason is None and folder.availability != "observed":
        reason = "current_size_unavailable"
    if reason is None and previous is None:
        reason = "no_previous_snapshot"
    if reason is None and previous is not None:
        previous_time, previous_size, complete = previous
        interval = (timestamp - datetime.fromisoformat(previous_time)).total_seconds()
        if not complete:
            reason = "previous_size_unavailable"
        elif interval <= 0:
            reason = "non_positive_scan_interval"
        else:
            size = folder.value["size_bytes"]
            assert isinstance(size, int)
            delta = size - previous_size
            value.update(
                {
                    "delta_bytes": delta,
                    "bytes_per_second": delta / interval,
                    "interval_seconds": interval,
                    "previous_timestamp": previous_time,
                    "basis": "logical_bytes_excluding_links",
                }
            )
    availability: Availability = "unavailable" if reason is not None else "observed"
    return bounded_evidence_item(
        id=make_evidence_id(
            "storage", bundle.subject_id, "snapshot_store", EvidenceKind.GROWTH_RATE
        ),
        source="snapshot_store",
        kind=EvidenceKind.GROWTH_RATE,
        value=value,
        availability=availability,
        reason=reason,
        timestamp=timestamp,
    )


def unavailable_snapshots(report: StorageReport, reason: str) -> StorageReport:
    bundles = tuple(
        bundle.model_copy(
            update={
                "items": (
                    *bundle.items,
                    _growth(
                        bundle,
                        report.timestamp,
                        failure=reason,
                    ),
                )
            }
        )
        if _folder_item(bundle) is not None
        else bundle
        for bundle in report.bundles
    )
    return report.model_copy(
        update={
            "bundles": bundles,
            "snapshot_saved": False,
            "snapshot_reason": reason,
        }
    )


class SQLiteSnapshotStore:
    def __init__(self, path: str) -> None:
        self.path = Path(normalized_path(path))

    def validate_destination(self, roots: tuple[SelectedRoot, ...]) -> None:
        if self.path.drive.startswith("\\\\"):
            raise ValueError("snapshot database must be local")
        for root in roots:
            root_path = Path(root.path)
            if self.path == root_path or root_path in self.path.parents:
                raise ValueError("snapshot database must be outside selected roots")

    def compare_and_save(self, report: StorageReport) -> StorageReport:
        self.validate_destination(report.roots)
        filesystem = LocalFileSystem()
        try:
            # Pin/check ancestors so a selected database path cannot traverse links.
            with filesystem.directory(self.path.parent):
                try:
                    info = filesystem.stat(self.path)
                except FileNotFoundError:
                    pass
                else:
                    if info.is_link or not info.is_file or info.link_count != 1:
                        raise CollectionFailure("snapshot_destination_not_regular")
                with closing(sqlite3.connect(self.path, timeout=2.0)) as connection:
                    connection.execute("PRAGMA foreign_keys = ON")
                    connection.executescript(_SCHEMA)
                    # Serialize read/compare/write: concurrent scans cannot compare
                    # against a half-written or mixed snapshot.
                    connection.execute("BEGIN IMMEDIATE")
                    bundles = self._compare_and_insert(connection, report)
                    connection.commit()
        except (*OS_ERRORS, sqlite3.Error, OverflowError):
            return unavailable_snapshots(report, "snapshot_database_unavailable")
        return report.model_copy(
            update={
                "bundles": bundles,
                "snapshot_saved": True,
                "snapshot_reason": None,
            }
        )

    def _compare_and_insert(
        self, connection: sqlite3.Connection, report: StorageReport
    ) -> tuple[EvidenceBundle, ...]:
        previous: dict[str, tuple[str, int, bool]] = {}
        scan_ids: dict[str, int] = {}
        for root in report.roots:
            row = connection.execute(
                "SELECT id, timestamp FROM storage_scans WHERE root_id = ? "
                "ORDER BY id DESC LIMIT 1",
                (root.root_id,),
            ).fetchone()
            if row is not None:
                for subject_id, size, complete in connection.execute(
                    "SELECT subject_id, size_bytes, complete FROM folder_sizes "
                    "WHERE scan_id = ?",
                    (row[0],),
                ):
                    previous[str(subject_id)] = (str(row[1]), int(size), bool(complete))
            cursor = connection.execute(
                "INSERT INTO storage_scans(root_id, timestamp) VALUES (?, ?)",
                (root.root_id, report.timestamp.isoformat()),
            )
            assert cursor.lastrowid is not None
            scan_ids[root.root_id] = cursor.lastrowid
        bundles: list[EvidenceBundle] = []
        for bundle in report.bundles:
            folder = _folder_item(bundle)
            if folder is None:
                bundles.append(bundle)
                continue
            assert isinstance(folder.value, dict)
            path = folder.value["path"]
            assert isinstance(path, dict) and isinstance(path["root_id"], str)
            connection.execute(
                "INSERT INTO folder_sizes(scan_id, subject_id, size_bytes, complete) "
                "VALUES (?, ?, ?, ?)",
                (
                    scan_ids[path["root_id"]],
                    bundle.subject_id,
                    folder.value["size_bytes"],
                    int(folder.availability == "observed"),
                ),
            )
            growth = _growth(
                bundle, report.timestamp, previous=previous.get(bundle.subject_id)
            )
            bundles.append(bundle.model_copy(update={"items": (*bundle.items, growth)}))
        return tuple(bundles)
