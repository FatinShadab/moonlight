"""Real local SQLite snapshots, growth comparability, and write containment."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

from moonlight.core.evidence import EvidenceKind
from moonlight.storage.scanner import StorageScanner
from moonlight.storage.snapshots import SQLiteSnapshotStore
from tests.test_storage_scanner import item_for

START = datetime(2026, 10, 27, tzinfo=UTC)


def test_persists_and_computes_growth_between_scans(tmp_path: Path) -> None:
    root = tmp_path / "selected"
    root.mkdir()
    file = root / "data.bin"
    file.write_bytes(b"first")
    database = tmp_path / "sizes.sqlite3"
    store = SQLiteSnapshotStore(str(database))
    first = store.compare_and_save(StorageScanner().scan([str(root)], timestamp=START))
    assert first.snapshot_saved and database.is_file()
    assert (
        item_for(first, root, EvidenceKind.GROWTH_RATE).reason == "no_previous_snapshot"
    )
    file.write_bytes(b"x" * 15)
    second = store.compare_and_save(
        StorageScanner().scan([str(root)], timestamp=START + timedelta(seconds=10))
    )
    growth = item_for(second, root, EvidenceKind.GROWTH_RATE)
    assert growth.availability == "observed"
    assert isinstance(growth.value, Mapping)
    assert growth.value["delta_bytes"] == 10
    assert growth.value["bytes_per_second"] == 1
    assert growth.id == item_for(first, root, EvidenceKind.GROWTH_RATE).id
    # A new store instance reads the same on-disk history, including shrinkage.
    file.write_bytes(b"x")
    third = SQLiteSnapshotStore(str(database)).compare_and_save(
        StorageScanner().scan([str(root)], timestamp=START + timedelta(seconds=20))
    )
    growth = item_for(third, root, EvidenceKind.GROWTH_RATE)
    assert isinstance(growth.value, Mapping) and growth.value["delta_bytes"] == -14


def test_incomplete_snapshots_never_become_false_growth(tmp_path: Path) -> None:
    root = tmp_path / "selected"
    root.mkdir()
    (root / "data").write_bytes(b"data")
    raw = StorageScanner().scan([str(root)], timestamp=START)
    root_bundle = raw.bundles[0]
    partial = root_bundle.items[0].model_copy(
        update={
            "availability": "unavailable",
            "reason": "access_denied",
        }
    )
    raw = raw.model_copy(
        update={
            "bundles": (
                root_bundle.model_copy(update={"items": (partial,)}),
                *raw.bundles[1:],
            )
        }
    )
    store = SQLiteSnapshotStore(str(tmp_path / "sizes.db"))
    first = store.compare_and_save(raw)
    assert (
        item_for(first, root, EvidenceKind.GROWTH_RATE).reason
        == "current_size_unavailable"
    )
    second = store.compare_and_save(
        StorageScanner().scan([str(root)], timestamp=START + timedelta(seconds=10))
    )
    assert (
        item_for(second, root, EvidenceKind.GROWTH_RATE).reason
        == "previous_size_unavailable"
    )


@pytest.mark.parametrize("offset", [0, -10])
def test_non_positive_interval_is_unavailable(tmp_path: Path, offset: int) -> None:
    root = tmp_path / "selected"
    root.mkdir()
    store = SQLiteSnapshotStore(str(tmp_path / "sizes.db"))
    store.compare_and_save(StorageScanner().scan([str(root)], timestamp=START))
    second = store.compare_and_save(
        StorageScanner().scan([str(root)], timestamp=START + timedelta(seconds=offset))
    )
    assert (
        item_for(second, root, EvidenceKind.GROWTH_RATE).reason
        == "non_positive_scan_interval"
    )


def test_database_inside_selected_tree_is_rejected_without_writes(
    tmp_path: Path,
) -> None:
    report = StorageScanner().scan([str(tmp_path)])
    database = tmp_path / "unsafe.db"
    with pytest.raises(ValueError, match="outside selected roots"):
        SQLiteSnapshotStore(str(database)).compare_and_save(report)
    assert not database.exists()


def test_database_failure_preserves_scan_and_explains_missing_growth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "selected"
    root.mkdir()
    report = StorageScanner().scan([str(root)])
    monkeypatch.setattr(
        sqlite3, "connect", Mock(side_effect=sqlite3.OperationalError("locked"))
    )
    result = SQLiteSnapshotStore(str(tmp_path / "sizes.db")).compare_and_save(report)
    assert not result.snapshot_saved
    assert result.snapshot_reason == "snapshot_database_unavailable"
    assert item_for(result, root, EvidenceKind.FOLDER_SIZE).availability == "observed"
    assert (
        item_for(result, root, EvidenceKind.GROWTH_RATE).reason
        == "snapshot_database_unavailable"
    )


def test_new_folders_and_changed_root_selection_have_no_fabricated_baseline(
    tmp_path: Path,
) -> None:
    root = tmp_path / "selected"
    root.mkdir()
    store = SQLiteSnapshotStore(str(tmp_path / "sizes.db"))
    store.compare_and_save(StorageScanner().scan([str(root)], timestamp=START))
    nested = root / "new"
    nested.mkdir()
    second = store.compare_and_save(
        StorageScanner().scan([str(root)], timestamp=START + timedelta(seconds=10))
    )
    assert (
        item_for(second, nested, EvidenceKind.GROWTH_RATE).reason
        == "no_previous_snapshot"
    )
    third = store.compare_and_save(
        StorageScanner().scan([str(nested)], timestamp=START + timedelta(seconds=20))
    )
    assert (
        item_for(third, nested, EvidenceKind.GROWTH_RATE).reason
        == "no_previous_snapshot"
    )


def test_failed_transaction_does_not_save_half_a_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "selected"
    root.mkdir()
    store = SQLiteSnapshotStore(str(tmp_path / "sizes.db"))
    original = store._compare_and_insert

    def fail(connection: sqlite3.Connection, report: object) -> None:
        connection.execute(
            "INSERT INTO storage_scans(root_id, timestamp) VALUES ('test', 'test')"
        )
        raise sqlite3.OperationalError("simulated write failure")

    monkeypatch.setattr(store, "_compare_and_insert", fail)
    result = store.compare_and_save(StorageScanner().scan([str(root)]))
    assert not result.snapshot_saved
    monkeypatch.setattr(store, "_compare_and_insert", original)
    with sqlite3.connect(store.path) as connection:
        assert (
            connection.execute("SELECT count(*) FROM storage_scans").fetchone()[0] == 0
        )


def test_snapshot_hard_link_cannot_write_to_a_scanned_file(tmp_path: Path) -> None:
    root = tmp_path / "selected"
    root.mkdir()
    original = root / "private.bin"
    original.write_bytes(b"private content")
    database = tmp_path / "aliased.db"
    database.hardlink_to(original)
    report = SQLiteSnapshotStore(str(database)).compare_and_save(
        StorageScanner().scan([str(root)])
    )
    assert not report.snapshot_saved
    assert original.read_bytes() == b"private content"
