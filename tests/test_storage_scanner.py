"""Temporary-tree scans, no-follow boundaries, and explicit partial evidence."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock

import pytest

from moonlight.collectors.hash_worker import hash_file
from moonlight.collectors.hashing import FileHash, HashAccess, HashLimits
from moonlight.core.evidence import EvidenceBundle, EvidenceItem, EvidenceKind
from moonlight.storage.filesystem import REPARSE_POINT, EntryInfo, LocalFileSystem
from moonlight.storage.models import StorageReport, path_id
from moonlight.storage.scanner import ScanLimits, StorageScanner


class TrackingHashes:
    def __init__(self) -> None:
        self.paths: list[str] = []

    def hash(self, path: str, limits: HashLimits) -> FileHash:
        self.paths.append(path)
        return hash_file(path, limits, open_file=LocalFileSystem().open_file)


def item_for(report: StorageReport, path: Path, kind: EvidenceKind) -> EvidenceItem:
    bundle = next(
        bundle for bundle in report.bundles if bundle.subject_id == path_id(str(path))
    )
    return next(item for item in bundle.items if item.kind == kind)


def test_tree_sizes_ages_types_and_duplicate_candidates(tmp_path: Path) -> None:
    root = tmp_path / "selected"
    root.mkdir()
    (root / "nested").mkdir()
    (root / "empty").mkdir()
    contents = {
        root / "alpha.txt": b"repeat",
        root / "beta.BIN": b"repeat",
        root / "gamma.bin": b"other!",
        root / "unique.zip": b"123456789",
        root / "nested" / "photo.jpg": b"x" * 11,
    }
    for path, content in contents.items():
        path.write_bytes(content)
        os.utime(path, (1700000000, 1700000000))
    before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in contents}
    hashes = TrackingHashes()
    report = StorageScanner(hashes=hashes).scan(
        [str(root)], timestamp=datetime.fromtimestamp(1700000060, UTC)
    )
    assert len(report.bundles) == 8
    folder = item_for(report, root, EvidenceKind.FOLDER_SIZE)
    assert folder.availability == "observed"
    assert isinstance(folder.value, dict)
    assert folder.value["size_bytes"] == sum(map(len, contents.values()))
    assert folder.value["complete"] is True
    assert item_for(report, root / "empty", EvidenceKind.FOLDER_SIZE).value == {
        "path": {"root_id": path_id(str(root)), "relative_path": "empty"},
        "size_bytes": 0,
        "complete": True,
        "excluded_entries": 0,
        "basis": "logical_bytes_excluding_links",
    }
    age = item_for(report, root / "alpha.txt", EvidenceKind.FILE_AGE)
    assert isinstance(age.value, dict) and age.value["modified_age_seconds"] == 60
    kind = item_for(report, root / "beta.BIN", EvidenceKind.FILE_TYPE)
    assert isinstance(kind.value, dict) and kind.value["extension"] == ".bin"
    assert {Path(path) for path in hashes.paths} == {
        root / name for name in ("alpha.txt", "beta.BIN", "gamma.bin")
    }
    assert report.hash_candidates == report.files_hashed == 3
    duplicate = item_for(report, root / "alpha.txt", EvidenceKind.DUPLICATE_HASH)
    assert isinstance(duplicate.value, dict)
    assert duplicate.value["matches"] == [
        {"root_id": path_id(str(root)), "relative_path": "beta.BIN"}
    ]
    unique_content = item_for(report, root / "gamma.bin", EvidenceKind.DUPLICATE_HASH)
    assert (
        isinstance(unique_content.value, dict) and unique_content.value["matches"] == []
    )
    assert {
        path: (path.read_bytes(), path.stat().st_mtime_ns) for path in contents
    } == before
    for bundle in report.bundles:
        assert EvidenceBundle.model_validate_json(bundle.model_dump_json()) == bundle
        assert str(root) not in bundle.subject_id


def test_only_selected_roots_and_stable_evidence_ids(tmp_path: Path) -> None:
    root = tmp_path / "selected"
    root.mkdir()
    (root / "one.txt").write_bytes(b"one")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.txt").write_bytes(b"private")
    hashes = Mock(spec=HashAccess)
    first = StorageScanner(hashes=hashes).scan([str(root), str(root)])
    second = StorageScanner(hashes=hashes).scan([str(root)])
    assert len(first.roots) == 1
    assert len(first.bundles) == 2
    assert [item.id for b in first.bundles for item in b.items] == [
        item.id for b in second.bundles for item in b.items
    ]
    hashes.hash.assert_not_called()


@pytest.mark.parametrize(
    "failure", [PermissionError(), FileNotFoundError(), TimeoutError()]
)
def test_missing_metadata_is_unavailable_and_parent_is_partial(
    tmp_path: Path, failure: Exception
) -> None:
    denied = tmp_path / "denied.txt"
    denied.write_bytes(b"private")
    (tmp_path / "ok.txt").write_bytes(b"ok")

    class DeniedFileSystem(LocalFileSystem):
        def stat(self, path: Path) -> EntryInfo:
            if path == denied:
                raise failure
            return super().stat(path)

    report = StorageScanner(filesystem=DeniedFileSystem()).scan([str(tmp_path)])
    assert (
        item_for(report, denied, EvidenceKind.FILE_TYPE).availability == "unavailable"
    )
    folder = item_for(report, tmp_path, EvidenceKind.FOLDER_SIZE)
    assert folder.availability == "unavailable" and folder.reason == "incomplete_tree"
    assert isinstance(folder.value, dict) and folder.value["size_bytes"] == 2


def test_denied_directory_does_not_abort_other_folders(tmp_path: Path) -> None:
    denied = tmp_path / "locked"
    denied.mkdir()
    (tmp_path / "good").mkdir()
    (tmp_path / "good" / "one.txt").write_bytes(b"one")

    class DeniedFileSystem(LocalFileSystem):
        @contextmanager
        def entries(self, path: Path) -> Iterator[Iterator[Path]]:
            if path == denied:
                raise PermissionError()
            with super().entries(path) as entries:
                yield entries

    report = StorageScanner(filesystem=DeniedFileSystem()).scan([str(tmp_path)])
    assert item_for(report, denied, EvidenceKind.FOLDER_SIZE).reason == "access_denied"
    assert (
        item_for(report, tmp_path / "good", EvidenceKind.FOLDER_SIZE).availability
        == "observed"
    )


@pytest.mark.parametrize("directory", [False, True])
def test_all_reparse_tags_are_skipped_before_enumeration_or_hash(
    tmp_path: Path, directory: bool
) -> None:
    linked = tmp_path / "linked"
    if directory:
        linked.mkdir()
        (linked / "must-not-read.txt").write_bytes(b"private")
    else:
        linked.write_bytes(b"private")

    class ReparseFileSystem(LocalFileSystem):
        def stat(self, path: Path) -> EntryInfo:
            info = super().stat(path)
            if path == linked:
                return EntryInfo(
                    info.mode,
                    info.size,
                    info.modified_ns,
                    info.device,
                    info.inode,
                    REPARSE_POINT,
                )
            return info

        @contextmanager
        def entries(self, path: Path) -> Iterator[Iterator[Path]]:
            assert path != linked
            with super().entries(path) as entries:
                yield entries

    hashes = Mock(spec=HashAccess)
    report = StorageScanner(filesystem=ReparseFileSystem(), hashes=hashes).scan(
        [str(tmp_path)]
    )
    folder = item_for(report, tmp_path, EvidenceKind.FOLDER_SIZE)
    assert folder.availability == "observed"
    assert isinstance(folder.value, dict) and folder.value["excluded_entries"] == 1
    assert len(report.bundles) == 2
    assert report.bundles[1].items[0].reason == "reparse_point_skipped"
    hashes.hash.assert_not_called()


def test_real_symlink_cannot_escape_selected_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.txt").write_bytes(b"private")
    link = root / "alias"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Windows account cannot create symlinks")
    report = StorageScanner().scan([str(root)])
    assert len(report.bundles) == 2
    assert report.bundles[1].items[0].reason == "reparse_point_skipped"
    # Selecting a descendant of the link must not enumerate outside either.
    (outside / "nested").mkdir()
    report = StorageScanner().scan([str(link / "nested")])
    assert len(report.bundles) == 1
    assert report.bundles[0].items[0].reason == "reparse_point_skipped"


def test_hard_links_are_not_duplicate_copies(tmp_path: Path) -> None:
    first = tmp_path / "first"
    first.write_bytes(b"same")
    (tmp_path / "alias").hardlink_to(first)
    hashes = Mock(spec=HashAccess)
    report = StorageScanner(hashes=hashes).scan([str(tmp_path)])
    assert report.hash_candidates == 0
    hashes.hash.assert_not_called()


@pytest.mark.parametrize("failure", [PermissionError(), TimeoutError(), OSError()])
def test_hash_failure_is_explicit_evidence(tmp_path: Path, failure: Exception) -> None:
    for name in ("one", "two"):
        (tmp_path / name).write_bytes(b"same")
    hashes = Mock(spec=HashAccess)
    hashes.hash.side_effect = failure
    report = StorageScanner(hashes=hashes).scan([str(tmp_path)])
    assert report.hash_candidates == 2 and report.files_hashed == 0
    for name in ("one", "two"):
        item = item_for(report, tmp_path / name, EvidenceKind.DUPLICATE_HASH)
        assert item.availability != "observed" and item.reason


def test_scan_and_hash_limits_remain_visible(tmp_path: Path) -> None:
    for name in ("one", "two"):
        (tmp_path / name).write_bytes(b"same")
    report = StorageScanner(limits=ScanLimits(max_entries=1)).scan([str(tmp_path)])
    assert report.bundles[0].items[0].reason == "scan_entry_limit"
    report = StorageScanner(limits=ScanLimits(max_hash_files=0)).scan([str(tmp_path)])
    assert report.files_hashed == 0
    assert (
        item_for(report, tmp_path / "one", EvidenceKind.DUPLICATE_HASH).reason
        == "hash_budget_exhausted"
    )


def test_default_hash_worker_reads_inert_candidates(tmp_path: Path) -> None:
    (tmp_path / "one").write_bytes(b"same")
    (tmp_path / "two").write_bytes(b"same")
    report = StorageScanner().scan([str(tmp_path)])
    assert report.files_hashed == 2


def test_roots_must_be_explicit_and_nonoverlapping(tmp_path: Path) -> None:
    scanner = StorageScanner()
    with pytest.raises(ValueError, match="explicit root"):
        scanner.scan([])
    with pytest.raises(ValueError, match="overlap"):
        scanner.scan([str(tmp_path), str(tmp_path / "nested")])


def test_changed_hash_metadata_cannot_be_reported_as_duplicate(tmp_path: Path) -> None:
    for name in ("one", "two"):
        (tmp_path / name).write_bytes(b"same")
    hashes = Mock(spec=HashAccess)
    actual = hash_file(str(tmp_path / "one"), HashLimits())
    hashes.hash.return_value = actual.model_copy(
        update={
            "stamp": actual.stamp.model_copy(update={"modified_ns": 0}),
        }
    )
    report = StorageScanner(hashes=hashes).scan([str(tmp_path)])
    assert report.files_hashed == 0
    assert (
        item_for(report, tmp_path / "one", EvidenceKind.DUPLICATE_HASH).reason
        == "file_changed_since_scan"
    )


def test_depth_limit_never_claims_a_complete_total(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "private").write_bytes(b"not scanned")
    report = StorageScanner(limits=ScanLimits(max_depth=0)).scan([str(tmp_path)])
    assert len(report.bundles) == 2
    assert (
        item_for(report, nested, EvidenceKind.FOLDER_SIZE).reason == "scan_depth_limit"
    )
    assert (
        item_for(report, tmp_path, EvidenceKind.FOLDER_SIZE).reason == "incomplete_tree"
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows directory sharing semantics")
def test_windows_directory_guard_pins_the_selected_path(tmp_path: Path) -> None:
    class RenameAttemptFileSystem(LocalFileSystem):
        @contextmanager
        def entries(self, path: Path) -> Iterator[Iterator[Path]]:
            if path == tmp_path:
                with pytest.raises(PermissionError):
                    path.rename(path.with_name(path.name + "-moved"))
            with super().entries(path) as entries:
                yield entries

    report = StorageScanner(filesystem=RenameAttemptFileSystem()).scan([str(tmp_path)])
    assert report.bundles[0].items[0].availability == "observed"
