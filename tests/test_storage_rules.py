"""Every storage classification branch, especially protected-location priority."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

import pytest

from moonlight.rules.storage import StorageLocations, classify_storage
from moonlight.storage.locations import KnownFolders, discover_locations
from moonlight.storage.models import StorageReport, path_id
from moonlight.storage.scanner import StorageScanner


def category(report: StorageReport, path: Path) -> str:
    return next(
        item.category
        for item in report.classifications
        if item.subject_id == path_id(str(path))
    )


def test_known_temp_cache_and_unknown_location(tmp_path: Path) -> None:
    cache = tmp_path / "trusted-cache"
    cache.mkdir()
    data = cache / "cache.bin"
    data.write_bytes(b"cache")
    unknown = tmp_path / "unknown"
    unknown.mkdir()
    (unknown / "setup.msi").write_bytes(b"installer")
    report = classify_storage(
        StorageScanner().scan([str(tmp_path)]), StorageLocations((), (str(cache),))
    )
    assert category(report, cache) == "clearly_safe"
    assert category(report, data) == "clearly_safe"
    assert category(report, unknown) == "review_first"
    assert category(report, tmp_path) == "review_first"
    all_ids = {item.id for bundle in report.bundles for item in bundle.items}
    assert all(set(result.evidence_ids) <= all_ids for result in report.classifications)


@pytest.mark.parametrize(
    "protected_name", ["Documents", "Windows", "redirected-personal"]
)
def test_protected_location_can_never_be_clearly_safe_even_when_allowlisted(
    tmp_path: Path, protected_name: str
) -> None:
    protected = tmp_path / protected_name
    protected.mkdir()
    nested = protected / "cache"
    nested.mkdir()
    file = nested / "cache.bin"
    file.write_bytes(b"private")
    # Deliberately unsafe/conflicting configuration: protection still wins.
    locations = StorageLocations(
        (str(protected),), (str(tmp_path), str(protected), str(nested))
    )
    report = classify_storage(StorageScanner().scan([str(tmp_path)]), locations)
    assert all(
        category(report, path) == "do_not_touch"
        for path in (tmp_path, protected, nested, file)
    )
    assert not any(
        result.category == "clearly_safe" for result in report.classifications
    )


@pytest.mark.parametrize("extension", [".docx", ".PDF", ".txt", ".xlsx", ".jpg"])
def test_personal_document_and_its_container_override_cache_label(
    tmp_path: Path, extension: str
) -> None:
    file = tmp_path / ("personal" + extension)
    file.write_bytes(b"personal")
    report = classify_storage(
        StorageScanner().scan([str(tmp_path)]), StorageLocations((), (str(tmp_path),))
    )
    assert category(report, file) == category(report, tmp_path) == "do_not_touch"
    parent = next(
        item
        for item in report.classifications
        if item.subject_id == path_id(str(tmp_path))
    )
    child_ids = {
        item.id
        for bundle in report.bundles
        if bundle.subject_id == path_id(str(file))
        for item in bundle.items
    }
    assert child_ids <= set(parent.evidence_ids)


def test_document_folder_names_are_protected_even_without_a_config_entry(
    tmp_path: Path,
) -> None:
    documents = tmp_path / "Documents"
    documents.mkdir()
    file = documents / "important.bin"
    file.write_bytes(b"private")
    report = classify_storage(
        StorageScanner().scan([str(tmp_path)]), StorageLocations((), (str(tmp_path),))
    )
    assert category(report, documents) == category(report, file) == "do_not_touch"
    assert category(report, tmp_path) == "do_not_touch"


def test_path_component_boundaries_and_case(tmp_path: Path) -> None:
    protected = tmp_path / "Protected"
    protected.mkdir()
    sibling = tmp_path / "Protected-other"
    sibling.mkdir()
    report = classify_storage(
        StorageScanner().scan([str(tmp_path)]),
        StorageLocations((str(protected).swapcase(),), (str(sibling),)),
    )
    # Windows paths are case-insensitive; prefixes alone are never containment.
    assert category(report, protected) == "do_not_touch"
    assert category(report, sibling) == "clearly_safe"


def test_incomplete_evidence_is_never_clearly_safe(tmp_path: Path) -> None:
    report = StorageScanner().scan([str(tmp_path)])
    bundle = report.bundles[0]
    missing = bundle.items[0].model_copy(
        update={"availability": "unavailable", "reason": "access_denied"}
    )
    report = report.model_copy(
        update={"bundles": (bundle.model_copy(update={"items": (missing,)}),)}
    )
    report = classify_storage(report, StorageLocations((), (str(tmp_path),)))
    assert category(report, tmp_path) == "review_first"


def test_known_folder_discovery_failure_disables_clearly_safe(tmp_path: Path) -> None:
    folders = Mock(spec=KnownFolders)
    folders.get.side_effect = OSError("redirected folder unavailable")
    locations = discover_locations(folders)
    assert not locations.discovery_complete
    report = classify_storage(
        StorageScanner().scan([str(tmp_path)]),
        StorageLocations(locations.protected, (str(tmp_path),), False),
    )
    assert category(report, tmp_path) == "review_first"


def test_known_folder_discovery_preserves_redirects(tmp_path: Path) -> None:
    redirected = tmp_path / "personal-redirect"
    folders = Mock(spec=KnownFolders)
    folders.get.return_value = str(redirected)
    locations = discover_locations(folders)
    assert locations.discovery_complete
    assert str(redirected) in locations.protected
    assert str(redirected / "Temp") in locations.safe


def test_excluded_links_prevent_a_whole_folder_safe_label(tmp_path: Path) -> None:
    report = StorageScanner().scan([str(tmp_path)])
    bundle = report.bundles[0]
    item = bundle.items[0]
    assert isinstance(item.value, dict)
    excluded = item.model_copy(update={"value": {**item.value, "excluded_entries": 1}})
    report = report.model_copy(
        update={"bundles": (bundle.model_copy(update={"items": (excluded,)}),)}
    )
    report = classify_storage(report, StorageLocations((), (str(tmp_path),)))
    assert category(report, tmp_path) == "review_first"
