"""Storage composition and explicit CLI root/snapshot boundaries."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from moonlight.cli import main
from moonlight.rules.storage import StorageLocations
from moonlight.storage.investigator import investigate_storage
from moonlight.storage.models import StorageReport
from moonlight.storage.scanner import StorageScanner


def test_storage_cli_real_tree_and_sqlite(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "selected"
    root.mkdir()
    (root / "data.bin").write_bytes(b"harmless")
    database = tmp_path / "sizes.db"
    assert main(["storage", "--root", str(root), "--snapshots", str(database)]) == 0
    result = StorageReport.model_validate_json(capsys.readouterr().out)
    assert result.snapshot_saved and result.classifications
    assert len(result.bundles) == 2


@pytest.mark.parametrize(
    "args",
    [
        ["storage"],
        ["storage", "--root", "selected"],
        ["storage", "--snapshots", "sizes.db"],
    ],
)
def test_cli_never_invents_roots_or_snapshot_destinations(
    args: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    investigate = Mock()
    monkeypatch.setattr("moonlight.cli.investigate_storage", investigate)
    with pytest.raises(SystemExit) as error:
        main(args)
    assert error.value.code == 2
    investigate.assert_not_called()


def test_snapshot_inside_root_rejected_before_scanning(tmp_path: Path) -> None:
    scanner = Mock(spec=StorageScanner)
    with pytest.raises(ValueError, match="outside selected roots"):
        investigate_storage(
            [str(tmp_path)], str(tmp_path / "sizes.db"), scanner=scanner
        )
    scanner.scan.assert_not_called()


def test_no_ai_or_actions_needed_when_snapshot_destination_unavailable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "selected"
    root.mkdir()
    database = tmp_path / "missing-parent" / "sizes.db"
    assert main(["storage", "--root", str(root), "--snapshots", str(database)]) == 1
    result = StorageReport.model_validate_json(capsys.readouterr().out)
    assert not result.snapshot_saved
    assert result.snapshot_reason == "snapshot_database_unavailable"
    assert result.bundles and result.classifications
    assert not database.parent.exists()


def test_redaction_ready_paths_do_not_leak_through_identifiers_or_reasons(
    tmp_path: Path,
) -> None:
    root = tmp_path / "sensitive-name"
    root.mkdir()
    (root / "private-label.bin").write_bytes(b"sample")
    result = investigate_storage(
        [str(root)], str(tmp_path / "sizes.db"), locations=StorageLocations((), ())
    )
    # Absolute roots occur only in SelectedRoot.path. Relative names occur only
    # in structured path references; replace those to simulate minimization.
    data = result.model_dump(mode="json")
    for selected in data["roots"]:
        selected["path"] = "[ROOT]"
    for bundle in data["bundles"]:
        for item in bundle["items"]:
            item["value"]["path"]["relative_path"] = "[RELATIVE]"
    for classification in data["classifications"]:
        classification["path"]["relative_path"] = "[RELATIVE]"
    encoded = json.dumps(data)
    assert "sensitive-name" not in encoded and "private-label" not in encoded


def test_cli_invalid_destination_is_a_usage_error(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as error:
        main(
            [
                "storage",
                "--root",
                str(tmp_path),
                "--snapshots",
                str(tmp_path / "inside.db"),
            ]
        )
    assert error.value.code == 2
