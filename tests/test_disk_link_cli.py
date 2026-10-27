"""Disk-link CLI composition; no real target process or security activity."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

import pytest

from moonlight.cli import main
from moonlight.collectors.process import CollectionError
from moonlight.core.evidence import SeverityHint
from moonlight.storage.attribution_models import DiskLinkReport, DiskSnapshot, P3Finding
from moonlight.storage.disk_snapshot import capture_disk_snapshot
from moonlight.storage.scanner import StorageScanner
from tests.test_disk_attribution import MIB, snapshot


def test_cli_compares_two_saved_synthetic_snapshots(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before_file, after_file = tmp_path / "before.json", tmp_path / "after.json"
    # Windows PowerShell's Set-Content -Encoding UTF8 includes a BOM.
    before_file.write_text(snapshot(tmp_path).model_dump_json(), encoding="utf-8-sig")
    after_file.write_text(
        snapshot(
            tmp_path,
            offset=10,
            size=11 * MIB,
            count=10 * MIB,
        ).model_dump_json(),
        encoding="utf-8",
    )
    assert (
        main(["disk-link", "--before", str(before_file), "--after", str(after_file)])
        == 0
    )
    output = capsys.readouterr().out
    report = DiskLinkReport.model_validate_json(output)
    assert output.isascii()
    assert report.findings[0].confidence == "high"
    assert not report.p3_findings


def test_cli_p3_contract_and_custom_growth_threshold(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before, after = (
        snapshot(tmp_path),
        snapshot(tmp_path, offset=10, size=2 * MIB, count=MIB),
    )
    files = [tmp_path / name for name in ("before.json", "after.json", "p3.json")]
    files[0].write_text(before.model_dump_json(), encoding="utf-8")
    files[1].write_text(after.model_dump_json(), encoding="utf-8")
    finding = P3Finding(
        finding_id="p3-synthetic",
        process_subject_id=after.processes[0].subject_id,
        rule_id="synthetic",
        severity=SeverityHint.LOW,
        evidence_ids=(after.processes[0].items[0].id,),
    )
    files[2].write_text("[" + finding.model_dump_json() + "]", encoding="utf-8-sig")
    assert (
        main(
            [
                "disk-link",
                "--before",
                str(files[0]),
                "--after",
                str(files[1]),
                "--p3-findings",
                str(files[2]),
                "--min-growth-rate",
                "1",
            ]
        )
        == 0
    )
    result = DiskLinkReport.model_validate_json(capsys.readouterr().out)
    assert result.findings[0].confidence == "high"
    assert result.findings[0].p3_finding_ids == ("p3-synthetic",)


@pytest.mark.parametrize("content", ["not JSON", "{}"])
def test_invalid_snapshot_is_an_explicit_cli_error(
    tmp_path: Path, content: str
) -> None:
    source = tmp_path / "input.json"
    source.write_text(content, encoding="utf-8")
    with pytest.raises(SystemExit) as error:
        main(["disk-link", "--before", str(source), "--after", str(source)])
    assert error.value.code == 2


def test_snapshot_capture_only_selected_pids_and_preserves_identity_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    example = snapshot(tmp_path)
    scanner = Mock(spec=StorageScanner)
    scanner.scan.return_value = example.storage
    scanner_factory = Mock(return_value=scanner)
    monkeypatch.setattr(
        "moonlight.storage.disk_snapshot.StorageScanner", scanner_factory
    )
    collector = Mock(
        side_effect=[
            example.processes[0],
            CollectionError(
                pid=99,
                availability="unavailable",
                reason="access_denied",
            ),
        ]
    )
    monkeypatch.setattr("moonlight.storage.disk_snapshot.collect_process", collector)
    result = capture_disk_snapshot([str(tmp_path)], [99, 42, 42])
    assert [call.args[0] for call in collector.call_args_list] == [42, 99]
    assert all(
        call.kwargs == {"include_open_files": True} for call in collector.call_args_list
    )
    assert result.processes == example.processes
    assert result.collection_errors[0].pid == 99
    assert scanner_factory.call_args.kwargs["limits"].max_hash_files == 0
    assert not list(tmp_path.iterdir())


def test_snapshot_cli_prints_json_without_writing_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    example = snapshot(tmp_path)
    capture = Mock(return_value=example)
    monkeypatch.setattr("moonlight.cli.capture_disk_snapshot", capture)
    assert main(["disk-snapshot", "--root", str(tmp_path), "--pid", "42"]) == 0
    assert DiskSnapshot.model_validate_json(capsys.readouterr().out) == example
    capture.assert_called_once_with([str(tmp_path)], [42])
    assert not list(tmp_path.iterdir())
