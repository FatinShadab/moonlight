"""Tests for the moonlight investigate CLI subcommand."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from moonlight.cli import main
from moonlight.core.evidence import (
    EvidenceBundle,
    EvidenceItem,
    EvidenceKind,
    SeverityHint,
    make_evidence_id,
)


@pytest.fixture
def sample_bundle_file(tmp_path: Path) -> Path:
    timestamp = datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC)
    id1 = make_evidence_id(
        "process", "4242", "process_collector", EvidenceKind.EXECUTABLE_PATH
    )
    items = [
        EvidenceItem(
            id=id1,
            source="process_collector",
            kind=EvidenceKind.EXECUTABLE_PATH,
            value={"path": "C:/Windows/System32/svchost.exe"},
            severity_hint=SeverityHint.INFO,
            availability="observed",
            reason=None,
            timestamp=timestamp,
        ),
    ]
    bundle = EvidenceBundle(
        subject_type="process",
        subject_id="4242",
        items=tuple(items),
    )
    bundle_file = tmp_path / "bundle.json"
    bundle_file.write_text(bundle.model_dump_json(indent=2), encoding="utf-8")
    return bundle_file


def test_cli_investigate_mock(
    sample_bundle_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(
        ["investigate", "--input", str(sample_bundle_file), "--provider", "mock"]
    )
    assert exit_code == 0
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert "risk_tier" in report
    assert "summary" in report
    assert "metadata" in report


def test_cli_investigate_offline_meta_provider_fallback(
    sample_bundle_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(
        ["investigate", "--input", str(sample_bundle_file), "--provider", "meta"]
    )
    assert exit_code == 0
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["is_fallback"] is True
    assert report["metadata"]["provider"] == "rules_only_fallback"


def test_cli_investigate_invalid_input(tmp_path: Path) -> None:
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("not json content", encoding="utf-8")
    with pytest.raises(SystemExit):
        main(["investigate", "--input", str(bad_file)])
