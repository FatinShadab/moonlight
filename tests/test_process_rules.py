"""Synthetic rule matches, abstentions, tiers, citations and metadata freshness."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from pydantic import JsonValue

from moonlight.core.evidence import (
    EvidenceBundle,
    EvidenceItem,
    EvidenceKind,
    make_evidence_id,
)
from moonlight.rules.process import evaluate_process, render_rule_docs, rules

SUBJECT = "42:1700000000.125"
STAMP = datetime(2026, 10, 27, tzinfo=UTC)


def bundle(**values: JsonValue) -> EvidenceBundle:
    items = tuple(
        EvidenceItem(
            id=make_evidence_id("process", SUBJECT, "synthetic", EvidenceKind(kind)),
            source="synthetic",
            kind=EvidenceKind(kind),
            value=value,
            availability="observed",
            timestamp=STAMP,
        )
        for kind, value in values.items()
    )
    return EvidenceBundle(subject_type="process", subject_id=SUBJECT, items=items)


@pytest.mark.parametrize(
    ("rule_id", "positive", "negative"),
    [
        (
            "system_path_mismatch",
            {"executable_path": "C:/Users/Test/Temp/svchost.exe"},
            {"executable_path": "C:/Windows/System32/svchost.exe"},
        ),
        (
            "unsigned_user_executable",
            {
                "executable_path": "C:/Users/Test/Downloads/tool.exe",
                "signature_status": {"state": "unsigned"},
            },
            {
                "executable_path": "C:/Program Files/Tool/tool.exe",
                "signature_status": {"state": "unsigned"},
            },
        ),
        (
            "invalid_signature",
            {"signature_status": {"state": "signed_invalid"}},
            {"signature_status": {"state": "signed_valid"}},
        ),
        (
            "system_name_lookalike",
            {"executable_path": "C:/Temp/svch0st.exe"},
            {"executable_path": "C:/Temp/svchost.exe"},
        ),
        (
            "unusual_system_parent",
            {
                "executable_path": "C:/Windows/System32/svchost.exe",
                "parent_chain": [{"name": "notepad.exe"}],
            },
            {
                "executable_path": "C:/Windows/System32/svchost.exe",
                "parent_chain": [{"name": "services.exe"}],
            },
        ),
        (
            "outbound_unsigned_user",
            {
                "executable_path": "C:/Users/Test/Temp/tool.exe",
                "signature_status": {"state": "unsigned"},
                "network_activity": [{"remote": ["203.0.113.10", 443]}],
            },
            {
                "executable_path": "C:/Users/Test/Temp/tool.exe",
                "signature_status": {"state": "unsigned"},
                "network_activity": [{"remote": []}],
            },
        ),
        (
            "encoded_command",
            {"command_line": ["tool.exe", "A" * 160]},
            {"command_line": ["tool.exe", "A" * 159]},
        ),
        (
            "heavy_temp_writes",
            {
                "executable_path": "C:/Users/Test/Temp/tool.exe",
                "signature_status": {"state": "unsigned"},
                "io_counters": {"write_bytes": 100 * 1024 * 1024},
            },
            {
                "executable_path": "C:/Users/Test/Temp/tool.exe",
                "signature_status": {"state": "unsigned"},
                "io_counters": {"write_bytes": 99 * 1024 * 1024},
            },
        ),
        (
            "valid_system_signature",
            {
                "executable_path": "C:/Windows/System32/svchost.exe",
                "signature_status": {"state": "signed_valid"},
            },
            {
                "executable_path": "C:/Users/Test/Temp/svchost.exe",
                "signature_status": {"state": "signed_valid"},
            },
        ),
    ],
)
def test_each_rule_positive_and_negative(
    rule_id: str, positive: dict[str, JsonValue], negative: dict[str, JsonValue]
) -> None:
    rule = next(r for r in rules() if r.id == rule_id)
    matched = rule.evaluate(bundle(**positive))
    assert matched is not None
    assert all(bundle(**positive).get_item(i) is not None for i in matched.evidence_ids)
    assert rule.evaluate(bundle(**negative)) is None


def test_tier_boundaries_and_p3_adapter() -> None:
    base: dict[str, JsonValue] = {
        "executable_path": "C:/Users/Test/Temp/svchost.exe",
        "signature_status": {"state": "unsigned"},
        "sha256": {"sha256": "a" * 64},
        "parent_chain": [{"name": "services.exe"}],
        "command_line": ["svchost.exe"],
    }
    high = evaluate_process(bundle(**base))
    assert high.tier == "high"
    assert high.score >= 7
    assert len(high.p3_findings) == len(high.findings)
    assert all(f.process_subject_id == SUBJECT for f in high.p3_findings)
    review = evaluate_process(
        bundle(**{**base, "executable_path": "C:/Users/Test/Temp/tool.exe"})
    )
    assert review.tier == "review"
    low = evaluate_process(
        bundle(**{**base, "executable_path": "C:/Program Files/Tool/tool.exe"})
    )
    assert low.tier == "low"
    assert "ev-process-" in high.derivation


@pytest.mark.parametrize(
    "reason", ["value_too_large", "access_denied", "os_or_collector_error"]
)
def test_unavailable_is_missing_not_suspicious(reason: str) -> None:
    original = bundle(
        executable_path="C:/Users/Test/Temp/svchost.exe",
        signature_status={"state": "unsigned"},
        sha256={"sha256": "a" * 64},
        parent_chain=[],
        command_line=["svchost.exe"],
    )
    items = tuple(
        item.model_copy(
            update={
                "availability": "unavailable"
                if reason != "os_or_collector_error"
                else "error",
                "reason": reason,
                "value": None,
            }
        )
        if item.kind in (EvidenceKind.EXECUTABLE_PATH, EvidenceKind.SIGNATURE_STATUS)
        else item
        for item in original.items
    )
    report = evaluate_process(
        EvidenceBundle(subject_type="process", subject_id=SUBJECT, items=items)
    )
    assert report.tier == "inconclusive"
    assert report.score == 0
    assert {m.reason for m in report.missing_evidence} == {reason}
    assert not report.findings


def test_nested_immutable_values_and_determinism() -> None:
    sample = bundle(
        executable_path="C:/Users/Test/Temp/tool.exe",
        signature_status={"state": "unsigned"},
        sha256={"sha256": "a" * 64},
        parent_chain=[{"name": "explorer.exe"}],
        command_line=["tool.exe"],
        network_activity=[{"remote": ["203.0.113.10", 443]}],
    )
    first = evaluate_process(sample).model_dump_json()
    assert first == evaluate_process(sample).model_dump_json()
    parent = cast(tuple[dict[str, JsonValue], ...], sample.items[3].value)
    assert parent[0]["name"] == "explorer.exe"


def test_missing_hash_caps_high_at_review() -> None:
    sample = bundle(
        executable_path="C:/Users/Test/Temp/svchost.exe",
        signature_status={"state": "unsigned"},
        parent_chain=[{"name": "services.exe"}],
        command_line=["svchost.exe"],
    )
    report = evaluate_process(sample)
    assert report.score >= 7
    assert report.tier == "review"
    assert report.missing_evidence[0].kind == EvidenceKind.SHA256


def test_rules_cli_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from moonlight import cli

    sample = bundle(
        executable_path="C:/Program Files/Tool/tool.exe",
        signature_status={"state": "signed_valid"},
        sha256={"sha256": "a" * 64},
        parent_chain=[],
        command_line=["tool.exe"],
    )
    monkeypatch.setattr(cli, "collect_evidence", lambda _pid: sample)
    assert cli.main(["rules", "--pid", "42"]) == 0
    assert '"tier": "low"' in capsys.readouterr().out


def test_rules_docs_are_current() -> None:
    path = Path(__file__).resolve().parents[1] / "docs" / "rules.md"
    assert path.read_text(encoding="utf-8") == render_rule_docs()
