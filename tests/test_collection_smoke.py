"""Regression for the hosted runner's legitimate Authenticode timeout."""

from __future__ import annotations

import io
from datetime import UTC, datetime

import pytest
from pydantic import JsonValue

from moonlight.collectors.process import PROCESS_KINDS
from moonlight.core.evidence import (
    EvidenceBundle,
    EvidenceItem,
    EvidenceKind,
    make_evidence_id,
)
from moonlight.eval.collection_smoke import main, validate_collection_smoke


def collected() -> EvidenceBundle:
    values: dict[EvidenceKind, JsonValue] = {
        EvidenceKind.EXECUTABLE_PATH: "C:/Synthetic/pwsh.exe",
        EvidenceKind.SHA256: {
            "sha256": "a" * 64,
            "stamp": {
                "size_bytes": 3,
                "modified_ns": 10,
                "device": 1,
                "inode": 2,
            },
        },
        EvidenceKind.SIGNATURE_STATUS: {"state": "signed_valid"},
    }
    return EvidenceBundle(
        subject_type="process",
        subject_id="42:1.0",
        items=tuple(
            EvidenceItem(
                id=make_evidence_id("process", "42:1.0", "synthetic", kind),
                source="synthetic",
                kind=kind,
                value=values.get(kind),
                availability="observed",
                timestamp=datetime(2026, 10, 27, tzinfo=UTC),
            )
            for kind in (
                *PROCESS_KINDS,
                EvidenceKind.SHA256,
                EvidenceKind.SIGNATURE_STATUS,
            )
        ),
    )


def changed(kind: EvidenceKind, **updates: object) -> EvidenceBundle:
    bundle = collected()
    return bundle.model_copy(
        update={
            "items": tuple(
                item.model_copy(update=updates) if item.kind == kind else item
                for item in bundle.items
            )
        }
    )


@pytest.mark.parametrize("state", ["signed_valid", "signed_invalid", "unsigned"])
def test_observed_signature_is_a_successful_smoke_check(state: str) -> None:
    bundle = changed(EvidenceKind.SIGNATURE_STATUS, value={"state": state})
    assert "signature observed" in validate_collection_smoke(bundle, 42)


@pytest.mark.parametrize(
    "reason", ["timeout", "access_denied", "signature_verification_unavailable"]
)
def test_documented_unavailable_signature_is_success_with_explicit_diagnostic(
    reason: str,
) -> None:
    bundle = changed(
        EvidenceKind.SIGNATURE_STATUS,
        availability="unavailable",
        reason=reason,
        value={"state": "unavailable"},
    )
    assert f"signature unavailable ({reason})" in validate_collection_smoke(bundle, 42)


@pytest.mark.parametrize(
    ("kind", "updates"),
    [
        (EvidenceKind.EXECUTABLE_PATH, {"value": ""}),
        (
            EvidenceKind.SIGNATURE_STATUS,
            {"availability": "error", "reason": "os_or_collector_error"},
        ),
        (
            EvidenceKind.SIGNATURE_STATUS,
            {
                "availability": "unavailable",
                "reason": "unexpected",
                "value": {"state": "unavailable"},
            },
        ),
        (EvidenceKind.SIGNATURE_STATUS, {"value": {"state": "unavailable"}}),
        (
            EvidenceKind.SIGNATURE_STATUS,
            {
                "availability": "unavailable",
                "reason": "timeout",
                "value": {"state": "signed_valid"},
            },
        ),
        (
            EvidenceKind.SHA256,
            {"availability": "unavailable", "reason": "timeout", "value": None},
        ),
        (EvidenceKind.SHA256, {"value": {"sha256": "malformed"}}),
        (
            EvidenceKind.EXECUTABLE_PATH,
            {"availability": "unavailable", "reason": "access_denied"},
        ),
        (
            EvidenceKind.IO_COUNTERS,
            {"availability": "error", "reason": "os_or_collector_error"},
        ),
    ],
)
def test_smoke_does_not_hide_collector_errors_or_invalid_results(
    kind: EvidenceKind,
    updates: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        validate_collection_smoke(changed(kind, **updates), 42)


def test_missing_repeated_kinds_and_wrong_process_fail() -> None:
    bundle = collected()
    with pytest.raises(ValueError, match="unexpected_process_identity"):
        validate_collection_smoke(bundle, 99)
    with pytest.raises(ValueError, match="unexpected_collection_kinds"):
        validate_collection_smoke(
            bundle.model_copy(update={"items": bundle.items[:-1]}), 42
        )
    replacement = bundle.items[0].model_copy(update={"id": bundle.items[-1].id})
    with pytest.raises(ValueError, match="unexpected_collection_kinds"):
        validate_collection_smoke(
            bundle.model_copy(update={"items": (*bundle.items[:-1], replacement)}), 42
        )


def test_cli_accepts_timed_out_signature_without_echoing_raw_evidence(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle = changed(
        EvidenceKind.SIGNATURE_STATUS,
        availability="unavailable",
        reason="timeout",
        value={"state": "unavailable"},
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(bundle.model_dump_json()))
    assert main(["--pid", "42"]) == 0
    result = capsys.readouterr()
    assert "signature unavailable (timeout)" in result.out
    assert "Synthetic" not in result.out and result.err == ""


def test_invalid_json_fails_without_echoing_untrusted_input(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("PRIVATE_UNTRUSTED_TEXT"))
    assert main(["--pid", "42"]) == 1
    result = capsys.readouterr()
    assert result.out == ""
    assert "PRIVATE_UNTRUSTED_TEXT" not in result.err
