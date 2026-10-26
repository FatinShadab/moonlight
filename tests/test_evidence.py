"""Contract tests for shared evidence and its public JSON Schema."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from moonlight.core.evidence import EvidenceBundle, EvidenceItem, make_evidence_id


def sample_item(**overrides: object) -> EvidenceItem:
    data: dict[str, object] = {
        "id": make_evidence_id(
            "process", "4242", "process_collector", "executable_path"
        ),
        "source": "process_collector",
        "kind": "executable_path",
        "value": {"path": "C:/Example/app.exe"},
        "severity_hint": "info",
        "availability": "observed",
        "reason": None,
        "timestamp": datetime(2026, 10, 27, tzinfo=UTC),
    }
    data.update(overrides)
    return EvidenceItem.model_validate(data)


def test_id_is_stable_and_changes_with_identity() -> None:
    first = make_evidence_id("process", "4242", "process_collector", "executable_path")
    assert first == "ev-process-executable_path-fcee12d7"
    assert first == make_evidence_id(
        "process", "4242", "process_collector", "executable_path"
    )
    assert first != make_evidence_id(
        "process", "4243", "process_collector", "executable_path"
    )
    assert first != make_evidence_id(
        "process", "4242", "other_collector", "executable_path"
    )
    assert first != make_evidence_id(
        "process", "4242", "process_collector", "command_line"
    )
    assert first != make_evidence_id(
        "process", "4242", "process_collector", "executable_path", "child-1"
    )
    assert "4242" not in first


def test_id_rejects_a_long_digest() -> None:
    with pytest.raises(ValidationError):
        sample_item(
            id=(
                "ev-process-executable_path-"
                "fcee12d76c81336c92bb9207a482f4b0b8e84f1d0bd6455e1f9e2455f9b63e8e"
            )
        )


def test_id_discriminator_is_stable_for_repeated_kinds() -> None:
    one = make_evidence_id("storage", "C:/Temp", "storage_scan", "file_age", "a.txt")
    two = make_evidence_id("storage", "C:/Temp", "storage_scan", "file_age", "b.txt")
    assert one != two
    assert one == make_evidence_id(
        "storage", "C:/Temp", "storage_scan", "file_age", "a.txt"
    )
    assert "C:/Temp" not in one
    assert "a.txt" not in one


def test_bundle_rejects_duplicate_ids() -> None:
    item = sample_item()
    with pytest.raises(ValidationError, match="unique"):
        EvidenceBundle(subject_type="process", subject_id="4242", items=(item, item))


def test_bundle_lookup_and_json_round_trip() -> None:
    item = sample_item()
    bundle = EvidenceBundle(subject_type="process", subject_id="4242", items=(item,))
    restored = EvidenceBundle.model_validate_json(bundle.model_dump_json())
    assert restored == bundle
    assert isinstance(restored.items, tuple)
    assert restored.get_item(item.id) == item
    assert restored.get_item("ev-process-missing") is None


@pytest.mark.parametrize("availability", ["unavailable", "error"])
def test_non_observed_evidence_requires_nonblank_reason(availability: str) -> None:
    for reason in (None, "", "  "):
        with pytest.raises(ValidationError, match="requires a reason"):
            sample_item(availability=availability, reason=reason, value=None)
    item = sample_item(availability=availability, reason="Access denied", value=None)
    assert item.reason == "Access denied"
    assert item.value is None


def test_observed_evidence_has_no_missing_reason() -> None:
    with pytest.raises(ValidationError, match="must not have a reason"):
        sample_item(reason="Access denied")


def test_timestamp_must_include_timezone() -> None:
    with pytest.raises(ValidationError):
        sample_item(timestamp=datetime(2026, 10, 27))


def test_committed_json_schema_matches_model() -> None:
    schema_path = Path(__file__).resolve().parents[1] / "docs" / "evidence-schema.json"
    committed = json.loads(schema_path.read_text(encoding="utf-8"))
    assert committed == EvidenceBundle.model_json_schema()
