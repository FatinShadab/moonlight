"""Contract tests for shared evidence and its public JSON Schema."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from moonlight.core.evidence import (
    MAX_EVIDENCE_VALUE_BYTES,
    EvidenceBundle,
    EvidenceItem,
    EvidenceKind,
    SeverityHint,
    make_evidence_id,
)


def sample_item(**overrides: object) -> EvidenceItem:
    data: dict[str, object] = {
        "id": make_evidence_id(
            "process", "4242", "process_collector", EvidenceKind.EXECUTABLE_PATH
        ),
        "source": "process_collector",
        "kind": EvidenceKind.EXECUTABLE_PATH,
        "value": {"path": "C:/Example/app.exe"},
        "severity_hint": SeverityHint.INFO,
        "availability": "observed",
        "reason": None,
        "timestamp": datetime(2026, 10, 27, tzinfo=UTC),
    }
    data.update(overrides)
    return EvidenceItem.model_validate(data)


def test_id_is_stable_and_changes_with_identity() -> None:
    first = make_evidence_id(
        "process", "4242", "process_collector", EvidenceKind.EXECUTABLE_PATH
    )
    assert first == "ev-process-executable_path-fcee12d7"
    assert first == make_evidence_id(
        "process", "4242", "process_collector", EvidenceKind.EXECUTABLE_PATH
    )
    assert first != make_evidence_id(
        "process", "4243", "process_collector", EvidenceKind.EXECUTABLE_PATH
    )
    assert first != make_evidence_id(
        "process", "4242", "other_collector", EvidenceKind.EXECUTABLE_PATH
    )
    assert first != make_evidence_id(
        "process", "4242", "process_collector", EvidenceKind.COMMAND_LINE
    )
    assert first != make_evidence_id(
        "process", "4242", "process_collector", EvidenceKind.EXECUTABLE_PATH, "child-1"
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
    one = make_evidence_id(
        "storage", "C:/Temp", "storage_scan", EvidenceKind.FILE_AGE, "a.txt"
    )
    two = make_evidence_id(
        "storage", "C:/Temp", "storage_scan", EvidenceKind.FILE_AGE, "b.txt"
    )
    assert one != two
    assert one == make_evidence_id(
        "storage", "C:/Temp", "storage_scan", EvidenceKind.FILE_AGE, "a.txt"
    )
    assert "C:/Temp" not in one
    assert "a.txt" not in one


def test_kind_and_severity_hint_reject_unknown_values() -> None:
    for field, value in (("kind", "unknown_kind"), ("severity_hint", "urgent")):
        with pytest.raises(ValidationError):
            sample_item(**{field: value})


def test_bundle_rejects_duplicate_ids() -> None:
    item = sample_item()
    with pytest.raises(ValidationError, match="unique"):
        EvidenceBundle(subject_type="process", subject_id="4242", items=(item, item))


def test_bundle_lookup_and_json_round_trip() -> None:
    item = sample_item(value={"nested": [1, 2]})
    bundle = EvidenceBundle(subject_type="process", subject_id="4242", items=(item,))
    restored = EvidenceBundle.model_validate_json(bundle.model_dump_json())
    assert restored == bundle
    assert bundle.model_copy(deep=True).model_dump(mode="json") == bundle.model_dump(
        mode="json"
    )
    assert isinstance(restored.items, tuple)
    assert restored.get_item(item.id) == item
    assert restored.get_item("ev-process-missing") is None


def test_nested_values_are_frozen_without_changing_json() -> None:
    original: dict[str, Any] = {"outer": [{"name": "before", "numbers": [1, 2]}]}
    item = sample_item(value=original)
    original["outer"][0]["name"] = "after"
    assert item.model_dump(mode="json")["value"] == {
        "outer": [{"name": "before", "numbers": [1, 2]}]
    }
    outer = cast(Any, item.value)
    nested = outer["outer"]
    leaf = nested[0]
    with pytest.raises(TypeError):
        leaf["name"] = "changed"
    with pytest.raises(TypeError):
        dict.__setitem__(leaf, "name", "changed")
    with pytest.raises(AttributeError):
        nested.append("changed")
    with pytest.raises(TypeError):
        leaf["numbers"][0] = 9
    copied = item.model_copy(update={"value": {"nested": [1, 2]}})
    with pytest.raises(AttributeError):
        cast(Any, copied.value)["nested"].append(3)
    deep_copy = item.model_copy(deep=True)
    assert (
        deep_copy.model_dump(mode="json")["value"]
        == item.model_dump(mode="json")["value"]
    )
    assert EvidenceItem.model_validate_json(item.model_dump_json()) == item


@pytest.mark.parametrize(
    ("length", "accepted"),
    [
        (MAX_EVIDENCE_VALUE_BYTES - 3, True),
        (MAX_EVIDENCE_VALUE_BYTES - 2, True),
        (MAX_EVIDENCE_VALUE_BYTES - 1, False),
    ],
)
def test_value_size_boundary(length: int, accepted: bool) -> None:
    value = "x" * length  # Two JSON quotation marks count toward the cap.
    if accepted:
        assert sample_item(value=value).value == value
    else:
        with pytest.raises(ValidationError, match="value_too_large"):
            sample_item(value=value)


def test_nested_json_overhead_counts_toward_size_cap() -> None:
    prefix_size = len(json.dumps({"nested": ""}, separators=(",", ":")))
    at_cap = {"nested": "x" * (MAX_EVIDENCE_VALUE_BYTES - prefix_size)}
    assert sample_item(value=at_cap).model_dump(mode="json")["value"] == at_cap
    with pytest.raises(ValidationError, match="value_too_large"):
        sample_item(value={"nested": at_cap["nested"] + "x"})


def test_multibyte_utf8_counts_bytes_not_characters() -> None:
    at_cap = "é" * ((MAX_EVIDENCE_VALUE_BYTES - 2) // 2)
    assert sample_item(value=at_cap).value == at_cap
    with pytest.raises(ValidationError, match="value_too_large"):
        sample_item(value=at_cap + "é")


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
    regenerated = json.dumps(
        EvidenceBundle.model_json_schema(), indent=2, sort_keys=True
    )
    assert schema_path.read_text(encoding="utf-8") == regenerated + "\n"
