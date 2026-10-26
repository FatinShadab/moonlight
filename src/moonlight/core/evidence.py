"""Structured evidence shared by local and reasoning pipeline stages."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    model_validator,
)

SubjectType = Literal["process", "storage"]
Availability = Literal["observed", "unavailable", "error"]
SeverityHint = Literal["info", "low", "medium", "high", "critical"]

_NAME_PATTERN = re.compile(r"[a-z][a-z0-9_-]*\Z")
_ID_PATTERN = r"^ev-(process|storage)-[a-z][a-z0-9_-]*-[0-9a-f]{8}$"


def make_evidence_id(
    subject_type: SubjectType,
    subject_id: str,
    source: str,
    kind: str,
    discriminator: str = "",
) -> str:
    """Return a stable ID for one logical observation on a subject.

    Use a stable discriminator when a source emits multiple items of the same
    kind for one subject. Values and timestamps are intentionally excluded.
    """
    if subject_type not in ("process", "storage"):
        raise ValueError("subject_type must be 'process' or 'storage'")
    if not subject_id:
        raise ValueError("subject_id must not be empty")
    if not _NAME_PATTERN.fullmatch(source):
        raise ValueError("source must be a lowercase machine name")
    if not _NAME_PATTERN.fullmatch(kind):
        raise ValueError("kind must be a lowercase machine name")

    identity = [subject_type, subject_id, source, kind, discriminator]
    canonical = json.dumps(identity, ensure_ascii=False, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"ev-{subject_type}-{kind}-{digest[:8]}"


class EvidenceItem(BaseModel):
    """One observed, unavailable, or failed piece of evidence."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra={
            "allOf": [
                {
                    "if": {"properties": {"availability": {"const": "observed"}}},
                    "then": {"properties": {"reason": {"type": "null"}}},
                },
                {
                    "if": {
                        "properties": {
                            "availability": {"enum": ["unavailable", "error"]}
                        }
                    },
                    "then": {
                        "required": ["reason"],
                        "properties": {"reason": {"type": "string", "pattern": r"\S"}},
                    },
                },
            ]
        },
    )

    id: str = Field(pattern=_ID_PATTERN)
    source: str = Field(pattern=r"^[a-z][a-z0-9_-]*$")
    kind: str = Field(pattern=r"^[a-z][a-z0-9_-]*$")
    value: JsonValue
    severity_hint: SeverityHint | None = None
    availability: Availability
    reason: str | None = None
    timestamp: AwareDatetime

    @model_validator(mode="after")
    def validate_reason(self) -> EvidenceItem:
        """Keep missing evidence explicit and observed evidence unambiguous."""
        if self.availability == "observed":
            if self.reason is not None:
                raise ValueError("observed evidence must not have a reason")
        elif self.reason is None or not self.reason.strip():
            raise ValueError("unavailable or errored evidence requires a reason")
        return self


class EvidenceBundle(BaseModel):
    """Evidence for one process or storage subject."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    subject_type: SubjectType
    subject_id: str = Field(min_length=1)
    items: tuple[EvidenceItem, ...]

    @model_validator(mode="after")
    def reject_duplicate_ids(self) -> EvidenceBundle:
        """Prevent ambiguous report citations within a bundle."""
        ids = [item.id for item in self.items]
        if len(ids) != len(set(ids)):
            raise ValueError("evidence IDs must be unique within a bundle")
        return self

    def get_item(self, item_id: str) -> EvidenceItem | None:
        """Look up an item by its stable ID, or return None."""
        return next((item for item in self.items if item.id == item_id), None)
