"""Structured evidence shared by local and reasoning pipeline stages."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Literal, Self, cast

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    field_serializer,
    model_validator,
)

SubjectType = Literal["process", "storage"]
Availability = Literal["observed", "unavailable", "error"]
MAX_EVIDENCE_VALUE_BYTES = 64 * 1024


class EvidenceKind(StrEnum):
    """Supported categories of process and storage evidence."""

    EXECUTABLE_PATH = "executable_path"
    PARENT_CHAIN = "parent_chain"
    COMMAND_LINE = "command_line"
    START_TIME = "start_time"
    USER = "user"
    IO_COUNTERS = "io_counters"
    OPEN_FILES = "open_files"
    NETWORK_ACTIVITY = "network_activity"
    SHA256 = "sha256"
    SIGNATURE_STATUS = "signature_status"
    FOLDER_SIZE = "folder_size"
    GROWTH_RATE = "growth_rate"
    FILE_AGE = "file_age"
    FILE_TYPE = "file_type"
    DUPLICATE_HASH = "duplicate_hash"
    PROCESS_DISK_LINK = "process_disk_link"


class SeverityHint(StrEnum):
    """Local relevance hint, not a final risk verdict."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_NAME_PATTERN = re.compile(r"[a-z][a-z0-9_-]*\Z")
_ID_PATTERN = r"^ev-(process|storage)-[a-z][a-z0-9_-]*-[0-9a-f]{8}$"


def _freeze_value(value: JsonValue) -> JsonValue:
    if isinstance(value, Mapping):
        frozen = {key: _freeze_value(child) for key, child in value.items()}
        return cast(JsonValue, MappingProxyType(frozen))
    if isinstance(value, (list, tuple)):
        return cast(JsonValue, tuple(_freeze_value(child) for child in value))
    return value


def _plain_value(value: JsonValue) -> JsonValue:
    if isinstance(value, Mapping):
        return {key: _plain_value(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain_value(child) for child in value]
    return value


def value_exceeds_size_limit(value: JsonValue) -> bool:
    """Bound compact UTF-8 JSON without materializing an oversized string."""
    size = 0
    encoder = json.JSONEncoder(
        ensure_ascii=False, separators=(",", ":"), allow_nan=True
    )
    for part in encoder.iterencode(_plain_value(value)):
        size += len(part.encode("utf-8"))
        if size > MAX_EVIDENCE_VALUE_BYTES:
            return True
    return False


def make_evidence_id(
    subject_type: SubjectType,
    subject_id: str,
    source: str,
    kind: EvidenceKind,
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
    kind = EvidenceKind(kind)

    identity = [subject_type, subject_id, source, kind.value, discriminator]
    canonical = json.dumps(identity, ensure_ascii=False, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"ev-{subject_type}-{kind.value}-{digest[:8]}"


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
    kind: EvidenceKind
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
            if value_exceeds_size_limit(self.value):
                raise ValueError("value_too_large")
        elif self.reason is None or not self.reason.strip():
            raise ValueError("unavailable or errored evidence requires a reason")
        object.__setattr__(self, "value", _freeze_value(self.value))
        return self

    @field_serializer("value")
    def serialize_value(self, value: JsonValue) -> JsonValue:
        return _plain_value(value)

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> Self:
        """Immutable items can be shared when a bundle is deep-copied."""
        return self

    def model_copy(
        self, *, update: Mapping[str, Any] | None = None, deep: bool = False
    ) -> Self:
        """Freeze values introduced through Pydantic's unvalidated copy API."""
        # The only container field is already immutable, so it can be shared.
        copied = super().model_copy(update=update, deep=False)
        if copied.availability == "observed" and value_exceeds_size_limit(copied.value):
            raise ValueError("value_too_large")
        object.__setattr__(copied, "value", _freeze_value(copied.value))
        return copied


def bounded_evidence_item(
    *,
    id: str,
    source: str,
    kind: EvidenceKind,
    value: JsonValue,
    availability: Availability,
    reason: str | None,
    timestamp: datetime,
    severity_hint: SeverityHint | None = None,
) -> EvidenceItem:
    """Convert an oversized collector observation to explicit missing evidence."""
    if value_exceeds_size_limit(value):
        value, availability, reason = None, "unavailable", "value_too_large"
    return EvidenceItem(
        id=id,
        source=source,
        kind=kind,
        value=_plain_value(value),
        severity_hint=severity_hint,
        availability=availability,
        reason=reason,
        timestamp=timestamp,
    )


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
