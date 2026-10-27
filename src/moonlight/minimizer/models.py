"""The wire payload is separate from the local UI audit envelope."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from moonlight.core.evidence import (
    Availability,
    EvidenceKind,
    SeverityHint,
    SubjectType,
)


class PrivacyContext(BaseModel):
    """Optional explicit identities; no ambient environment or network discovery."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    usernames: tuple[str, ...] = ()
    hostnames: tuple[str, ...] = ()


class MinimizerSettings(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    max_command_chars: int = Field(default=512, ge=32, le=8192)
    max_evidence_items: int = Field(default=256, ge=1, le=4096)


class MinimizedItem(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    id: str
    kind: EvidenceKind
    availability: Availability
    severity_hint: SeverityHint | None
    value: JsonValue


class MinimizedBundle(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    subject_type: SubjectType
    subject: str
    items: tuple[MinimizedItem, ...]


class ModelPayload(BaseModel):
    """Only this JSON object is eligible for a future model transport."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    schema_version: Literal[1] = 1
    untrusted_evidence: tuple[MinimizedBundle, ...]


class RedactionEvent(BaseModel):
    """Local metadata only: never record the original or unknown field names."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    location: str
    operation: Literal["replace", "omit", "truncate"]
    category: str
    placeholder: str | None = None


class MinimizationResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    payload_json: str
    redaction_log: tuple[RedactionEvent, ...]

    def payload_bytes(self) -> bytes:
        """UI preview and future transport must use these exact UTF-8 bytes."""
        return self.payload_json.encode("utf-8")


class MinimizationError(ValueError):
    """A fixed-code failure: withhold the payload and retain local rules results."""
