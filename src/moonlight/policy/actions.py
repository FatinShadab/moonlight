"""Allowed action types and models for policy validation, preview, and execution."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class ActionType(StrEnum):
    """The strict allowlist of permitted action types in Moonlight.

    There is NO action that terminates a process or permanently deletes anything.
    """

    OPEN_FILE_LOCATION = "open_file_location"
    COPY_HASH_TO_CLIPBOARD = "copy_hash_to_clipboard"
    MOVE_TO_RECYCLE_BIN = "move_to_recycle_bin"
    MARK_REVIEWED = "mark_reviewed"


ALLOWED_ACTION_TYPES: frozenset[str] = frozenset(action.value for action in ActionType)
ALLOWED_ACTION_IDS: frozenset[str] = ALLOWED_ACTION_TYPES


class ProposedAction(BaseModel):
    """Action suggested by a model, rule, or user prior to policy verification."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action_type: str
    target_path: str | None = None
    target_process: str | None = None
    target_pid: int | None = None
    hash_value: str | None = None
    target_id: str | None = None
    evidence_ids: tuple[str, ...] = ()
    reason: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ValidationDecision(BaseModel):
    """Result of policy verification on a proposed action."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action: ProposedAction
    allowed: bool
    rejection_reason: str | None = None
    resolved_path: str | None = None


class ActionPreview(BaseModel):
    """Dry-run preview detailing exactly what an action would change."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    preview_id: str
    action: ProposedAction
    allowed: bool
    rejection_reason: str | None = None
    resolved_target_path: str | None = None
    description: str
    requires_confirmation: bool = False
    requires_extra_confirmation: bool = False
    storage_category: str | None = None
    target_size_bytes: int | None = None
    target_item_count: int | None = None
    target_mtime: AwareDatetime | None = None
    destination: str | None = None
    changes: tuple[str, ...] = ()
    fingerprint: str = ""
    confirmation_token: str | None = None
    timestamp: AwareDatetime


class ExecutionResult(BaseModel):
    """Result of attempting to execute an action."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    success: bool
    action_type: str
    target: str
    message: str
    error: str | None = None
    timestamp: AwareDatetime
    details: dict[str, Any] = Field(default_factory=dict)
