"""Local append-only JSON lines audit logging for every attempted policy action."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class AuditRecord(BaseModel):
    """A single immutable audit log entry."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    timestamp: AwareDatetime
    event_type: Literal["validation", "preview", "execution"]
    action_type: str
    status: Literal["allowed", "rejected", "previewed", "executed"]
    allowed: bool
    target: str | None = None
    reason: str | None = None
    preview_id: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class PolicyAuditLogger:
    """Thread-safe, append-only logger writing structured JSON lines."""

    def __init__(self, log_path: Path | str | None = None) -> None:
        if log_path is not None:
            self._path = Path(log_path)
        else:
            self._path = Path.home() / ".moonlight" / "policy_audit.jsonl"
        self._lock = Lock()

    @property
    def path(self) -> Path:
        return self._path

    def log(self, record: AuditRecord) -> None:
        """Append an AuditRecord as a JSON line."""
        line = record.model_dump_json() + "\n"
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(line)

    def log_event(
        self,
        event_type: Literal["validation", "preview", "execution"],
        action_type: str,
        status: Literal["allowed", "rejected", "previewed", "executed"],
        allowed: bool,
        target: str | None = None,
        reason: str | None = None,
        preview_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditRecord:
        """Create, log, and return an AuditRecord."""
        record = AuditRecord(
            timestamp=datetime.now(UTC),
            event_type=event_type,
            action_type=action_type,
            status=status,
            allowed=allowed,
            target=target,
            reason=reason,
            preview_id=preview_id,
            details=details or {},
        )
        self.log(record)
        return record

    def read_records(self) -> tuple[AuditRecord, ...]:
        """Read and validate all audit records from disk."""
        with self._lock:
            if not self._path.exists():
                return ()
            records: list[AuditRecord] = []
            with open(self._path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        records.append(AuditRecord.model_validate(json.loads(line)))
            return tuple(records)
