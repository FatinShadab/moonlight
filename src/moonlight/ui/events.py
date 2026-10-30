"""Event bus and investigation telemetry models for Moonlight UI.

Provides:
- InvestigationEvent capturing immutable investigation lifecycle events.
- Qt-signal EventBus enabling decoupled reactive updates (Activity timeline, logs).
- Derived event emission helpers without modifying core engine modules.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Final, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field
from PySide6.QtCore import QObject, Signal

EventSeverity = Literal["info", "low", "review", "high", "warning", "error"]


class InvestigationEvent(BaseModel):
    """An immutable investigation event from collection, rules, or reasoning."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    timestamp: AwareDatetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timezone-aware timestamp when the event occurred.",
    )
    kind: str = Field(
        min_length=1,
        description="Event kind identifier (e.g. collection_started, rules_evaluated).",
    )
    subject: str = Field(
        default="",
        description="Subject of the investigation (process name, PID, path).",
    )
    message: str = Field(
        min_length=1,
        description="Human-readable event message for the activity timeline.",
    )
    evidence_ids: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Citations to evidence items associated with this event.",
    )
    severity: EventSeverity = Field(
        default="info",
        description="Visual severity hint for badges and styling.",
    )


class EventBus(QObject):
    """Qt-signal event bus for publishing and subscribing to investigation events."""

    event_emitted = Signal(object)  # InvestigationEvent instance

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)

    def publish(self, event: InvestigationEvent) -> None:
        """Publish an InvestigationEvent to all subscribers."""
        self.event_emitted.emit(event)

    def emit_event(
        self,
        kind: str,
        message: str,
        *,
        subject: str = "",
        evidence_ids: tuple[str, ...] = (),
        severity: EventSeverity = "info",
        timestamp: datetime | None = None,
    ) -> InvestigationEvent:
        """Helper to create and emit an event in a single call."""
        event = InvestigationEvent(
            timestamp=timestamp or datetime.now(UTC),
            kind=kind,
            subject=subject,
            message=message,
            evidence_ids=evidence_ids,
            severity=severity,
        )
        self.publish(event)
        return event


_GLOBAL_BUS: Final[EventBus] = EventBus()


def get_event_bus() -> EventBus:
    """Return the shared application event bus."""
    return _GLOBAL_BUS
