"""Desktop review interface and UI components."""

from __future__ import annotations

from moonlight.ui.badge import (
    CLOUD_PLACEHOLDER_BADGE_TEXT,
    ProviderBadgeWidget,
    get_provider_badge,
)
from moonlight.ui.controller import (
    InvestigationController,
    InvestigationRunResult,
    InvestigationWorker,
)
from moonlight.ui.dialogs import (
    ActionPreviewDialog,
    LiveProviderWarningDialog,
)
from moonlight.ui.events import (
    EventBus,
    InvestigationEvent,
    get_event_bus,
)
from moonlight.ui.panels import (
    ActivityTimelineWidget,
    ApprovalsPanelWidget,
    RightSidePanelWidget,
)
from moonlight.ui.review import ReportReviewWidget
from moonlight.ui.theme import (
    COLORS,
    RADII,
    SPACING,
    TYPE,
    build_qss,
    get_confidence_chip_style,
    get_fallback_badge_style,
    get_risk_chip_style,
)
from moonlight.ui.views import (
    PolicyLogWidget,
    ProcessesViewWidget,
    SentToModelWidget,
    StorageViewWidget,
)
from moonlight.ui.window import MoonlightMainWindow

__all__ = [
    "CLOUD_PLACEHOLDER_BADGE_TEXT",
    "COLORS",
    "RADII",
    "SPACING",
    "TYPE",
    "ActionPreviewDialog",
    "ActivityTimelineWidget",
    "ApprovalsPanelWidget",
    "EventBus",
    "InvestigationController",
    "InvestigationEvent",
    "InvestigationRunResult",
    "InvestigationWorker",
    "LiveProviderWarningDialog",
    "MoonlightMainWindow",
    "PolicyLogWidget",
    "ProcessesViewWidget",
    "ProviderBadgeWidget",
    "ReportReviewWidget",
    "RightSidePanelWidget",
    "SentToModelWidget",
    "StorageViewWidget",
    "build_qss",
    "get_confidence_chip_style",
    "get_event_bus",
    "get_fallback_badge_style",
    "get_provider_badge",
    "get_risk_chip_style",
]
