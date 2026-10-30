"""Right side panel widgets: Activity Timeline and Approvals.

Features:
- ActivityTimelineWidget: reactive stream of InvestigationEvents from EventBus.
- ApprovalsPanelWidget: pending action recommendations, policy validation chips,
  and dry-run preview launcher.
- RightSidePanelWidget: dual-tab container holding Activity and Approvals with
  guaranteed non-collapsing dimensions and zero horizontal overflow.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from moonlight.policy.actions import ProposedAction
from moonlight.policy.engine import validate_proposed_action
from moonlight.reasoning.models import RecommendedAction, Report
from moonlight.ui.dialogs import ActionPreviewDialog
from moonlight.ui.events import EventBus, InvestigationEvent, get_event_bus
from moonlight.ui.review import CitationButton
from moonlight.ui.theme import (
    COLORS,
    RADII,
    SPACING,
)


class ActivityItemWidget(QFrame):
    """Card representing a single investigation event on the timeline."""

    citation_clicked = Signal(str)

    def __init__(
        self,
        event: InvestigationEvent,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("card_subtle")
        self.investigation_event = event

        c = COLORS
        r = RADII

        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACING.sm, SPACING.sm, SPACING.sm, SPACING.sm)
        layout.setSpacing(SPACING.xs)

        # Header row: timestamp, severity chip, kind
        header_row = QHBoxLayout()
        header_row.setSpacing(SPACING.xs)

        time_str = event.timestamp.strftime("%H:%M:%S")
        time_lbl = QLabel(time_str)
        time_lbl.setStyleSheet(f"color: {c.text_muted}; font-size: 11px;")
        header_row.addWidget(time_lbl)

        # Severity chip
        sev = event.severity.lower()
        sev_chip = QLabel(event.severity.upper())
        if sev in ("high", "error"):
            sev_style = (
                f"background-color: {c.risk_high_bg}; color: {c.risk_high_text}; "
                f"border: 1px solid {c.risk_high_border};"
            )
        elif sev in ("review", "warning"):
            sev_style = (
                f"background-color: {c.risk_review_bg}; color: {c.risk_review_text}; "
                f"border: 1px solid {c.risk_review_border};"
            )
        elif sev == "low":
            sev_style = (
                f"background-color: {c.risk_low_bg}; color: {c.risk_low_text}; "
                f"border: 1px solid {c.risk_low_border};"
            )
        else:
            sev_style = (
                f"background-color: {c.accent_surface}; color: {c.accent_primary}; "
                f"border: 1px solid {c.accent_border};"
            )
        sev_chip.setStyleSheet(
            f"{sev_style} font-weight: 700; font-size: 10px; "
            f"padding: 1px 6px; border-radius: {r.pill}px;"
        )
        header_row.addWidget(sev_chip)

        # Event kind label
        kind_clean = event.kind.replace("_", " ").title()
        kind_lbl = QLabel(kind_clean)
        kind_lbl.setWordWrap(True)
        kind_lbl.setStyleSheet(
            f"color: {c.text_secondary}; font-weight: 600; font-size: 11px;"
        )
        header_row.addWidget(kind_lbl)
        header_row.addStretch()

        layout.addLayout(header_row)

        # Subject if present
        if event.subject:
            sub_lbl = QLabel(f"Subject: {event.subject}")
            sub_lbl.setWordWrap(True)
            sub_lbl.setStyleSheet(
                f"color: {c.accent_primary}; font-weight: 600; font-size: 12px;"
            )
            layout.addWidget(sub_lbl)

        # Message
        msg_lbl = QLabel(event.message)
        msg_lbl.setWordWrap(True)
        msg_lbl.setStyleSheet(
            f"color: {c.text_primary}; font-size: 12px; line-height: 1.3;"
        )
        layout.addWidget(msg_lbl)

        # Citations if present (compact with elided display and full tooltip)
        if event.evidence_ids:
            cit_box = QVBoxLayout()
            cit_box.setSpacing(2)

            cit_label = QLabel("Citations:")
            cit_label.setStyleSheet(
                f"color: {c.text_muted}; font-size: 11px; font-weight: 600;"
            )
            cit_box.addWidget(cit_label)

            row = QHBoxLayout()
            row.setSpacing(SPACING.xs)
            for idx, cid in enumerate(event.evidence_ids):
                # Format short display name for long evidence IDs
                display_name = cid
                if len(cid) > 22:
                    display_name = cid[:12] + "…" + cid[-7:]
                chip = CitationButton(display_name)
                chip.setToolTip(f"Jump to evidence item: {cid}")
                chip.clicked.connect(
                    lambda _checked=False, ev_id=cid: self.citation_clicked.emit(ev_id)
                )
                row.addWidget(chip)
                # Create wrapped rows if more than 2 citations
                if (idx + 1) % 2 == 0 and idx + 1 < len(event.evidence_ids):
                    row.addStretch()
                    cit_box.addLayout(row)
                    row = QHBoxLayout()
                    row.setSpacing(SPACING.xs)

            row.addStretch()
            cit_box.addLayout(row)
            layout.addLayout(cit_box)


class ActivityTimelineWidget(QWidget):
    """Investigation telemetry event stream rendering events in chronological order."""

    citation_clicked = Signal(str)

    def __init__(
        self,
        event_bus: EventBus | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("activity_timeline_widget")
        self._bus = event_bus if event_bus is not None else get_event_bus()
        self._events: list[InvestigationEvent] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACING.sm, SPACING.sm, SPACING.sm, SPACING.sm)
        layout.setSpacing(SPACING.sm)

        # Top bar with event count and clear button
        top_bar = QHBoxLayout()
        self.count_label = QLabel("0 Events")
        self.count_label.setStyleSheet(
            f"color: {COLORS.text_muted}; font-size: 12px; font-weight: 600;"
        )
        top_bar.addWidget(self.count_label)
        top_bar.addStretch()

        clear_btn = QPushButton("Clear")
        clear_btn.setStyleSheet("font-size: 11px; padding: 2px 8px;")
        clear_btn.clicked.connect(self.clear_events)
        top_bar.addWidget(clear_btn)
        layout.addLayout(top_bar)

        # Scrollable events container
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll_area.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )

        self.container = QWidget()
        self.events_layout = QVBoxLayout(self.container)
        self.events_layout.setContentsMargins(0, 0, 0, 0)
        self.events_layout.setSpacing(SPACING.xs)

        # Empty state label
        self.empty_label = QLabel("No investigation activity recorded yet.")
        self.empty_label.setStyleSheet(
            f"color: {COLORS.text_muted}; font-style: italic; padding: 20px 0;"
        )
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.events_layout.addWidget(self.empty_label)
        self.events_layout.addStretch()

        self.scroll_area.setWidget(self.container)
        layout.addWidget(self.scroll_area)

        # Connect to event bus
        self._bus.event_emitted.connect(self.add_event)

    @property
    def event_count(self) -> int:
        return len(self._events)

    def add_event(self, event: InvestigationEvent) -> None:
        """Add an event to the timeline and update UI."""
        self._events.append(event)
        self.empty_label.setVisible(False)

        # Remove stretch item if at end
        item_count = self.events_layout.count()
        if item_count > 0:
            last_item = self.events_layout.itemAt(item_count - 1)
            if last_item is not None and last_item.spacerItem() is not None:
                self.events_layout.takeAt(item_count - 1)

        # Create event item widget
        item_widget = ActivityItemWidget(event)
        item_widget.citation_clicked.connect(self.citation_clicked)
        self.events_layout.addWidget(item_widget)
        self.events_layout.addStretch()

        self.count_label.setText(f"{len(self._events)} Events")

    def clear_events(self) -> None:
        """Clear all events from the timeline."""
        self._events.clear()
        while self.events_layout.count() > 0:
            layout_item = self.events_layout.takeAt(0)
            if layout_item is not None:
                w = layout_item.widget()
                if w is not None:
                    w.deleteLater()

        self.empty_label.setVisible(True)
        self.events_layout.addWidget(self.empty_label)
        self.events_layout.addStretch()
        self.count_label.setText("0 Events")


class ApprovalItemWidget(QFrame):
    """Card for an action approval item in the right panel."""

    action_executed = Signal(object)  # ExecutionResult
    citation_clicked = Signal(str)

    def __init__(
        self,
        action_rec: RecommendedAction,
        hooks: dict[str, Callable[..., Any]] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("card_subtle")
        self.rec = action_rec
        self._hooks = hooks or {}

        c = COLORS
        r = RADII

        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACING.sm, SPACING.sm, SPACING.sm, SPACING.sm)
        layout.setSpacing(SPACING.xs)

        top_row = QHBoxLayout()
        act_title = QLabel(action_rec.action_id.replace("_", " ").upper())
        act_title.setWordWrap(True)
        act_title.setStyleSheet(
            f"color: {c.accent_primary}; font-weight: 700; font-size: 12px;"
        )
        top_row.addWidget(act_title)

        # Validate with policy
        self.proposed = ProposedAction(
            action_type=action_rec.action_id,
            reason=action_rec.reason,
            evidence_ids=action_rec.evidence_ids,
        )
        decision = validate_proposed_action(self.proposed)

        self.verdict_chip = QLabel()
        if decision.allowed:
            self.verdict_chip.setText("ALLOWED")
            self.verdict_chip.setStyleSheet(
                f"background-color: {c.risk_low_bg}; color: {c.risk_low_text}; "
                f"font-weight: 700; font-size: 10px; padding: 1px 6px; "
                f"border-radius: {r.pill}px;"
            )
        else:
            self.verdict_chip.setText("BLOCKED")
            self.verdict_chip.setStyleSheet(
                f"background-color: {c.risk_high_bg}; color: {c.risk_high_text}; "
                f"font-weight: 700; font-size: 10px; padding: 1px 6px; "
                f"border-radius: {r.pill}px;"
            )
        top_row.addWidget(self.verdict_chip)
        top_row.addStretch()
        layout.addLayout(top_row)

        reason_lbl = QLabel(action_rec.reason)
        reason_lbl.setWordWrap(True)
        reason_lbl.setStyleSheet(
            f"color: {c.text_secondary}; font-size: 12px; line-height: 1.3;"
        )
        layout.addWidget(reason_lbl)

        # Action button or executed badge
        btn_row = QHBoxLayout()
        if decision.allowed:
            self.review_btn = QPushButton("Review & Consent")
            self.review_btn.setObjectName("review_approval_btn")
            self.review_btn.setProperty("primary", "true")
            self.review_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self.review_btn.clicked.connect(self._open_preview_dialog)
            btn_row.addWidget(self.review_btn)

            self.status_label = QLabel("Pending Review")
            self.status_label.setStyleSheet(f"color: {c.text_muted}; font-size: 11px;")
            btn_row.addWidget(self.status_label)
        else:
            self.blocked_btn = QPushButton("Action Blocked")
            self.blocked_btn.setEnabled(False)
            self.blocked_btn.setStyleSheet(
                f"background-color: {c.bg_surface_alt}; color: {c.text_muted}; "
                f"font-size: 11px; padding: 4px 10px; "
                f"border: 1px solid {c.border_subtle};"
            )
            rej = (
                str(decision.rejection_reason)
                if decision.rejection_reason
                else "Blocked by policy rule"
            )
            tooltip_msg = f"Policy enforcement: {rej}"
            self.blocked_btn.setToolTip(tooltip_msg)
            btn_row.addWidget(self.blocked_btn)

            disp_rej = rej[:28] + "…" if len(rej) > 28 else rej
            self.status_label = QLabel(disp_rej)
            self.status_label.setToolTip(rej)
            self.status_label.setStyleSheet(
                f"color: {c.risk_high_text}; font-size: 10px;"
            )
            btn_row.addWidget(self.status_label)

        btn_row.addStretch()
        layout.addLayout(btn_row)

    def _open_preview_dialog(self) -> None:
        dialog = ActionPreviewDialog(
            action=self.proposed,
            hooks=self._hooks,
            parent=self.window(),
        )
        if dialog.exec():
            res = dialog.execution_result
            if res and res.success:
                if hasattr(self, "review_btn"):
                    self.review_btn.setEnabled(False)
                    self.review_btn.setText("Executed")
                self.status_label.setText("✓ Executed")
                self.status_label.setStyleSheet(
                    f"color: {COLORS.risk_low_text}; font-weight: 600;"
                )
                self.action_executed.emit(res)


class ApprovalsPanelWidget(QWidget):
    """Panel managing pending action recommendations and consent decisions."""

    action_executed = Signal(object)
    citation_clicked = Signal(str)

    def __init__(
        self,
        hooks: dict[str, Callable[..., Any]] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("approvals_panel_widget")
        self._hooks = hooks or {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACING.sm, SPACING.sm, SPACING.sm, SPACING.sm)
        layout.setSpacing(SPACING.sm)

        # Header info
        top_bar = QHBoxLayout()
        self.info_label = QLabel("Policy-gated action queue")
        self.info_label.setStyleSheet(
            f"color: {COLORS.text_muted}; font-size: 12px; font-weight: 600;"
        )
        top_bar.addWidget(self.info_label)
        layout.addLayout(top_bar)

        # Scroll area
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll_area.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )

        self.container = QWidget()
        self.items_layout = QVBoxLayout(self.container)
        self.items_layout.setContentsMargins(0, 0, 0, 0)
        self.items_layout.setSpacing(SPACING.xs)

        self.empty_label = QLabel("No pending actions in current investigation.")
        self.empty_label.setStyleSheet(
            f"color: {COLORS.text_muted}; font-style: italic; padding: 20px 0;"
        )
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.items_layout.addWidget(self.empty_label)
        self.items_layout.addStretch()

        self.scroll_area.setWidget(self.container)
        layout.addWidget(self.scroll_area)

    def set_actions(
        self,
        actions: Sequence[RecommendedAction],
        report: Report | None = None,
    ) -> None:
        """Populate approvals panel with recommended actions from report."""
        while self.items_layout.count() > 0:
            layout_item = self.items_layout.takeAt(0)
            if layout_item is not None:
                w = layout_item.widget()
                if w is not None:
                    w.deleteLater()

        if not actions:
            self.empty_label.setVisible(True)
            self.items_layout.addWidget(self.empty_label)
            self.items_layout.addStretch()
            self.info_label.setText("0 Pending Actions")
            return

        self.empty_label.setVisible(False)
        for act in actions:
            item = ApprovalItemWidget(act, hooks=self._hooks)
            item.action_executed.connect(self.action_executed)
            item.citation_clicked.connect(self.citation_clicked)
            self.items_layout.addWidget(item)

        self.items_layout.addStretch()
        self.info_label.setText(f"{len(actions)} Pending Action(s)")


class RightSidePanelWidget(QTabWidget):
    """Dual-tab right side panel combining Activity timeline and Approvals."""

    citation_clicked = Signal(str)
    action_executed = Signal(object)

    def __init__(
        self,
        event_bus: EventBus | None = None,
        hooks: dict[str, Callable[..., Any]] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("side_panel")

        # Responsive dock constraints preventing collapse when empty
        self.setMinimumWidth(320)
        self.setMaximumWidth(420)

        # Tab bar configuration: expanding tabs, no scroll arrows
        tab_bar = self.tabBar()
        tab_bar.setUsesScrollButtons(False)
        tab_bar.setExpanding(True)

        self.activity_widget = ActivityTimelineWidget(event_bus=event_bus)
        self.activity_widget.citation_clicked.connect(self.citation_clicked)
        self.addTab(self.activity_widget, "Activity")

        self.approvals_widget = ApprovalsPanelWidget(hooks=hooks)
        self.approvals_widget.citation_clicked.connect(self.citation_clicked)
        self.approvals_widget.action_executed.connect(self.action_executed)
        self.addTab(self.approvals_widget, "Approvals")
