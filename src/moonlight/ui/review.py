"""Review interface widget displaying reports, citations, and model badges.

Features:
- Risk tier and calibrated confidence rendered as status chips carrying text
  label and color (never color alone).
- Badges: 'cloud placeholder model' for non-meta providers, 'rules-only fallback'
  for fallback reports.
- Separation of observed facts and hypotheses.
- Benign explanations, missing evidence, and uncertainty notes sections.
- Recommended actions gated by policy allowlist, with preview dry-run dialog.
- Clickable citation chips (E1, E2, ...) emitting jump-to-evidence signals.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from moonlight.policy.actions import ProposedAction
from moonlight.policy.engine import validate_proposed_action
from moonlight.reasoning.models import (
    Hypothesis,
    ObservedFact,
    RecommendedAction,
    Report,
)
from moonlight.ui.badge import ProviderBadgeWidget
from moonlight.ui.dialogs import ActionPreviewDialog
from moonlight.ui.theme import (
    COLORS,
    RADII,
    SPACING,
    get_confidence_chip_style,
    get_fallback_badge_style,
    get_risk_chip_style,
)


class CitationButton(QPushButton):
    """Clickable evidence citation chip (e.g. E1, ev-process-...)."""

    def __init__(self, citation_id: str, parent: QWidget | None = None) -> None:
        super().__init__(citation_id, parent)
        self.citation_id = citation_id
        self.setObjectName("citation_chip")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(f"Jump to evidence item: {citation_id}")
        self.setStyleSheet(
            f"background-color: {COLORS.accent_surface}; "
            f"color: {COLORS.accent_primary}; "
            f"border: 1px solid {COLORS.accent_border}; "
            f"border-radius: {RADII.sm}px; "
            f"font-weight: 700; font-size: 11px; padding: 2px 6px;"
        )


class ReportReviewWidget(QWidget):
    """Review panel displaying an investigation report with model/provider badges."""

    citation_clicked = Signal(str)
    action_preview_requested = Signal(object)  # ProposedAction

    def __init__(
        self,
        report: Report | None = None,
        hooks: dict[str, Callable[..., Any]] | None = None,
        parent: Any = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("report_review_widget")
        self._report: Report | None = None
        self._hooks = hooks or {}

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(SPACING.sm)

        # Header card with risk tier, provider info, and placeholder badges
        self.header_card = QFrame()
        self.header_card.setObjectName("card")
        header_layout = QVBoxLayout(self.header_card)
        header_layout.setContentsMargins(SPACING.md, SPACING.md, SPACING.md, SPACING.md)
        header_layout.setSpacing(SPACING.sm)

        top_row = QHBoxLayout()

        # Risk tier label and visual chip
        self.risk_label = QLabel()
        self.risk_label.setObjectName("risk_label")
        self.risk_label.setStyleSheet("font-weight: 600; font-size: 13px;")
        top_row.addWidget(self.risk_label)

        self.risk_chip = QLabel()
        self.risk_chip.setObjectName("risk_chip")
        top_row.addWidget(self.risk_chip)

        self.confidence_chip = QLabel()
        self.confidence_chip.setObjectName("confidence_chip")
        top_row.addWidget(self.confidence_chip)

        top_row.addStretch()

        self.provider_label = QLabel()
        self.provider_label.setObjectName("provider_label")
        self.provider_label.setStyleSheet(
            f"color: {COLORS.text_muted}; font-size: 12px; font-weight: 500;"
        )
        top_row.addWidget(self.provider_label)

        self.badge_widget = ProviderBadgeWidget()
        top_row.addWidget(self.badge_widget)

        self.fallback_badge = QLabel()
        self.fallback_badge.setObjectName("fallback_badge")
        self.fallback_badge.setVisible(False)
        top_row.addWidget(self.fallback_badge)

        header_layout.addLayout(top_row)

        # Executive summary
        summary_title = QLabel("Executive Summary")
        summary_title.setObjectName("section_title")
        header_layout.addWidget(summary_title)

        self.summary_label = QLabel()
        self.summary_label.setObjectName("summary_label")
        self.summary_label.setWordWrap(True)
        self.summary_label.setStyleSheet(
            f"color: {COLORS.text_primary}; font-size: 13px; line-height: 1.4;"
        )
        header_layout.addWidget(self.summary_label)

        main_layout.addWidget(self.header_card)

        # Scrollable sections for facts, hypotheses, actions
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        self.sections_container = QWidget()
        self.sections_layout = QVBoxLayout(self.sections_container)
        self.sections_layout.setContentsMargins(0, SPACING.sm, 0, 0)
        self.sections_layout.setSpacing(SPACING.md)

        scroll.setWidget(self.sections_container)
        main_layout.addWidget(scroll)

        if report is not None:
            self.set_report(report)

    @property
    def report(self) -> Report | None:
        return self._report

    def set_report(self, report: Report) -> None:
        """Bind and display a Report model."""
        self._report = report

        # 1. Update risk label and chips
        self.risk_label.setText(
            f"Risk: {report.risk_tier.upper()} ({report.confidence:.0%})"
        )

        tier_text, tier_style = get_risk_chip_style(report.risk_tier)
        self.risk_chip.setText(tier_text)
        self.risk_chip.setStyleSheet(tier_style)
        self.risk_chip.setVisible(True)

        conf_text, conf_style = get_confidence_chip_style(report.confidence)
        self.confidence_chip.setText(conf_text)
        self.confidence_chip.setStyleSheet(conf_style)
        self.confidence_chip.setVisible(True)

        # 2. Update provider and badges
        prov = report.metadata.provider
        mod = report.metadata.model
        self.provider_label.setText(f"Provider: {prov} ({mod})")
        self.badge_widget.update_provider(prov)

        if report.is_fallback:
            fb_text, fb_style = get_fallback_badge_style(report.fallback_reason)
            self.fallback_badge.setText(fb_text)
            self.fallback_badge.setStyleSheet(fb_style)
            tooltip = "Local rules-only fallback report"
            if report.fallback_reason:
                tooltip += f": {report.fallback_reason}"
            self.fallback_badge.setToolTip(tooltip)
            self.fallback_badge.setVisible(True)
        else:
            self.fallback_badge.setVisible(False)

        # 3. Update summary
        self.summary_label.setText(report.summary)

        # 4. Rebuild detail section cards
        self._rebuild_sections(report)

    def _rebuild_sections(self, report: Report) -> None:
        """Populate facts, hypotheses, actions, explanations cards."""
        # Clear previous widgets in sections layout
        while self.sections_layout.count() > 0:
            layout_item = self.sections_layout.takeAt(0)
            if layout_item is not None:
                widget = layout_item.widget()
                if widget is not None:
                    widget.deleteLater()

        # Observed Facts Card
        if report.observed_facts:
            facts_card = self._create_card("Observed Facts (Grounded Findings)")
            facts_layout = facts_card.layout()
            if isinstance(facts_layout, QVBoxLayout):
                for fact in report.observed_facts:
                    facts_layout.addLayout(self._build_fact_item(fact))
            self.sections_layout.addWidget(facts_card)

        # Hypotheses Card
        if report.hypotheses:
            hypo_card = self._create_card("Investigative Hypotheses")
            hypo_layout = hypo_card.layout()
            if isinstance(hypo_layout, QVBoxLayout):
                for hypo in report.hypotheses:
                    hypo_layout.addLayout(self._build_hypothesis_item(hypo))
            self.sections_layout.addWidget(hypo_card)

        # Benign Explanations Card
        if report.benign_explanations:
            benign_card = self._create_card("Benign Explanations")
            benign_layout = benign_card.layout()
            if isinstance(benign_layout, QVBoxLayout):
                for exp in report.benign_explanations:
                    lbl = QLabel(f"• {exp}")
                    lbl.setWordWrap(True)
                    lbl.setStyleSheet(f"color: {COLORS.text_secondary};")
                    benign_layout.addWidget(lbl)
            self.sections_layout.addWidget(benign_card)

        # Missing Evidence Card
        if report.missing_evidence:
            missing_card = self._create_card("Missing or Unavailable Evidence")
            missing_layout = missing_card.layout()
            if isinstance(missing_layout, QVBoxLayout):
                for item in report.missing_evidence:
                    lbl = QLabel(f"• {item}")
                    lbl.setWordWrap(True)
                    lbl.setStyleSheet(f"color: {COLORS.warning_text};")
                    missing_layout.addWidget(lbl)
            self.sections_layout.addWidget(missing_card)

        # Uncertainty Notes Card
        if report.uncertainty_notes:
            unc_card = self._create_card("Uncertainty Notes & Caveats")
            unc_layout = unc_card.layout()
            if isinstance(unc_layout, QVBoxLayout):
                lbl = QLabel(report.uncertainty_notes)
                lbl.setWordWrap(True)
                lbl.setStyleSheet(f"color: {COLORS.text_secondary};")
                unc_layout.addWidget(lbl)
            self.sections_layout.addWidget(unc_card)

        # Recommended Actions Card
        if report.recommended_actions:
            actions_card = self._create_card("Recommended Actions (Policy Gated)")
            actions_layout = actions_card.layout()
            if isinstance(actions_layout, QVBoxLayout):
                for action_rec in report.recommended_actions:
                    actions_layout.addWidget(self._build_action_card(action_rec))
            self.sections_layout.addWidget(actions_card)

        self.sections_layout.addStretch()

    def _create_card(self, title: str) -> QFrame:
        """Helper to create a styled card frame with title."""
        card = QFrame()
        card.setObjectName("card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(SPACING.md, SPACING.md, SPACING.md, SPACING.md)
        layout.setSpacing(SPACING.sm)

        t_lbl = QLabel(title)
        t_lbl.setObjectName("section_title")
        layout.addWidget(t_lbl)
        return card

    def _build_fact_item(self, fact: ObservedFact) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(SPACING.sm)

        text_lbl = QLabel(f"• {fact.text}")
        text_lbl.setWordWrap(True)
        text_lbl.setStyleSheet(f"color: {COLORS.text_primary};")
        row.addWidget(text_lbl, stretch=1)

        # Citations
        citations_layout = QHBoxLayout()
        citations_layout.setSpacing(SPACING.xs)
        for ev_id in fact.evidence_ids:
            chip = CitationButton(ev_id)
            chip.clicked.connect(
                lambda _checked=False, cid=ev_id: self.citation_clicked.emit(cid)
            )
            citations_layout.addWidget(chip)
        row.addLayout(citations_layout)

        return row

    def _build_hypothesis_item(self, hypo: Hypothesis) -> QVBoxLayout:
        box = QVBoxLayout()
        box.setSpacing(SPACING.xs)

        top_row = QHBoxLayout()
        top_row.setSpacing(SPACING.sm)

        text_lbl = QLabel(f"• {hypo.text}")
        text_lbl.setWordWrap(True)
        text_lbl.setStyleSheet(f"color: {COLORS.text_primary}; font-weight: 500;")
        top_row.addWidget(text_lbl, stretch=1)

        # Likelihood chip
        lh = hypo.likelihood.lower()
        lh_chip = QLabel(f"LIKELIHOOD: {hypo.likelihood.upper()}")
        if lh == "high":
            lh_style = (
                f"background-color: {COLORS.risk_high_bg}; "
                f"color: {COLORS.risk_high_text}; border: 1px solid "
                f"{COLORS.risk_high_border};"
            )
        elif lh == "medium":
            lh_style = (
                f"background-color: {COLORS.risk_review_bg}; "
                f"color: {COLORS.risk_review_text}; border: 1px solid "
                f"{COLORS.risk_review_border};"
            )
        else:
            lh_style = (
                f"background-color: {COLORS.risk_low_bg}; "
                f"color: {COLORS.risk_low_text}; border: 1px solid "
                f"{COLORS.risk_low_border};"
            )
        lh_chip.setStyleSheet(
            f"{lh_style} font-weight: 700; font-size: 10px; "
            f"padding: 2px 6px; border-radius: {RADII.pill}px;"
        )
        top_row.addWidget(lh_chip)

        box.addLayout(top_row)

        if hypo.evidence_ids:
            cit_row = QHBoxLayout()
            cit_row.setSpacing(SPACING.xs)
            cit_label = QLabel("Citations:")
            cit_label.setStyleSheet(f"color: {COLORS.text_muted}; font-size: 11px;")
            cit_row.addWidget(cit_label)
            for ev_id in hypo.evidence_ids:
                chip = CitationButton(ev_id)
                chip.clicked.connect(
                    lambda _checked=False, cid=ev_id: self.citation_clicked.emit(cid)
                )
                cit_row.addWidget(chip)
            cit_row.addStretch()
            box.addLayout(cit_row)

        return box

    def _build_action_card(self, rec: RecommendedAction) -> QFrame:
        card = QFrame()
        card.setObjectName("card_subtle")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(SPACING.sm, SPACING.sm, SPACING.sm, SPACING.sm)
        layout.setSpacing(SPACING.xs)

        top_row = QHBoxLayout()
        act_name = rec.action_id.replace("_", " ").upper()
        act_title = QLabel(act_name)
        act_title.setStyleSheet(
            f"color: {COLORS.accent_primary}; font-weight: 700; font-size: 13px;"
        )
        top_row.addWidget(act_title)

        # Policy validation check
        proposed = ProposedAction(
            action_type=rec.action_id,
            reason=rec.reason,
            evidence_ids=rec.evidence_ids,
        )
        decision = validate_proposed_action(proposed)

        verdict_chip = QLabel()
        if decision.allowed:
            verdict_chip.setText("POLICY ALLOWED")
            verdict_chip.setStyleSheet(
                f"background-color: {COLORS.risk_low_bg}; "
                f"color: {COLORS.risk_low_text}; font-weight: 700; font-size: 10px; "
                f"padding: 2px 6px; border-radius: {RADII.pill}px;"
            )
        else:
            verdict_chip.setText("BLOCKED BY POLICY")
            verdict_chip.setStyleSheet(
                f"background-color: {COLORS.risk_high_bg}; "
                f"color: {COLORS.risk_high_text}; font-weight: 700; font-size: 10px; "
                f"padding: 2px 6px; border-radius: {RADII.pill}px;"
            )
        top_row.addWidget(verdict_chip)

        top_row.addStretch()

        # Preview & Approve Button
        if decision.allowed:
            preview_btn = QPushButton("Preview & Consent")
            preview_btn.setObjectName("preview_action_btn")
            preview_btn.setProperty("primary", "true")
            preview_btn.clicked.connect(
                lambda _checked=False, act=proposed: self._open_action_dialog(act)
            )
            top_row.addWidget(preview_btn)

        layout.addLayout(top_row)

        # Reason
        reason_lbl = QLabel(f"Rationale: {rec.reason}")
        reason_lbl.setWordWrap(True)
        reason_lbl.setStyleSheet(f"color: {COLORS.text_secondary};")
        layout.addWidget(reason_lbl)

        # Citations
        if rec.evidence_ids:
            cit_row = QHBoxLayout()
            cit_row.setSpacing(SPACING.xs)
            cit_label = QLabel("Citations:")
            cit_label.setStyleSheet(f"color: {COLORS.text_muted}; font-size: 11px;")
            cit_row.addWidget(cit_label)
            for ev_id in rec.evidence_ids:
                chip = CitationButton(ev_id)
                chip.clicked.connect(
                    lambda _checked=False, cid=ev_id: self.citation_clicked.emit(cid)
                )
                cit_row.addWidget(chip)
            cit_row.addStretch()
            layout.addLayout(cit_row)

        return card

    def _open_action_dialog(self, action: ProposedAction) -> None:
        """Open ActionPreviewDialog for dry-run inspection and consent."""
        self.action_preview_requested.emit(action)
        dialog = ActionPreviewDialog(
            action=action,
            hooks=self._hooks,
            parent=self.window(),
        )
        dialog.exec()
