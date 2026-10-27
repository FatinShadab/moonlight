"""Review interface widget displaying reports, citations, and model badges."""

from __future__ import annotations

from typing import Any

from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from moonlight.reasoning.models import Report
from moonlight.ui.badge import ProviderBadgeWidget


class ReportReviewWidget(QWidget):
    """Review panel displaying an investigation report with model/provider badges."""

    def __init__(self, report: Report | None = None, parent: Any = None) -> None:
        super().__init__(parent)
        self.setObjectName("report_review_widget")

        layout = QVBoxLayout(self)

        # Header with risk tier, provider info, and placeholder badge
        header_layout = QHBoxLayout()
        self.risk_label = QLabel()
        self.risk_label.setObjectName("risk_label")
        header_layout.addWidget(self.risk_label)

        self.provider_label = QLabel()
        self.provider_label.setObjectName("provider_label")
        header_layout.addWidget(self.provider_label)

        self.badge_widget = ProviderBadgeWidget()
        header_layout.addWidget(self.badge_widget)
        header_layout.addStretch()

        layout.addLayout(header_layout)

        # Summary text
        self.summary_label = QLabel()
        self.summary_label.setObjectName("summary_label")
        self.summary_label.setWordWrap(True)
        layout.addWidget(self.summary_label)

        if report is not None:
            self.set_report(report)

    def set_report(self, report: Report) -> None:
        """Bind and display a Report model."""
        self.risk_label.setText(
            f"Risk: {report.risk_tier.upper()} ({report.confidence:.0%})"
        )
        prov = report.metadata.provider
        mod = report.metadata.model
        self.provider_label.setText(f"Provider: {prov} ({mod})")
        self.badge_widget.update_provider(prov)
        self.summary_label.setText(report.summary)
