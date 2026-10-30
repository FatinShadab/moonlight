"""Central content views for Moonlight review interface.

Views:
- ProcessesViewWidget: process evidence table with citation navigation and search.
- StorageViewWidget: storage classification table with citation navigation and search.
- SentToModelWidget: real minimized JSON wire payload and redaction audit log.
- PolicyLogWidget: audit records of validation, preview, and execution decisions.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from moonlight.core.evidence import EvidenceBundle
from moonlight.minimizer.models import MinimizationResult
from moonlight.policy.audit import AuditRecord
from moonlight.ui.theme import COLORS, RADII, SPACING


def _format_size(num_bytes: int | None) -> str:
    if num_bytes is None:
        return "N/A"
    if num_bytes < 1024:
        return f"{num_bytes} B"
    elif num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024.0:.1f} KB"
    elif num_bytes < 1024 * 1024 * 1024:
        return f"{num_bytes / (1024.0 * 1024.0):.1f} MB"
    else:
        return f"{num_bytes / (1024.0 * 1024.0 * 1024.0):.2f} GB"


class ProcessesViewWidget(QWidget):
    """Processes evidence table with citation selection and text filtering."""

    citation_selected = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("processes_view_widget")
        self._bundles: list[EvidenceBundle] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACING.md, SPACING.md, SPACING.md, SPACING.md)
        layout.setSpacing(SPACING.sm)

        # Header card
        header_card = QFrame()
        header_card.setObjectName("card")
        h_layout = QHBoxLayout(header_card)
        h_layout.setContentsMargins(SPACING.md, SPACING.sm, SPACING.md, SPACING.sm)

        title_box = QVBoxLayout()
        title_lbl = QLabel("Process Evidence & Investigation Inventory")
        title_lbl.setObjectName("header_title")
        sub_lbl = QLabel(
            "Read-only observations gathered from process inspection and synthetic "
            "scenarios. Each item carries a deterministic citation ID."
        )
        sub_lbl.setStyleSheet(f"color: {COLORS.text_secondary}; font-size: 12px;")
        title_box.addWidget(title_lbl)
        title_box.addWidget(sub_lbl)
        h_layout.addLayout(title_box)

        h_layout.addStretch()

        # Search filter
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter processes or citations...")
        self.search_input.setFixedWidth(260)
        self.search_input.textChanged.connect(self._apply_filter)
        h_layout.addWidget(self.search_input)

        layout.addWidget(header_card)

        # Splitter: Table on top/left, Details card on bottom/right
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Process Items Table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(
            [
                "Citation ID",
                "Subject ID",
                "Evidence Kind",
                "Availability",
                "Value / Summary",
                "Severity",
            ]
        )
        self.table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        self.table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.ResizeToContents
        )
        self.table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.ResizeToContents
        )
        self.table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.Stretch
        )
        self.table.horizontalHeader().setSectionResizeMode(
            5, QHeaderView.ResizeMode.ResizeToContents
        )
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.itemSelectionChanged.connect(self._on_row_selected)
        splitter.addWidget(self.table)

        # Details Panel
        self.details_card = QFrame()
        self.details_card.setObjectName("card")
        self.details_layout = QVBoxLayout(self.details_card)
        self.details_layout.setContentsMargins(
            SPACING.md, SPACING.sm, SPACING.md, SPACING.sm
        )

        self.details_title = QLabel("Select an evidence item to view raw data")
        self.details_title.setStyleSheet(
            f"color: {COLORS.text_muted}; font-weight: 600;"
        )
        self.details_layout.addWidget(self.details_title)

        self.details_text = QPlainTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setFont(QFont("Consolas", 10))
        self.details_layout.addWidget(self.details_text)

        splitter.addWidget(self.details_card)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)

        layout.addWidget(splitter)

    def set_bundles(self, bundles: Sequence[EvidenceBundle]) -> None:
        """Populate the table with evidence items from bundles."""
        self._bundles = list(bundles)
        self.table.setRowCount(0)

        row_idx = 0
        for bundle in bundles:
            for item in bundle.items:
                self.table.insertRow(row_idx)

                id_item = QTableWidgetItem(item.id)
                id_item.setForeground(QColor(COLORS.accent_primary))
                id_item.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
                self.table.setItem(row_idx, 0, id_item)

                subj_item = QTableWidgetItem(bundle.subject_id)
                self.table.setItem(row_idx, 1, subj_item)

                kind_item = QTableWidgetItem(str(item.kind.value))
                self.table.setItem(row_idx, 2, kind_item)

                avail_item = QTableWidgetItem(str(item.availability))
                self.table.setItem(row_idx, 3, avail_item)

                val_str = (
                    json.dumps(item.value, default=str)
                    if item.value is not None
                    else f"({item.availability})"
                )
                val_item = QTableWidgetItem(val_str)
                self.table.setItem(row_idx, 4, val_item)

                sev_str = str(item.severity_hint.value) if item.severity_hint else "-"
                sev_item = QTableWidgetItem(sev_str)
                self.table.setItem(row_idx, 5, sev_item)

                row_idx += 1

    def highlight_evidence_id(self, citation_id: str) -> bool:
        """Select, highlight, and scroll to the row matching citation_id."""
        clean = citation_id.strip()
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item and item.text() == clean:
                self.table.selectRow(row)
                self.table.scrollToItem(item)
                return True
        return False

    def _apply_filter(self, text: str) -> None:
        query = text.strip().lower()
        for row in range(self.table.rowCount()):
            match = False
            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                if item and query in item.text().lower():
                    match = True
                    break
            self.table.setRowHidden(row, not match)

    def _on_row_selected(self) -> None:
        selected = self.table.selectedItems()
        if not selected:
            return
        row = selected[0].row()
        cid = self.table.item(row, 0)
        kind = self.table.item(row, 2)
        val = self.table.item(row, 4)

        if cid and kind and val:
            self.details_title.setText(f"Evidence Item: {cid.text()} ({kind.text()})")
            self.details_title.setStyleSheet(
                f"color: {COLORS.accent_primary}; font-weight: 700;"
            )
            self.details_text.setPlainText(val.text())
            self.citation_selected.emit(cid.text())


class StorageViewWidget(QWidget):
    """Storage evidence and classification table with search and citation selection."""

    citation_selected = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("storage_view_widget")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACING.md, SPACING.md, SPACING.md, SPACING.md)
        layout.setSpacing(SPACING.sm)

        # Header card
        header_card = QFrame()
        header_card.setObjectName("card")
        h_layout = QHBoxLayout(header_card)
        h_layout.setContentsMargins(SPACING.md, SPACING.sm, SPACING.md, SPACING.sm)

        title_box = QVBoxLayout()
        title_lbl = QLabel("Storage Investigation & Classification")
        title_lbl.setObjectName("header_title")
        sub_lbl = QLabel(
            "Evaluated filesystem targets, sizes, and policy safety categories: "
            "clearly_safe, review_first, and do_not_touch."
        )
        sub_lbl.setStyleSheet(f"color: {COLORS.text_secondary}; font-size: 12px;")
        title_box.addWidget(title_lbl)
        title_box.addWidget(sub_lbl)
        h_layout.addLayout(title_box)

        h_layout.addStretch()

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter storage paths or citations...")
        self.search_input.setFixedWidth(260)
        self.search_input.textChanged.connect(self._apply_filter)
        h_layout.addWidget(self.search_input)

        layout.addWidget(header_card)

        # Storage Table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(
            [
                "Citation ID",
                "Target Path",
                "Policy Classification",
                "Size",
                "Finding Details",
            ]
        )
        self.table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self.table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.ResizeToContents
        )
        self.table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.ResizeToContents
        )
        self.table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.Stretch
        )
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        layout.addWidget(self.table)

    def set_storage_items(self, items: Sequence[dict[str, Any]]) -> None:
        """Populate storage items."""
        self.table.setRowCount(0)
        for row_idx, item in enumerate(items):
            self.table.insertRow(row_idx)

            cid = item.get("citation_id", f"ev-storage-{row_idx + 1}")
            id_item = QTableWidgetItem(cid)
            id_item.setForeground(QColor(COLORS.accent_primary))
            id_item.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
            self.table.setItem(row_idx, 0, id_item)

            path_item = QTableWidgetItem(item.get("path", ""))
            self.table.setItem(row_idx, 1, path_item)

            cat = item.get("category", "unknown")
            cat_item = QTableWidgetItem(cat.upper())
            if cat == "clearly_safe":
                cat_item.setForeground(QColor(COLORS.risk_low_text))
            elif cat == "review_first":
                cat_item.setForeground(QColor(COLORS.risk_review_text))
            elif cat == "do_not_touch":
                cat_item.setForeground(QColor(COLORS.risk_high_text))
            cat_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            self.table.setItem(row_idx, 2, cat_item)

            size_str = _format_size(item.get("size_bytes"))
            size_item = QTableWidgetItem(size_str)
            self.table.setItem(row_idx, 3, size_item)

            details_item = QTableWidgetItem(item.get("details", ""))
            self.table.setItem(row_idx, 4, details_item)

    def highlight_evidence_id(self, citation_id: str) -> bool:
        """Select, highlight, and scroll to the row matching citation_id."""
        clean = citation_id.strip()
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item and item.text() == clean:
                self.table.selectRow(row)
                self.table.scrollToItem(item)
                return True
        return False

    def _apply_filter(self, text: str) -> None:
        query = text.strip().lower()
        for row in range(self.table.rowCount()):
            match = False
            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                if item and query in item.text().lower():
                    match = True
                    break
            self.table.setRowHidden(row, not match)


class SentToModelWidget(QWidget):
    """Inspection tab for exact minimized JSON wire payload and redaction log."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("sent_to_model_widget")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACING.md, SPACING.md, SPACING.md, SPACING.md)
        layout.setSpacing(SPACING.sm)

        # Header card
        header_card = QFrame()
        header_card.setObjectName("card")
        h_layout = QHBoxLayout(header_card)
        h_layout.setContentsMargins(SPACING.md, SPACING.sm, SPACING.md, SPACING.sm)

        title_box = QVBoxLayout()
        title_lbl = QLabel("Sent to the Model (Privacy Minimized Wire Payload)")
        title_lbl.setObjectName("header_title")
        sub_lbl = QLabel(
            "Verifiable dry-run preview: exactly what enters model prompts. "
            "Private usernames, hostnames, command secrets, and paths are redacted."
        )
        sub_lbl.setStyleSheet(f"color: {COLORS.text_secondary}; font-size: 12px;")
        title_box.addWidget(title_lbl)
        title_box.addWidget(sub_lbl)
        h_layout.addLayout(title_box)

        h_layout.addStretch()

        # Stat chips
        self.size_chip = QLabel("0 Bytes")
        self.size_chip.setStyleSheet(
            f"background-color: {COLORS.bg_surface_alt}; color: {COLORS.text_primary}; "
            f"border: 1px solid {COLORS.border_default}; font-weight: 600; "
            f"padding: 4px 10px; border-radius: {RADII.pill}px;"
        )
        h_layout.addWidget(self.size_chip)

        self.redactions_chip = QLabel("0 Redactions")
        self.redactions_chip.setStyleSheet(
            f"background-color: {COLORS.accent_surface}; "
            f"color: {COLORS.accent_primary}; "
            f"border: 1px solid {COLORS.accent_border}; "
            f"font-weight: 600; padding: 4px 10px; border-radius: {RADII.pill}px;"
        )
        h_layout.addWidget(self.redactions_chip)

        layout.addWidget(header_card)

        # Splitter: Minimized Payload JSON on top/left, Redaction Log on bottom/right
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Wire Payload Card
        payload_card = QFrame()
        payload_card.setObjectName("card")
        p_layout = QVBoxLayout(payload_card)
        p_layout.setContentsMargins(SPACING.md, SPACING.sm, SPACING.md, SPACING.sm)

        p_header = QHBoxLayout()
        p_title = QLabel("Wire Payload JSON")
        p_title.setObjectName("section_title")
        p_header.addWidget(p_title)
        p_header.addStretch()

        copy_btn = QPushButton("Copy JSON")
        copy_btn.setStyleSheet("font-size: 11px; padding: 2px 8px;")
        copy_btn.clicked.connect(self._copy_payload)
        p_header.addWidget(copy_btn)
        p_layout.addLayout(p_header)

        self.payload_view = QPlainTextEdit()
        self.payload_view.setReadOnly(True)
        self.payload_view.setFont(QFont("Consolas", 10))
        p_layout.addWidget(self.payload_view)
        splitter.addWidget(payload_card)

        # Redaction Log Card
        redaction_card = QFrame()
        redaction_card.setObjectName("card")
        r_layout = QVBoxLayout(redaction_card)
        r_layout.setContentsMargins(SPACING.md, SPACING.sm, SPACING.md, SPACING.sm)

        r_title = QLabel("Local Redaction Audit Log (Withheld from Model)")
        r_title.setObjectName("section_title")
        r_layout.addWidget(r_title)

        self.redaction_table = QTableWidget()
        self.redaction_table.setColumnCount(4)
        self.redaction_table.setHorizontalHeaderLabels(
            [
                "Location",
                "Operation",
                "Category",
                "Placeholder Assigned",
            ]
        )
        self.redaction_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.redaction_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        self.redaction_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.ResizeToContents
        )
        self.redaction_table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.Stretch
        )
        r_layout.addWidget(self.redaction_table)
        splitter.addWidget(redaction_card)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter)

    def set_result(self, result: MinimizationResult) -> None:
        """Bind and render minimization wire payload and redaction log."""
        # Payload JSON
        try:
            parsed = json.loads(result.payload_json)
            formatted = json.dumps(parsed, indent=2)
        except Exception:
            formatted = result.payload_json

        self.payload_view.setPlainText(formatted)

        # Update stats
        byte_count = len(result.payload_bytes())
        self.size_chip.setText(f"{byte_count:,} Bytes Wire Size")
        self.redactions_chip.setText(f"{len(result.redaction_log)} Redactions")

        # Redaction table
        self.redaction_table.setRowCount(0)
        for row_idx, event in enumerate(result.redaction_log):
            self.redaction_table.insertRow(row_idx)

            loc_item = QTableWidgetItem(event.location)
            self.redaction_table.setItem(row_idx, 0, loc_item)

            op_item = QTableWidgetItem(event.operation.upper())
            if event.operation == "replace":
                op_item.setForeground(QColor(COLORS.accent_primary))
            elif event.operation == "omit":
                op_item.setForeground(QColor(COLORS.risk_review_text))
            elif event.operation == "truncate":
                op_item.setForeground(QColor(COLORS.warning_text))
            op_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            self.redaction_table.setItem(row_idx, 1, op_item)

            cat_item = QTableWidgetItem(event.category)
            self.redaction_table.setItem(row_idx, 2, cat_item)

            ph_item = QTableWidgetItem(event.placeholder or "-")
            ph_item.setForeground(QColor(COLORS.text_secondary))
            self.redaction_table.setItem(row_idx, 3, ph_item)

    def _copy_payload(self) -> None:
        text = self.payload_view.toPlainText()
        if text:
            from PySide6.QtWidgets import QApplication

            clipboard = QApplication.clipboard()
            if clipboard:
                clipboard.setText(text)


class PolicyLogWidget(QWidget):
    """Audit log viewer displaying policy validation, preview, and execution records."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("policy_log_widget")
        self._records: list[AuditRecord] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACING.md, SPACING.md, SPACING.md, SPACING.md)
        layout.setSpacing(SPACING.sm)

        # Header card
        header_card = QFrame()
        header_card.setObjectName("card")
        h_layout = QHBoxLayout(header_card)
        h_layout.setContentsMargins(SPACING.md, SPACING.sm, SPACING.md, SPACING.sm)

        title_box = QVBoxLayout()
        title_lbl = QLabel("Local Policy Audit Log")
        title_lbl.setObjectName("header_title")
        sub_lbl = QLabel(
            "Append-only local log recording every policy verification, preview, "
            "and execution decision. Actions must strictly pass policy boundaries."
        )
        sub_lbl.setStyleSheet(f"color: {COLORS.text_secondary}; font-size: 12px;")
        title_box.addWidget(title_lbl)
        title_box.addWidget(sub_lbl)
        h_layout.addLayout(title_box)

        h_layout.addStretch()

        self.count_chip = QLabel("0 Audit Records")
        self.count_chip.setStyleSheet(
            f"background-color: {COLORS.bg_surface_alt}; color: {COLORS.text_primary}; "
            f"border: 1px solid {COLORS.border_default}; font-weight: 600; "
            f"padding: 4px 10px; border-radius: {RADII.pill}px;"
        )
        h_layout.addWidget(self.count_chip)

        layout.addWidget(header_card)

        # Audit Table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(
            [
                "Timestamp (UTC)",
                "Event Type",
                "Action Type",
                "Verdict",
                "Target Subject / Path",
                "Details / Reason",
            ]
        )
        self.table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        self.table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.ResizeToContents
        )
        self.table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.ResizeToContents
        )
        self.table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.Stretch
        )
        self.table.horizontalHeader().setSectionResizeMode(
            5, QHeaderView.ResizeMode.Stretch
        )
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        layout.addWidget(self.table)

    def set_records(self, records: Sequence[AuditRecord]) -> None:
        """Bind audit records into table."""
        self._records = list(records)
        self.table.setRowCount(0)

        for row_idx, rec in enumerate(records):
            self.table.insertRow(row_idx)

            time_str = rec.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            time_item = QTableWidgetItem(time_str)
            self.table.setItem(row_idx, 0, time_item)

            ev_item = QTableWidgetItem(rec.event_type.upper())
            self.table.setItem(row_idx, 1, ev_item)

            act_str = rec.action_type or "-"
            act_item = QTableWidgetItem(act_str.replace("_", " ").upper())
            self.table.setItem(row_idx, 2, act_item)

            status_str = rec.status.upper()
            status_item = QTableWidgetItem(status_str)
            if rec.allowed:
                status_item.setForeground(QColor(COLORS.risk_low_text))
            else:
                status_item.setForeground(QColor(COLORS.risk_high_text))
            status_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            self.table.setItem(row_idx, 3, status_item)

            target_item = QTableWidgetItem(rec.target or "-")
            self.table.setItem(row_idx, 4, target_item)

            reason_str = rec.reason or (
                json.dumps(rec.details) if rec.details else "OK"
            )
            reason_item = QTableWidgetItem(reason_str)
            self.table.setItem(row_idx, 5, reason_item)

        self.count_chip.setText(f"{len(records)} Audit Records")
