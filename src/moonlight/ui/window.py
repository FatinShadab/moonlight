"""Main review window for Moonlight investigation and remediation interface.

Features:
- Left navigation rail: Processes, Storage, Reports, Sent to model, Policy log, World.
- Extensible structure for optional isometric World View device map.
- Top bar with Replay / Live toggle, provider badge, scenario selector, run trigger.
- Central stacked views: Processes, Storage, Reports, SentToModel, PolicyLog, WorldView.
- Right side panel with Activity timeline and Approvals queue.
- Interactive cross-linking: clicking citations jumps to matching evidence rows.
- Consent dialog flow: confirmation token held in memory, policy-gated execution.
- Background worker execution preventing UI freezes.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from moonlight.eval.scenarios import load_all_scenarios
from moonlight.policy.actions import ExecutionResult, ProposedAction
from moonlight.policy.audit import PolicyAuditLogger
from moonlight.ui.badge import ProviderBadgeWidget
from moonlight.ui.controller import (
    InvestigationController,
    InvestigationRunResult,
)
from moonlight.ui.dialogs import ActionPreviewDialog, LiveProviderWarningDialog
from moonlight.ui.events import EventBus, get_event_bus
from moonlight.ui.icons import get_icon
from moonlight.ui.panels import RightSidePanelWidget
from moonlight.ui.review import ReportReviewWidget
from moonlight.ui.theme import COLORS, SPACING, build_qss
from moonlight.ui.views import (
    PolicyLogWidget,
    ProcessesViewWidget,
    SentToModelWidget,
    StorageViewWidget,
)
from moonlight.ui.world_view import WorldViewWidget


class NavButton(QPushButton):
    """Button item in left navigation rail."""

    def __init__(
        self,
        text: str,
        icon_name: str,
        index: int,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(text, parent)
        self.setObjectName("nav_button")
        self.view_index = index
        self.setIcon(get_icon(icon_name))
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)


class MoonlightMainWindow(QMainWindow):
    """Primary Moonlight desktop application window."""

    def __init__(
        self,
        event_bus: EventBus | None = None,
        audit_logger: PolicyAuditLogger | None = None,
        hooks: Mapping[str, Callable[..., Any]] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("moonlight_main_window")
        self.setWindowTitle("Moonlight - Local-First Process & Storage Investigator")
        self.setMinimumSize(1200, 750)
        self.resize(1340, 840)

        self.bus = event_bus if event_bus is not None else get_event_bus()
        self.audit_logger = audit_logger or PolicyAuditLogger()
        self._hooks = dict(hooks) if hooks else {}
        self._scenarios_map: dict[str, Any] = {}

        # Controller managing async execution
        self.controller = InvestigationController(event_bus=self.bus, parent=self)
        self.controller.investigation_finished.connect(self._on_investigation_finished)
        self.controller.status_changed.connect(self._on_status_changed)

        # Apply dark theme QSS
        self.setStyleSheet(build_qss())

        self._init_layout()
        self._load_replay_scenarios()

    def _init_layout(self) -> None:
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        root_layout = QVBoxLayout(central_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # 1. Top Bar
        self.top_bar = self._create_top_bar()
        root_layout.addWidget(self.top_bar)

        # 2. Main Body: Left Rail + Central Content Stack + Right Side Panel
        body_layout = QHBoxLayout()
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        # Left Navigation Rail
        self.nav_rail = self._create_nav_rail()
        body_layout.addWidget(self.nav_rail)

        # Central Stacked Views
        self.stacked_views = QStackedWidget()
        self.stacked_views.setObjectName("central_stack")

        # View 0: Processes
        self.processes_view = ProcessesViewWidget()
        self.processes_view.citation_selected.connect(self._on_citation_navigated)
        self.stacked_views.addWidget(self.processes_view)

        # View 1: Storage
        self.storage_view = StorageViewWidget()
        self.storage_view.citation_selected.connect(self._on_citation_navigated)
        self.stacked_views.addWidget(self.storage_view)

        # View 2: Reports (Extending ReportReviewWidget)
        self.report_view = ReportReviewWidget(hooks=self._hooks)
        self.report_view.citation_clicked.connect(self._on_citation_clicked)
        self.report_view.action_preview_requested.connect(self._on_action_requested)
        self.stacked_views.addWidget(self.report_view)

        # View 3: Sent to the model
        self.sent_to_model_view = SentToModelWidget()
        self.stacked_views.addWidget(self.sent_to_model_view)

        # View 4: Policy log
        self.policy_log_view = PolicyLogWidget()
        self.stacked_views.addWidget(self.policy_log_view)

        # View 5: World View (Isometric Device Map)
        self.world_view = WorldViewWidget(event_bus=self.bus, parent=self)
        self.world_view.citation_clicked.connect(self._on_citation_clicked)
        self.stacked_views.addWidget(self.world_view)

        body_layout.addWidget(self.stacked_views, stretch=1)

        # Right Side Panel (Activity Timeline + Approvals)
        self.side_panel = RightSidePanelWidget(
            event_bus=self.bus,
            hooks=self._hooks,
            parent=self,
        )
        self.side_panel.citation_clicked.connect(self._on_citation_clicked)
        self.side_panel.action_executed.connect(self._on_action_executed)
        body_layout.addWidget(self.side_panel)

        root_layout.addLayout(body_layout)

        # Set default active view to Reports (View 2)
        self._select_nav_view(2)

    def _create_top_bar(self) -> QFrame:
        bar = QFrame()
        bar.setObjectName("top_bar")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(SPACING.md, SPACING.sm, SPACING.md, SPACING.sm)
        layout.setSpacing(SPACING.md)

        # App branding title
        brand_lbl = QLabel("MOONLIGHT")
        brand_lbl.setObjectName("app_brand")
        brand_lbl.setStyleSheet(
            f"color: {COLORS.accent_primary}; font-weight: 800; font-size: 15px; "
            f"letter-spacing: 2px;"
        )
        layout.addWidget(brand_lbl)

        sep1 = QLabel("|")
        sep1.setStyleSheet(f"color: {COLORS.border_subtle}; font-weight: 300;")
        layout.addWidget(sep1)

        # Mode toggle: Replay vs Live
        mode_box = QHBoxLayout()
        mode_box.setSpacing(2)
        self.btn_replay = QPushButton("Replay")
        self.btn_replay.setObjectName("btn_replay")
        self.btn_replay.setCheckable(True)
        self.btn_replay.setChecked(True)
        self.btn_replay.clicked.connect(lambda: self._set_mode("replay"))
        mode_box.addWidget(self.btn_replay)

        self.btn_live = QPushButton("Live")
        self.btn_live.setObjectName("btn_live")
        self.btn_live.setCheckable(True)
        self.btn_live.setChecked(False)
        self.btn_live.clicked.connect(lambda: self._set_mode("live"))
        mode_box.addWidget(self.btn_live)

        layout.addLayout(mode_box)

        # Scenario Selector (Active in Replay Mode)
        self.scenario_combo = QComboBox()
        self.scenario_combo.setObjectName("scenario_selector")
        self.scenario_combo.setMinimumWidth(240)
        self.scenario_combo.currentIndexChanged.connect(self._on_scenario_changed)
        layout.addWidget(self.scenario_combo)

        # Provider Selector
        prov_lbl = QLabel("Provider:")
        prov_lbl.setStyleSheet(f"color: {COLORS.text_muted}; font-size: 11px;")
        layout.addWidget(prov_lbl)

        self.provider_combo = QComboBox()
        self.provider_combo.setObjectName("provider_selector")
        self.provider_combo.addItems(["mock", "ollama-cloud", "meta"])
        self.provider_combo.currentTextChanged.connect(self._on_provider_changed)
        layout.addWidget(self.provider_combo)

        # Provider Badge
        self.provider_badge = ProviderBadgeWidget(provider="mock")
        layout.addWidget(self.provider_badge)

        layout.addStretch()

        # Status text
        self.status_lbl = QLabel("Ready")
        self.status_lbl.setObjectName("status_indicator")
        self.status_lbl.setStyleSheet(
            f"color: {COLORS.text_muted}; font-size: 11px; font-style: italic;"
        )
        layout.addWidget(self.status_lbl)

        # Investigate / Run Button
        self.run_btn = QPushButton("Investigate")
        self.run_btn.setObjectName("run_investigation_btn")
        self.run_btn.setProperty("primary", "true")
        self.run_btn.setIcon(get_icon("refresh"))
        self.run_btn.clicked.connect(self.trigger_investigation)
        layout.addWidget(self.run_btn)

        return bar

    def _create_nav_rail(self) -> QFrame:
        rail = QFrame()
        rail.setObjectName("nav_rail")
        layout = QVBoxLayout(rail)
        layout.setContentsMargins(SPACING.sm, SPACING.md, SPACING.sm, SPACING.md)
        layout.setSpacing(SPACING.xs)

        nav_header = QLabel("INVESTIGATION")
        nav_header.setStyleSheet(
            f"font-size: 10px; font-weight: 700; color: {COLORS.text_muted}; "
            f"letter-spacing: 1px; padding: 0 10px 4px 10px;"
        )
        layout.addWidget(nav_header)

        self.nav_buttons: list[NavButton] = []

        # 5 Required Core Navigation Views
        nav_items = [
            ("Processes", "processes", 0),
            ("Storage", "storage", 1),
            ("Reports", "reports", 2),
            ("Sent to the model", "model", 3),
            ("Policy log", "shield", 4),
        ]

        for text, icon, idx in nav_items:
            btn = NavButton(text, icon, idx)
            btn.clicked.connect(lambda _c=False, i=idx: self._select_nav_view(i))
            self.nav_buttons.append(btn)
            layout.addWidget(btn)

        # Isometric World View Navigation Button
        layout.addSpacing(SPACING.md)
        world_header = QLabel("VISUALIZATION")
        world_header.setStyleSheet(
            f"font-size: 10px; font-weight: 700; color: {COLORS.text_muted}; "
            f"letter-spacing: 1px; padding: 0 10px 4px 10px;"
        )
        layout.addWidget(world_header)

        self.world_view_btn = NavButton("World Map", "world", 5)
        self.world_view_btn.setObjectName("btn_world_view")
        self.world_view_btn.clicked.connect(lambda _c=False: self._select_nav_view(5))
        layout.addWidget(self.world_view_btn)

        layout.addStretch()

        # Version stamp
        v_lbl = QLabel("Moonlight v0.1.0 (local)")
        v_lbl.setStyleSheet(
            f"color: {COLORS.text_muted}; font-size: 10px; padding: 8px;"
        )
        layout.addWidget(v_lbl)

        return rail

    def _select_nav_view(self, index: int) -> None:
        """Switch active view in central stack and update nav button selection."""
        self.stacked_views.setCurrentIndex(index)
        for btn in self.nav_buttons:
            btn.setChecked(btn.view_index == index)
        if hasattr(self, "world_view_btn"):
            self.world_view_btn.setChecked(index == 5)

    def _set_mode(self, mode: str) -> None:
        """Toggle between Replay mode and Live mode."""
        if mode == "live" and self.controller.provider_name not in ("mock", "meta"):
            # Check confirmation for cloud provider in live mode
            dlg = LiveProviderWarningDialog(
                provider_name=self.controller.provider_name, parent=self
            )
            if not dlg.exec():
                return

        self.controller.mode = mode
        self.btn_replay.setChecked(mode == "replay")
        self.btn_live.setChecked(mode == "live")
        self.scenario_combo.setEnabled(mode == "replay")
        self.status_lbl.setText(f"Mode set to {mode.upper()}")

    def _on_provider_changed(self, provider: str) -> None:
        """Handle provider selection change."""
        if self.controller.mode == "live" and provider not in ("mock", "meta"):
            dlg = LiveProviderWarningDialog(provider_name=provider, parent=self)
            if not dlg.exec():
                # Revert to mock
                idx = self.provider_combo.findText("mock")
                if idx >= 0:
                    self.provider_combo.setCurrentIndex(idx)
                return

        self.controller.provider_name = provider
        self.provider_badge.update_provider(provider)
        self.status_lbl.setText(f"Provider: {provider}")

    def _load_replay_scenarios(self) -> None:
        """Load labeled scenarios into replay dropdown."""
        try:
            scenarios = load_all_scenarios()
            self.scenario_combo.clear()
            self._scenarios_map.clear()
            for sc in scenarios:
                self._scenarios_map[sc.id] = sc
                display_text = f"{sc.id} ({getattr(sc, 'description', '')[:35]}...)"
                self.scenario_combo.addItem(display_text, sc.id)
            if scenarios:
                self.world_view.load_scenario(scenarios[0])
        except Exception:
            self.scenario_combo.addItem("default (mock)", "default")

    def _on_scenario_changed(self, index: int) -> None:
        sid = self.scenario_combo.currentData()
        if sid and str(sid) in self._scenarios_map:
            sc = self._scenarios_map[str(sid)]
            self.world_view.load_scenario(sc)

    def trigger_investigation(self) -> None:
        """Execute investigation pipeline in background worker."""
        sid: str | None = None
        if self.controller.mode == "replay":
            sid = str(self.scenario_combo.currentData() or "default")

        self.run_btn.setEnabled(False)
        self.run_btn.setText("Investigating...")
        self.controller.run_investigation(scenario_id=sid)

    def _on_status_changed(self, status: str) -> None:
        self.status_lbl.setText(status)

    def _on_investigation_finished(self, result: InvestigationRunResult) -> None:
        """Update all central views and side panels with completed findings."""
        self.run_btn.setEnabled(True)
        self.run_btn.setText("Investigate")

        # 1. Update Processes View
        self.processes_view.set_bundles(result.bundles)

        # 2. Update Storage View
        self.storage_view.set_storage_items(result.storage_items)

        # 3. Update Report Review View
        if result.report is not None:
            self.report_view.set_report(result.report)
            # Update Approvals Panel with recommended actions
            self.side_panel.approvals_widget.set_actions(
                result.report.recommended_actions,
                report=result.report,
            )

        # 4. Update Sent to the Model View
        if result.minimization_result is not None:
            self.sent_to_model_view.set_result(result.minimization_result)

        # 5. Update World View
        self.world_view.load_investigation_result(result)

        # 6. Switch to Report view by default so analyst sees synthesis
        self._select_nav_view(2)

    def _on_citation_clicked(self, citation_id: str) -> None:
        """Jump from citation click in report/activity to matching evidence row."""
        clean = citation_id.strip()
        if clean.startswith("ev-storage"):
            self._select_nav_view(1)  # Storage view
            found = self.storage_view.highlight_evidence_id(clean)
            if not found:
                self.status_lbl.setText(f"Storage citation '{clean}' not found.")
        else:
            self._select_nav_view(0)  # Processes view
            found = self.processes_view.highlight_evidence_id(clean)
            if not found:
                self.status_lbl.setText(f"Process citation '{clean}' not found.")

    def _on_citation_navigated(self, citation_id: str) -> None:
        self.status_lbl.setText(f"Focused evidence: {citation_id}")

    def _on_action_requested(self, action: ProposedAction) -> None:
        """Triggered when user clicks Preview on an action in Report."""
        dialog = ActionPreviewDialog(
            action=action,
            hooks=self._hooks,
            parent=self,
        )
        if dialog.exec():
            res = dialog.execution_result
            if res:
                self._on_action_executed(res)

    def _on_action_executed(self, result: ExecutionResult) -> None:
        """Update audit records and log action execution."""
        self.status_lbl.setText(f"Action executed: {result.message}")
        records = self.audit_logger.read_records()
        self.policy_log_view.set_records(records)
