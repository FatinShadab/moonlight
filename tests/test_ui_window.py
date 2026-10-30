"""Integration and component tests for MoonlightMainWindow and review interface.

Verifies:
- Layout and navigation rail (Processes, Storage, Reports, Sent to model, Policy log).
- Replay mode loading from fixtures with MockProvider.
- Citation click-through jumping to matching process and storage evidence rows.
- Badges: 'cloud placeholder model' for non-meta, 'rules-only fallback' for fallback.
- Investigation events published via EventBus rendered in Activity timeline.
- No UI code path executes an action without the dialog.
- Fakes used for launcher and recycle operations (never real Explorer or Recycle Bin).
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from PySide6.QtWidgets import QApplication

from moonlight.core.evidence import (
    EvidenceBundle,
    EvidenceItem,
    EvidenceKind,
    make_evidence_id,
)
from moonlight.eval.scenarios import load_process_scenarios
from moonlight.reasoning.models import (
    Hypothesis,
    ObservedFact,
    RecommendedAction,
    Report,
    ReportMetadata,
)
from moonlight.reasoning.provider import MockProvider
from moonlight.ui.badge import CLOUD_PLACEHOLDER_BADGE_TEXT
from moonlight.ui.events import EventBus, InvestigationEvent
from moonlight.ui.window import MoonlightMainWindow


@pytest.fixture(scope="session")
def qapp() -> QApplication:
    app = QApplication.instance()
    if not isinstance(app, QApplication):
        app = QApplication([])
    return app


def test_main_window_layout_and_navigation(qapp: QApplication) -> None:
    bus = EventBus()
    win = MoonlightMainWindow(event_bus=bus)
    win.show()

    # 5 Navigation buttons exist
    assert len(win.nav_buttons) == 5
    button_labels = [b.text() for b in win.nav_buttons]
    assert button_labels == [
        "Processes",
        "Storage",
        "Reports",
        "Sent to the model",
        "Policy log",
    ]

    # Future world view slot exists
    assert win.world_view_btn is not None
    assert win.world_view_btn.isEnabled() is False

    # Top bar elements exist
    assert win.btn_replay.isChecked() is True
    assert win.btn_live.isChecked() is False
    assert win.provider_badge.isVisible() is True
    assert win.provider_badge.text() == CLOUD_PLACEHOLDER_BADGE_TEXT

    # Navigating views updates stacked widget index
    win._select_nav_view(0)
    assert win.stacked_views.currentIndex() == 0

    win._select_nav_view(1)
    assert win.stacked_views.currentIndex() == 1

    win._select_nav_view(2)
    assert win.stacked_views.currentIndex() == 2

    win._select_nav_view(3)
    assert win.stacked_views.currentIndex() == 3

    win._select_nav_view(4)
    assert win.stacked_views.currentIndex() == 4

    win.close()
    win.deleteLater()
    qapp.processEvents()


def test_provider_badges_in_window(qapp: QApplication) -> None:
    bus = EventBus()
    win = MoonlightMainWindow(event_bus=bus)
    win.show()

    # Default provider is 'mock'; badge must be visible
    assert win.provider_badge.isVisible() is True
    assert win.provider_badge.text() == CLOUD_PLACEHOLDER_BADGE_TEXT

    # Switch to 'meta'; badge must be hidden
    win.provider_combo.setCurrentText("meta")
    assert win.provider_badge.isVisible() is False
    assert win.provider_badge.text() == ""

    # Switch to 'ollama-cloud'; badge must be visible
    win.provider_combo.setCurrentText("ollama-cloud")
    assert win.provider_badge.isVisible() is True
    assert win.provider_badge.text() == CLOUD_PLACEHOLDER_BADGE_TEXT

    win.close()
    win.deleteLater()
    qapp.processEvents()


def test_rules_only_fallback_badge(qapp: QApplication) -> None:
    timestamp = datetime.now(UTC)
    ev_id = make_evidence_id(
        "process", "100", "collector", EvidenceKind.EXECUTABLE_PATH
    )

    fallback_report = Report(
        summary="Fallback summary due to provider timeout",
        risk_tier="low",
        confidence=0.5,
        observed_facts=(
            ObservedFact(text="Executable path found", evidence_ids=(ev_id,)),
        ),
        metadata=ReportMetadata(
            provider="rules_only_fallback",
            model="rules_engine",
            prompt_version="1.0.0",
            timestamp=timestamp,
        ),
        is_fallback=True,
        fallback_reason="Provider timeout after 2 retries",
    )

    bus = EventBus()
    win = MoonlightMainWindow(event_bus=bus)
    win.show()
    win.report_view.set_report(fallback_report)

    assert win.report_view.fallback_badge.isVisible() is True
    assert win.report_view.fallback_badge.text() == "rules-only fallback"
    assert "Provider timeout" in win.report_view.fallback_badge.toolTip()

    win.close()
    win.deleteLater()
    qapp.processEvents()


def test_citation_clickthrough_jumps_to_processes_and_storage(
    qapp: QApplication,
) -> None:
    bus = EventBus()
    win = MoonlightMainWindow(event_bus=bus)
    win.show()

    proc_ev_id = make_evidence_id(
        "process", "proc-1", "collector", EvidenceKind.EXECUTABLE_PATH
    )
    storage_ev_id = "ev-storage-test-12345678"

    # Populate process table
    bundle = EvidenceBundle(
        subject_type="process",
        subject_id="proc-1",
        items=(
            EvidenceItem(
                id=proc_ev_id,
                source="collector",
                kind=EvidenceKind.EXECUTABLE_PATH,
                availability="observed",
                value=r"C:\Tools\analyzer.exe",
                timestamp=datetime.now(UTC),
            ),
        ),
    )
    win.processes_view.set_bundles([bundle])

    # Populate storage table
    win.storage_view.set_storage_items(
        [
            {
                "citation_id": storage_ev_id,
                "path": r"C:\Temp\cache.tmp",
                "category": "clearly_safe",
                "size_bytes": 1024,
                "details": "Cache item",
            }
        ]
    )

    # 1. Click process citation -> should jump to Processes view (index 0)
    win._select_nav_view(2)  # Start on Reports view
    win._on_citation_clicked(proc_ev_id)

    assert win.stacked_views.currentIndex() == 0  # Processes view
    selected_items = win.processes_view.table.selectedItems()
    assert len(selected_items) > 0
    assert selected_items[0].text() == proc_ev_id

    # 2. Click storage citation -> should jump to Storage view (index 1)
    win._select_nav_view(2)  # Back to Reports view
    win._on_citation_clicked(storage_ev_id)

    assert win.stacked_views.currentIndex() == 1  # Storage view
    storage_selected = win.storage_view.table.selectedItems()
    assert len(storage_selected) > 0
    assert storage_selected[0].text() == storage_ev_id

    win.close()
    win.deleteLater()
    qapp.processEvents()


def test_event_bus_updates_activity_timeline(qapp: QApplication) -> None:
    bus = EventBus()
    win = MoonlightMainWindow(event_bus=bus)
    win.show()

    initial_count = win.side_panel.activity_widget.event_count

    # Publish an event via event bus
    test_event = InvestigationEvent(
        kind="rules_evaluated",
        subject="test_proc.exe",
        message="Evaluated rules: 2 positive findings, tier REVIEW.",
        evidence_ids=("ev-1", "ev-2"),
        severity="review",
    )
    bus.publish(test_event)

    # Activity timeline must reflect new event
    assert win.side_panel.activity_widget.event_count == initial_count + 1
    assert "1 Events" in win.side_panel.activity_widget.count_label.text()

    win.close()
    win.deleteLater()
    qapp.processEvents()


def test_replay_mode_loading_populates_views(qapp: QApplication) -> None:
    bus = EventBus()
    win = MoonlightMainWindow(event_bus=bus)
    win.show()

    # Load a synthetic scenario from fixtures
    scenarios = load_process_scenarios()
    assert len(scenarios) > 0
    scenario = scenarios[0]

    # Run investigation with custom mock provider to return a valid grounded report
    ev_id = scenario.bundle.items[0].id
    mock_report = Report(
        summary="Replay investigation of synthetic scenario",
        risk_tier="low",
        confidence=0.95,
        observed_facts=(
            ObservedFact(text="Executable path verified", evidence_ids=(ev_id,)),
        ),
        hypotheses=(
            Hypothesis(
                text="Standard utility", evidence_ids=(ev_id,), likelihood="low"
            ),
        ),
        recommended_actions=(
            RecommendedAction(
                action_id="open_file_location",
                reason="Review file location",
                evidence_ids=(ev_id,),
            ),
        ),
        metadata=ReportMetadata(
            provider="mock",
            model="mock_engine",
            prompt_version="1.0.0",
            timestamp=datetime.now(UTC),
        ),
    )

    mock_provider = MockProvider(replay_sequence=[mock_report])
    win.controller.set_custom_provider_for_test(mock_provider)

    # Trigger investigation
    win.controller.run_investigation(scenario_id=scenario.id)

    # Wait for background worker to complete and process queued Qt signals
    if win.controller._current_worker:
        win.controller._current_worker.wait(10000)
    qapp.processEvents()

    # Verify report view was populated
    assert win.report_view.report is not None
    assert (
        win.report_view.report.summary == "Replay investigation of synthetic scenario"
    )
    assert "LOW" in win.report_view.risk_label.text()

    # Verify processes view was populated
    assert win.processes_view.table.rowCount() > 0

    # Verify sent to model view was populated
    assert len(win.sent_to_model_view.payload_view.toPlainText()) > 10

    # Verify approvals panel has the recommended action
    assert "1 Pending Action" in win.side_panel.approvals_widget.info_label.text()

    win.close()
    win.deleteLater()
    qapp.processEvents()


def test_no_ui_code_path_executes_action_without_dialog(qapp: QApplication) -> None:
    """Verify that UI triggers execution ONLY through ActionPreviewDialog."""
    fake_trash = MagicMock()
    fake_launcher = MagicMock()

    hooks = {
        "send2trash": fake_trash,
        "open_file_location": fake_launcher,
    }

    bus = EventBus()
    win = MoonlightMainWindow(event_bus=bus, hooks=hooks)
    win.show()

    ev_id = "ev-process-test-action"
    report = Report(
        summary="Action consent test report",
        risk_tier="review",
        confidence=0.88,
        observed_facts=(
            ObservedFact(text="Candidate action item", evidence_ids=(ev_id,)),
        ),
        recommended_actions=(
            RecommendedAction(
                action_id="move_to_recycle_bin",
                reason="Delete staged temp file",
                evidence_ids=(ev_id,),
            ),
        ),
        metadata=ReportMetadata(
            provider="mock",
            model="mock_engine",
            prompt_version="1.0.0",
            timestamp=datetime.now(UTC),
        ),
    )

    win.report_view.set_report(report)
    win.side_panel.approvals_widget.set_actions(
        report.recommended_actions, report=report
    )

    # Merely displaying or queueing actions must NEVER invoke execution hooks
    assert fake_trash.called is False
    assert fake_launcher.called is False

    win.close()
    win.deleteLater()
    qapp.processEvents()
