"""Script to generate offscreen UI screenshots for documentation."""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime
from pathlib import Path

# Force offscreen headless Qt rendering
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtWidgets import QApplication

from moonlight.core.evidence import (
    EvidenceBundle,
    EvidenceItem,
    EvidenceKind,
    make_evidence_id,
)
from moonlight.minimizer import PrivacyContext, minimize_evidence
from moonlight.policy.actions import ActionType, ProposedAction
from moonlight.reasoning.models import (
    Hypothesis,
    ObservedFact,
    RecommendedAction,
    Report,
    ReportMetadata,
)
from moonlight.ui.dialogs import ActionPreviewDialog
from moonlight.ui.events import get_event_bus
from moonlight.ui.window import MoonlightMainWindow


def generate_screenshots() -> None:
    """Capture offscreen screenshots of the review interface."""
    app = QApplication.instance()
    if not isinstance(app, QApplication):
        app = QApplication(sys.argv)

    out_dir = Path(__file__).resolve().parents[1] / "docs" / "images"
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Prepare Realistic Mock Evidence & Report
    timestamp = datetime.now(UTC)
    ev_path_id = make_evidence_id(
        "process", "proc-4284", "collector", EvidenceKind.EXECUTABLE_PATH
    )
    ev_sig_id = make_evidence_id(
        "process", "proc-4284", "collector", EvidenceKind.SIGNATURE_STATUS
    )
    ev_hash_id = make_evidence_id(
        "process", "proc-4284", "collector", EvidenceKind.SHA256
    )

    bundle = EvidenceBundle(
        subject_type="process",
        subject_id="proc-4284-analyzer",
        items=(
            EvidenceItem(
                id=ev_path_id,
                source="collector",
                kind=EvidenceKind.EXECUTABLE_PATH,
                availability="observed",
                value=r"C:\Tools\Diagnostic\net_tracer.exe",
                timestamp=timestamp,
            ),
            EvidenceItem(
                id=ev_sig_id,
                source="collector",
                kind=EvidenceKind.SIGNATURE_STATUS,
                availability="observed",
                value="unsigned",
                timestamp=timestamp,
            ),
            EvidenceItem(
                id=ev_hash_id,
                source="collector",
                kind=EvidenceKind.SHA256,
                availability="observed",
                value=(
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                ),
                timestamp=timestamp,
            ),
        ),
    )

    min_res = minimize_evidence((bundle,), context=PrivacyContext())

    report = Report(
        summary=(
            "Investigation of portable diagnostic binary 'net_tracer.exe' running "
            "from custom tools folder without digital signature. Rule evaluation "
            "matches benign administrative utility profile."
        ),
        risk_tier="review",
        confidence=0.88,
        observed_facts=(
            ObservedFact(
                text=(
                    "Executable path located in custom directory "
                    "'C:\\Tools\\Diagnostic\\net_tracer.exe'"
                ),
                evidence_ids=(ev_path_id,),
            ),
            ObservedFact(
                text="Authenticode digital signature status is unsigned",
                evidence_ids=(ev_sig_id,),
            ),
            ObservedFact(
                text="Cryptographic SHA-256 hash calculated and verified",
                evidence_ids=(ev_hash_id,),
            ),
        ),
        hypotheses=(
            Hypothesis(
                text="Portable network diagnostic tool for endpoint troubleshooting",
                evidence_ids=(ev_path_id, ev_sig_id),
                likelihood="high",
            ),
            Hypothesis(
                text="Unsanctioned portable executable evading patch management",
                evidence_ids=(ev_sig_id,),
                likelihood="low",
            ),
        ),
        benign_explanations=(
            "Administrative toolkits and standalone utilities are frequently unsigned.",
            "No unusual parent chain or persistence mechanisms were detected.",
        ),
        missing_evidence=(
            "Publisher certificate chain unavailable due to unsigned binary state.",
        ),
        uncertainty_notes=(
            "Behavioral telemetry during execution was limited to snapshot duration."
        ),
        recommended_actions=(
            RecommendedAction(
                action_id="open_file_location",
                reason="Inspect directory permissions and neighbors in Explorer",
                evidence_ids=(ev_path_id,),
            ),
            RecommendedAction(
                action_id="copy_hash_to_clipboard",
                reason="Query hash against internal threat intelligence database",
                evidence_ids=(ev_hash_id,),
            ),
        ),
        metadata=ReportMetadata(
            provider="mock",
            model="mock_engine",
            prompt_version="1.0.0",
            timestamp=timestamp,
        ),
    )

    # 2. Main Window Screenshot (Overview)
    bus = get_event_bus()
    win = MoonlightMainWindow(event_bus=bus)
    win.resize(1340, 840)

    # Populate data
    win.processes_view.set_bundles([bundle])
    win.sent_to_model_view.set_result(min_res)
    win.report_view.set_report(report)
    win.side_panel.approvals_widget.set_actions(
        report.recommended_actions, report=report
    )

    # Emit telemetry events into activity timeline
    bus.emit_event(
        kind="collection_started",
        message="Started investigation in Replay mode (scenario: proc_curl_portable).",
        subject="proc-4284",
        severity="info",
    )
    bus.emit_event(
        kind="collection_finished",
        message="Collected 3 evidence observations for subject 'proc-4284-analyzer'.",
        subject="proc-4284",
        evidence_ids=(ev_path_id, ev_sig_id, ev_hash_id),
        severity="info",
    )
    bus.emit_event(
        kind="rules_evaluated",
        message="Evaluated rules: unsigned_user_executable (+3), tier REVIEW.",
        subject="proc-4284",
        severity="review",
    )
    bus.emit_event(
        kind="payload_minimized",
        message=(
            f"Privacy minimizer generated {len(min_res.payload_bytes())} bytes payload."
        ),
        subject="proc-4284",
        severity="info",
    )
    bus.emit_event(
        kind="report_validated",
        message="AI report grounded and validated. Risk tier: REVIEW (88% confidence).",
        subject="proc-4284",
        severity="info",
    )

    win.show()
    app.processEvents()

    # Capture Overview
    pix_overview = win.grab()
    pix_overview.save(str(out_dir / "ui_overview.png"), "PNG")
    print(f"Captured: {out_dir / 'ui_overview.png'}")

    # 3. Sent to Model View Screenshot
    win._select_nav_view(3)
    app.processEvents()
    pix_sent = win.grab()
    pix_sent.save(str(out_dir / "ui_sent_to_model.png"), "PNG")
    print(f"Captured: {out_dir / 'ui_sent_to_model.png'}")

    # 4. Isometric World View Screenshot
    win._select_nav_view(5)
    app.processEvents()
    pix_world = win.grab()
    pix_world.save(str(out_dir / "ui_world_view.png"), "PNG")
    print(f"Captured: {out_dir / 'ui_world_view.png'}")

    # 5. Action Preview Dialog Screenshot
    action = ProposedAction(
        action_type=ActionType.MOVE_TO_RECYCLE_BIN,
        target_path=r"C:\Users\analyst\AppData\Local\Temp\cache_staging.tmp",
        reason="Reclaim transient cache space after review",
    )
    dialog = ActionPreviewDialog(action=action)
    dialog.resize(620, 460)
    dialog.show()
    app.processEvents()

    pix_dialog = dialog.grab()
    pix_dialog.save(str(out_dir / "ui_consent_dialog.png"), "PNG")
    print(f"Captured: {out_dir / 'ui_consent_dialog.png'}")
    dialog.close()
    dialog.deleteLater()
    win.close()
    win.deleteLater()
    app.processEvents()
    print("Screenshot generation complete.")
    sys.exit(0)


if __name__ == "__main__":
    generate_screenshots()
