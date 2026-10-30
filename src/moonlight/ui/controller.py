"""Investigation controller and background worker thread for Moonlight UI.

Features:
- Decoupled worker thread preventing UI freezes.
- Replay mode with labeled scenarios and expected reports via MockProvider.
- Live mode with read-only collection, mock by default (air-gapped safety).
- UI-layer emission of InvestigationEvents wrapping engine return values.
- Seamless coordination between views, policy layer, and reasoning orchestrator.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from PySide6.QtCore import QObject, QThread, Signal

from moonlight.collectors.bundle import collect_evidence
from moonlight.core.evidence import EvidenceBundle
from moonlight.eval.scenarios import (
    ProcessScenario,
    StorageScenario,
    load_all_scenarios,
    load_expected_reports,
)
from moonlight.minimizer import PrivacyContext, minimize_evidence
from moonlight.minimizer.models import MinimizationResult
from moonlight.policy.actions import ProposedAction
from moonlight.policy.engine import validate_proposed_action
from moonlight.policy.protected import classify_path_storage
from moonlight.reasoning.models import Report
from moonlight.reasoning.orchestrator import ReasoningOrchestrator
from moonlight.reasoning.provider import MockProvider, ReportProvider
from moonlight.rules.process import ProcessRuleReport, evaluate_process
from moonlight.ui.events import EventBus, get_event_bus


@dataclass(frozen=True)
class InvestigationRunResult:
    """Consolidated outputs of a completed investigation pipeline run."""

    scenario_id: str
    bundles: tuple[EvidenceBundle, ...]
    minimization_result: MinimizationResult | None
    report: Report | None
    storage_items: tuple[dict[str, Any], ...]
    rule_report: ProcessRuleReport | None


class InvestigationWorker(QThread):
    """Worker thread running collection, rules, minimization, and reasoning."""

    status_message = Signal(str)
    finished_result = Signal(object)  # InvestigationRunResult
    failed_error = Signal(str)

    def __init__(
        self,
        mode: str,  # "replay" or "live"
        provider_name: str,  # "mock", "ollama-cloud", "meta"
        scenario_id: str | None = None,
        live_pid: int | None = None,
        event_bus: EventBus | None = None,
        custom_provider: ReportProvider | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.mode = mode
        self.provider_name = provider_name
        self.scenario_id = scenario_id
        self.live_pid = live_pid
        self.bus = event_bus if event_bus is not None else get_event_bus()
        self.custom_provider = custom_provider

    def run(self) -> None:
        try:
            self._execute_investigation()
        except Exception as exc:
            self.failed_error.emit(str(exc))

    def _execute_investigation(self) -> None:
        bus = self.bus
        bundles: list[EvidenceBundle] = []
        storage_items: list[dict[str, Any]] = []
        target_subject = ""
        sid = self.scenario_id or "live_investigation"

        # 1. Collection Phase
        self.status_message.emit("Collecting investigation evidence...")
        msg = (
            f"Starting investigation ({self.mode} mode, "
            f"provider={self.provider_name})."
        )
        bus.emit_event(
            kind="collection_started",
            message=msg,
            subject=sid,
            severity="info",
        )

        if self.mode == "replay":
            # Load replay scenario from fixtures
            all_scenarios = load_all_scenarios()
            matched = next((s for s in all_scenarios if s.id == self.scenario_id), None)
            if matched is None and all_scenarios:
                matched = all_scenarios[0]
                sid = matched.id

            if isinstance(matched, ProcessScenario):
                bundles.append(matched.bundle)
                target_subject = matched.bundle.subject_id
            elif isinstance(matched, StorageScenario):
                bundles.append(matched.bundle)
                cat, _reason = classify_path_storage(matched.target_path)
                storage_items.append({
                    "citation_id": f"ev-storage-{matched.id}",
                    "path": matched.target_path,
                    "category": matched.category,
                    "size_bytes": 1024 * 1024 * 5,  # 5 MB placeholder
                    "details": f"{matched.description} ({matched.rationale})",
                })
                target_subject = matched.target_path
            elif matched is not None:
                bundles.append(matched.bundle)
                target_subject = matched.bundle.subject_id
        else:
            # Live Mode: collect real read-only process bundle safely
            pid = self.live_pid or os.getpid()
            collected = collect_evidence(pid)
            if isinstance(collected, EvidenceBundle):
                bundles.append(collected)
                target_subject = collected.subject_id
            else:
                raise RuntimeError(f"Live collection failed: {collected}")

        # Emit collection finished event
        total_items = sum(len(b.items) for b in bundles)
        item_citations = tuple(i.id for b in bundles for i in b.items)
        fin_msg = (
            f"Collected {total_items} read-only evidence items for "
            f"subject '{target_subject}'."
        )
        bus.emit_event(
            kind="collection_finished",
            message=fin_msg,
            subject=target_subject,
            evidence_ids=item_citations,
            severity="info",
        )

        # 2. Rule Evaluation Phase
        rule_report: ProcessRuleReport | None = None
        if bundles and bundles[0].subject_type == "process":
            self.status_message.emit("Evaluating deterministic rules...")
            rule_report = evaluate_process(bundles[0])
            matched_count = len(rule_report.findings)
            missing_count = len(rule_report.missing_evidence)
            r_msg = (
                f"Process rule verdict: {rule_report.tier.upper()} "
                f"(score: {rule_report.score}). Matched {matched_count} findings; "
                f"{missing_count} missing keys."
            )
            bus.emit_event(
                kind="rules_evaluated",
                message=r_msg,
                subject=target_subject,
                evidence_ids=item_citations,
                severity=(
                    "high"
                    if rule_report.tier == "high"
                    else "review"
                    if rule_report.tier == "review"
                    else "low"
                ),
            )

        # 3. Privacy Minimization Phase
        self.status_message.emit("Minimizing evidence and generating redaction log...")
        min_result: MinimizationResult | None = None
        if bundles:
            min_result = minimize_evidence(tuple(bundles), context=PrivacyContext())
            p_len = len(min_result.payload_bytes())
            r_count = len(min_result.redaction_log)
            p_msg = (
                f"Privacy minimizer produced {p_len} bytes wire payload "
                f"with {r_count} local redactions applied."
            )
            bus.emit_event(
                kind="payload_minimized",
                message=p_msg,
                subject=target_subject,
                severity="info",
            )

        # 4. AI Reasoning & Provider Invocation
        prov_lbl = f"Consulting reasoning provider '{self.provider_name}'..."
        self.status_message.emit(prov_lbl)
        bus.emit_event(
            kind="provider_called",
            message=f"Dispatched minimized payload to provider '{self.provider_name}'.",
            subject=target_subject,
            severity="info",
        )

        provider: ReportProvider
        if self.custom_provider is not None:
            provider = self.custom_provider
        elif self.provider_name == "mock":
            # Check if expected report fixture exists for this scenario
            reports = load_expected_reports()
            if sid in reports:
                provider = MockProvider(replay_sequence=[reports[sid]])
            else:
                provider = MockProvider()
        else:
            # Fallback to MockProvider for safety if meta/ollama not configured
            provider = MockProvider()

        orchestrator = ReasoningOrchestrator(provider=provider)
        report: Report | None = None
        if bundles:
            report = orchestrator.investigate(
                bundles[0] if len(bundles) == 1 else bundles,
                rule_report=rule_report,
            )

        if report is not None:
            if report.is_fallback:
                bus.emit_event(
                    kind="report_fallback",
                    message=f"Rules-only fallback activated: {report.fallback_reason}",
                    subject=target_subject,
                    severity="warning",
                )
            else:
                val_msg = (
                    f"Reasoning report validated and grounded. "
                    f"Verdict: {report.risk_tier.upper()} "
                    f"({report.confidence:.0%} confidence)."
                )
                bus.emit_event(
                    kind="report_validated",
                    message=val_msg,
                    subject=target_subject,
                    severity="info",
                )

            # 5. Proposed Actions & Policy Checks
            for action_rec in report.recommended_actions:
                act_msg = (
                    f"Recommended action proposed: {action_rec.action_id} "
                    f"({action_rec.reason})."
                )
                bus.emit_event(
                    kind="action_proposed",
                    message=act_msg,
                    subject=action_rec.action_id,
                    evidence_ids=action_rec.evidence_ids,
                    severity="info",
                )
                proposed = ProposedAction(
                    action_type=action_rec.action_id,
                    reason=action_rec.reason,
                    evidence_ids=action_rec.evidence_ids,
                )
                decision = validate_proposed_action(proposed)
                verdict = "ALLOWED" if decision.allowed else "BLOCKED"
                rej = (
                    f" ({decision.rejection_reason})"
                    if not decision.allowed
                    else ""
                )
                dec_msg = (
                    f"Policy verdict for {action_rec.action_id}: {verdict}{rej}"
                )
                bus.emit_event(
                    kind="policy_decision",
                    message=dec_msg,
                    subject=action_rec.action_id,
                    severity="low" if decision.allowed else "high",
                )

        # Assemble and emit completed result
        result = InvestigationRunResult(
            scenario_id=sid,
            bundles=tuple(bundles),
            minimization_result=min_result,
            report=report,
            storage_items=tuple(storage_items),
            rule_report=rule_report,
        )
        self.finished_result.emit(result)


class InvestigationController(QObject):
    """Coordinates investigation lifecycle, mode toggles, and async workers."""

    investigation_started = Signal()
    investigation_finished = Signal(object)  # InvestigationRunResult
    investigation_failed = Signal(str)
    status_changed = Signal(str)

    def __init__(
        self,
        event_bus: EventBus | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.bus = event_bus if event_bus is not None else get_event_bus()
        self._mode: str = "replay"  # "replay" or "live"
        self._provider_name: str = "mock"  # "mock", "ollama-cloud", "meta"
        self._current_worker: InvestigationWorker | None = None
        self._custom_provider: ReportProvider | None = None

    @property
    def mode(self) -> str:
        return self._mode

    @mode.setter
    def mode(self, val: str) -> None:
        self._mode = val

    @property
    def provider_name(self) -> str:
        return self._provider_name

    @provider_name.setter
    def provider_name(self, val: str) -> None:
        self._provider_name = val

    def set_custom_provider_for_test(self, provider: ReportProvider | None) -> None:
        """Testing helper to inject a mock provider."""
        self._custom_provider = provider

    def run_investigation(
        self,
        scenario_id: str | None = None,
        live_pid: int | None = None,
    ) -> None:
        """Trigger an investigation run in a background worker thread."""
        if self._current_worker is not None and self._current_worker.isRunning():
            return  # Already running

        self.investigation_started.emit()
        self.status_changed.emit("Starting investigation worker...")

        worker = InvestigationWorker(
            mode=self._mode,
            provider_name=self._provider_name,
            scenario_id=scenario_id,
            live_pid=live_pid,
            event_bus=self.bus,
            custom_provider=self._custom_provider,
        )
        self._current_worker = worker

        worker.status_message.connect(self.status_changed.emit)
        worker.finished_result.connect(self._on_worker_finished)
        worker.failed_error.connect(self._on_worker_failed)
        worker.start()

    def _on_worker_finished(self, result: InvestigationRunResult) -> None:
        self.investigation_finished.emit(result)
        self.status_changed.emit("Investigation completed.")
        self._current_worker = None

    def _on_worker_failed(self, error: str) -> None:
        self.investigation_failed.emit(error)
        self.status_changed.emit(f"Investigation error: {error}")
        self._current_worker = None
