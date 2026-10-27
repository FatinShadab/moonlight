"""Reasoning orchestrator with validation, repair retry, and rules-only fallback."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any

from moonlight.core.evidence import EvidenceBundle
from moonlight.minimizer import MinimizationError, PrivacyContext, minimize_evidence
from moonlight.minimizer.models import MinimizedBundle, ModelPayload
from moonlight.reasoning.fallback import build_rules_fallback_report
from moonlight.reasoning.grounding import (
    extract_known_evidence_ids,
    validate_grounding,
)
from moonlight.reasoning.models import Report
from moonlight.reasoning.prompting import (
    EvidenceAliasMap,
    build_repair_prompt,
    remap_report_citations,
)
from moonlight.reasoning.provider import ReasoningConfig, ReportProvider, get_provider
from moonlight.rules.process import ProcessRuleReport

logger = logging.getLogger(__name__)


class ReasoningOrchestrator:
    """Coordinates evidence minimization, AI reasoning, validation, and fallback."""

    def __init__(
        self,
        provider: ReportProvider | None = None,
        config: ReasoningConfig | None = None,
    ) -> None:
        self.config = config or ReasoningConfig()
        self.provider = provider or get_provider(self.config)

    def investigate(
        self,
        evidence: (
            EvidenceBundle
            | ModelPayload
            | MinimizedBundle
            | Sequence[EvidenceBundle]
            | Sequence[MinimizedBundle]
        ),
        rule_report: ProcessRuleReport | None = None,
        privacy_context: PrivacyContext | None = None,
    ) -> Report:
        """Run the end-to-end reasoning investigation pipeline.

        1. Extract known evidence IDs and build short aliases (E1, E2, ...).
        2. Prepare minimized payload (if raw EvidenceBundle is provided).
        3. Attempt 1: Call provider.investigate().
        4. Remap short aliases and validate grounding and schema.
        5. If validation fails or provider errors, attempt ONE repair retry.
        6. If repair retry fails, fall back to rules-only report with visible flag.
        """
        known_ids = extract_known_evidence_ids(evidence)
        alias_map = EvidenceAliasMap.build(known_ids)

        payload: ModelPayload | dict[str, Any] | str
        if isinstance(evidence, ModelPayload):
            payload = evidence
        elif isinstance(evidence, EvidenceBundle):
            try:
                min_result = minimize_evidence(
                    (evidence,), context=privacy_context or PrivacyContext()
                )
                payload = min_result.payload_json
            except MinimizationError as err:
                logger.warning("Minimization failed: %s; falling back to rules", err)
                return build_rules_fallback_report(
                    evidence=evidence,
                    rule_report=rule_report,
                    reason=f"Privacy minimization withheld payload: {err}",
                )
        elif (
            isinstance(evidence, Sequence)
            and evidence
            and isinstance(evidence[0], EvidenceBundle)
        ):
            try:
                min_result = minimize_evidence(
                    evidence,  # type: ignore[arg-type]
                    context=privacy_context or PrivacyContext(),
                )
                payload = min_result.payload_json
            except MinimizationError as err:
                logger.warning("Minimization failed: %s; falling back to rules", err)
                return build_rules_fallback_report(
                    evidence=evidence,
                    rule_report=rule_report,
                    reason=f"Privacy minimization withheld payload: {err}",
                )
        else:
            payload = str(evidence)

        # Attempt 1
        attempt_error: str | None = None
        first_report: Report | None = None

        try:
            raw_report = self.provider.investigate(payload)
            remapped = remap_report_citations(raw_report, alias_map)
            grounding = validate_grounding(remapped, known_ids)
            if grounding.is_valid:
                return remapped
            attempt_error = "; ".join(grounding.errors)
            first_report = remapped
        except Exception as exc:
            attempt_error = f"Provider investigation error: {exc}"

        # Attempt 2: ONE repair retry through the provider
        logger.info(
            "Initial report failed (%s); attempting 1 repair retry",
            attempt_error,
        )

        repair_prompt: str
        if first_report is not None:
            repair_prompt = build_repair_prompt(
                first_report,
                [attempt_error or "Validation failed"],
                evidence,
                alias_map,
            )
        else:
            repair_prompt = (
                f"Previous attempt failed: {attempt_error}. "
                "Please provide a valid Report JSON."
            )

        try:
            repaired_raw = self.provider.investigate(
                payload, repair_instruction=repair_prompt
            )
            repaired = remap_report_citations(repaired_raw, alias_map)
            repaired_grounding = validate_grounding(repaired, known_ids)
            if repaired_grounding.is_valid:
                return repaired
            final_reason = (
                f"Repair retry failed grounding: {'; '.join(repaired_grounding.errors)}"
            )
        except Exception as exc:
            final_reason = f"Repair retry provider error: {exc}"

        # Fall back to deterministic rules-only report
        logger.warning(
            "Reasoning failed after repair (%s); returning rules-only report",
            final_reason,
        )
        return build_rules_fallback_report(
            evidence=evidence,
            rule_report=rule_report,
            reason=final_reason,
        )
