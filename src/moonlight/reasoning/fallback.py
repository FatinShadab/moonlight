"""Local rules-only report synthesis for offline and fallback modes.

Ensures the Moonlight pipeline can always produce a schema-valid,
grounded Report even when AI reasoning fails, is unavailable, or returns invalid output.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from moonlight.core.evidence import EvidenceBundle
from moonlight.minimizer.models import MinimizedBundle, ModelPayload
from moonlight.reasoning.models import (
    Hypothesis,
    ObservedFact,
    RecommendedAction,
    Report,
    ReportMetadata,
    RiskTier,
)
from moonlight.rules.process import ProcessRuleReport, evaluate_process


def build_rules_fallback_report(
    evidence: (
        EvidenceBundle
        | ModelPayload
        | MinimizedBundle
        | Sequence[EvidenceBundle]
        | Sequence[MinimizedBundle]
        | None
    ) = None,
    rule_report: ProcessRuleReport | None = None,
    reason: str = "AI reasoning provider offline or failed",
) -> Report:
    """Build a schema-valid, grounded Report using deterministic local rules.

    Args:
        evidence: Source evidence bundle(s) or minimized payload.
        rule_report: Optional pre-evaluated process rules report.
        reason: Explanation of why the fallback was triggered.

    Returns:
        A Report with is_fallback=True and fallback_reason populated.
    """
    bundle: EvidenceBundle | None = None
    if isinstance(evidence, EvidenceBundle):
        bundle = evidence
    elif (
        isinstance(evidence, Sequence)
        and evidence
        and isinstance(evidence[0], EvidenceBundle)
    ):
        bundle = evidence[0]

    if rule_report is None and bundle is not None and bundle.subject_type == "process":
        try:
            rule_report = evaluate_process(bundle)
        except Exception:
            rule_report = None

    observed_items: list[tuple[str, str]] = []
    if bundle is not None:
        for item in bundle.items:
            if item.availability == "observed":
                observed_items.append((item.id, f"{item.kind.value}: {item.value}"))
    elif isinstance(evidence, ModelPayload):
        for mb in evidence.untrusted_evidence:
            for item_m in mb.items:
                if item_m.availability == "observed":
                    observed_items.append(
                        (item_m.id, f"{item_m.kind.value}: {item_m.value}")
                    )
    elif isinstance(evidence, MinimizedBundle):
        for item_m in evidence.items:
            if item_m.availability == "observed":
                observed_items.append(
                    (item_m.id, f"{item_m.kind.value}: {item_m.value}")
                )

    tier: RiskTier = "inconclusive"
    confidence = 0.5
    derivation = "No rule report available; defaulted to inconclusive."
    observed_facts: list[ObservedFact] = []
    hypotheses: list[Hypothesis] = []
    benign_explanations: list[str] = [
        "Legitimate administrative tool or background system process.",
    ]
    missing_evidence: list[str] = []

    if rule_report is not None:
        tier = rule_report.tier
        confidence = 1.0 if tier != "inconclusive" else 0.5
        derivation = rule_report.derivation

        for finding in rule_report.findings:
            observed_facts.append(
                ObservedFact(
                    text=f"{finding.title}: {finding.explanation}",
                    evidence_ids=finding.evidence_ids,
                )
            )
            hypotheses.append(
                Hypothesis(
                    text=f"Rule '{finding.rule_id}' matched: {finding.title}",
                    evidence_ids=finding.evidence_ids,
                    likelihood="high" if finding.weight >= 4 else "medium",
                )
            )

        for miss in rule_report.missing_evidence:
            missing_evidence.append(f"{miss.kind.value}: {miss.reason}")

    if not observed_facts:
        if observed_items:
            first_id, first_desc = observed_items[0]
            observed_facts.append(
                ObservedFact(
                    text=(
                        f"Observed system evidence ({first_desc[:50]}...); "
                        "no security rules flagged anomalies."
                    ),
                    evidence_ids=(first_id,),
                )
            )
            hypotheses.append(
                Hypothesis(
                    text="Process execution conforms to standard system baseline.",
                    evidence_ids=(first_id,),
                    likelihood="high",
                )
            )
        else:
            observed_facts.append(
                ObservedFact(
                    text="Inspection concluded with limited or unavailable evidence.",
                    evidence_ids=("ev-placeholder-none",),
                )
            )

    action_ev_ids: tuple[str, ...] = (
        (observed_facts[0].evidence_ids[0],)
        if observed_facts and observed_facts[0].evidence_ids
        else ()
    )
    recommended_actions: tuple[RecommendedAction, ...] = (
        RecommendedAction(
            action_id="mark_reviewed",
            reason="Local rules evaluation completed; marked for manual review.",
            evidence_ids=action_ev_ids,
        ),
    )

    summary = (
        f"Local rules-only assessment: risk tier capped at '{tier}'. "
        f"AI reasoning unavailable ({reason})."
    )

    metadata = ReportMetadata(
        provider="rules_only_fallback",
        model="local_rules",
        prompt_version="none",
        timestamp=datetime.now(UTC),
    )

    return Report(
        summary=summary,
        risk_tier=tier,
        confidence=confidence,
        observed_facts=tuple(observed_facts),
        hypotheses=tuple(hypotheses),
        benign_explanations=tuple(benign_explanations),
        missing_evidence=tuple(missing_evidence),
        recommended_actions=recommended_actions,
        uncertainty_notes=(
            f"Fallback report generated deterministically. Derivation: {derivation}"
        ),
        metadata=metadata,
        is_fallback=True,
        fallback_reason=reason,
    )
