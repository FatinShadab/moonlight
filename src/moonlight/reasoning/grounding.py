"""Grounding validator for Moonlight investigation reports.

Enforces:
1. Every cited evidence ID exists in the evidence bundle / model payload.
2. Every observed fact cites at least one valid evidence ID.
3. Every recommended action is on the policy allowlist (from P8).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from moonlight.core.evidence import EvidenceBundle
from moonlight.minimizer.models import MinimizedBundle, ModelPayload
from moonlight.policy.actions import ALLOWED_ACTION_IDS
from moonlight.reasoning.models import Report


class GroundingError(ValueError):
    """Base exception for investigation report grounding failures."""


class UngroundedCitationError(GroundingError):
    """Raised when a report cites an evidence ID not in the evidence bundle."""


class EmptyCitationError(GroundingError):
    """Raised when an observed fact fails to cite any evidence IDs."""


class OffAllowlistActionError(GroundingError):
    """Raised when a recommended action is not on the policy allowlist."""


@dataclass(frozen=True)
class GroundingValidationResult:
    """Detailed outcome of grounding validation."""

    is_valid: bool
    errors: tuple[str, ...]
    ungrounded_citations: tuple[str, ...]
    empty_fact_indices: tuple[int, ...]
    disallowed_actions: tuple[str, ...]


def extract_known_evidence_ids(
    evidence: (
        EvidenceBundle
        | ModelPayload
        | MinimizedBundle
        | Sequence[EvidenceBundle]
        | Sequence[MinimizedBundle]
        | Iterable[str]
    ),
) -> frozenset[str]:
    """Extract all available evidence IDs from bundles, payloads, or collections."""
    if isinstance(evidence, EvidenceBundle):
        return frozenset(item.id for item in evidence.items)
    if isinstance(evidence, ModelPayload):
        return frozenset(
            item.id for bundle in evidence.untrusted_evidence for item in bundle.items
        )
    if isinstance(evidence, MinimizedBundle):
        return frozenset(item.id for item in evidence.items)
    if isinstance(evidence, (set, frozenset)):
        return frozenset(evidence)
    if isinstance(evidence, Sequence) and evidence:
        first = evidence[0]
        if isinstance(first, EvidenceBundle):
            return frozenset(
                item.id
                for b in evidence
                if isinstance(b, EvidenceBundle)
                for item in b.items
            )
        if isinstance(first, MinimizedBundle):
            return frozenset(
                item.id
                for b in evidence
                if isinstance(b, MinimizedBundle)
                for item in b.items
            )
        if isinstance(first, str):
            return frozenset(s for s in evidence if isinstance(s, str))
    return frozenset(str(x) for x in evidence)


def validate_grounding(
    report: Report,
    evidence: (
        EvidenceBundle
        | ModelPayload
        | MinimizedBundle
        | Sequence[EvidenceBundle]
        | Sequence[MinimizedBundle]
        | Iterable[str]
    ),
) -> GroundingValidationResult:
    """Validate report grounding against the known evidence IDs and allowlist.

    Rules:
    1. Every cited ID in observed_facts, hypotheses, and recommended_actions
       exists in the bundle.
    2. Every observed fact cites at least one evidence ID.
    3. Every action_id in recommended_actions is in ALLOWED_ACTION_IDS.
    """
    known_ids = extract_known_evidence_ids(evidence)
    errors: list[str] = []
    ungrounded: list[str] = []
    empty_facts: list[int] = []
    disallowed_actions: list[str] = []

    # Rule 2: Every observed fact cites at least one ID
    for idx, fact in enumerate(report.observed_facts):
        if not fact.evidence_ids:
            empty_facts.append(idx)
            errors.append(
                f"Observed fact [{idx}] ('{fact.text[:40]}...') cites no evidence IDs."
            )

    # Rule 1: Every cited ID exists in the bundle
    for fact in report.observed_facts:
        for ev_id in fact.evidence_ids:
            if ev_id not in known_ids and ev_id not in ungrounded:
                ungrounded.append(ev_id)
                errors.append(
                    f"Observed fact cites unknown evidence ID '{ev_id}' not in bundle."
                )

    for hyp in report.hypotheses:
        for ev_id in hyp.evidence_ids:
            if ev_id not in known_ids and ev_id not in ungrounded:
                ungrounded.append(ev_id)
                errors.append(
                    f"Hypothesis cites unknown evidence ID '{ev_id}' not in bundle."
                )

    for action in report.recommended_actions:
        # Rule 3: Every action_id is on the policy allowlist from P8
        if action.action_id not in ALLOWED_ACTION_IDS:
            if action.action_id not in disallowed_actions:
                disallowed_actions.append(action.action_id)
            errors.append(
                f"Recommended action '{action.action_id}' is not permitted by policy "
                f"allowlist ({sorted(ALLOWED_ACTION_IDS)})."
            )

        for ev_id in action.evidence_ids:
            if ev_id not in known_ids and ev_id not in ungrounded:
                ungrounded.append(ev_id)
                errors.append(
                    f"Action '{action.action_id}' cites unknown ID '{ev_id}'."
                )

    is_valid = len(errors) == 0
    return GroundingValidationResult(
        is_valid=is_valid,
        errors=tuple(errors),
        ungrounded_citations=tuple(ungrounded),
        empty_fact_indices=tuple(empty_facts),
        disallowed_actions=tuple(disallowed_actions),
    )


def validate_grounding_or_raise(
    report: Report,
    evidence: (
        EvidenceBundle
        | ModelPayload
        | MinimizedBundle
        | Sequence[EvidenceBundle]
        | Sequence[MinimizedBundle]
        | Iterable[str]
    ),
) -> None:
    """Validate grounding or raise an appropriate GroundingError."""
    result = validate_grounding(report, evidence)
    if result.is_valid:
        return

    if result.empty_fact_indices:
        raise EmptyCitationError(result.errors[0])
    if result.ungrounded_citations:
        raise UngroundedCitationError(result.errors[0])
    if result.disallowed_actions:
        raise OffAllowlistActionError(result.errors[0])
    raise GroundingError("; ".join(result.errors))
