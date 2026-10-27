"""Prompt construction, untrusted evidence datamarking, and citation alias mapping."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from importlib.resources import files
from typing import Any, cast

from moonlight.core.evidence import EvidenceBundle
from moonlight.minimizer.models import MinimizedBundle, ModelPayload
from moonlight.reasoning.models import (
    Hypothesis,
    ObservedFact,
    RecommendedAction,
    Report,
)

PROMPT_VERSION = "1.0.0"


def _plain_value(value: Any) -> Any:
    """Convert mappingproxy and frozen containers to plain JSON-serializable types."""
    if isinstance(value, Mapping):
        return {str(k): _plain_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain_value(v) for v in value]
    return value


@dataclass(frozen=True)
class EvidenceAliasMap:
    """Mapping between stable evidence IDs and short prompt aliases (E1, E2)."""

    alias_to_id: dict[str, str]
    id_to_alias: dict[str, str]

    @classmethod
    def build(cls, evidence_ids: Iterable[str]) -> EvidenceAliasMap:
        alias_to_id: dict[str, str] = {}
        id_to_alias: dict[str, str] = {}
        for idx, ev_id in enumerate(sorted(set(evidence_ids)), start=1):
            alias = f"E{idx}"
            alias_to_id[alias] = ev_id
            id_to_alias[ev_id] = alias
        return cls(alias_to_id=alias_to_id, id_to_alias=id_to_alias)

    def remap_citation(self, citation: str) -> str:
        """Remap a short alias if known, or return original citation."""
        return self.alias_to_id.get(citation, citation)

    def remap_citations(self, citations: Sequence[str]) -> tuple[str, ...]:
        """Remap a sequence of citations using the alias map."""
        return tuple(self.remap_citation(c) for c in citations)


def load_prompt_template(filename: str) -> str:
    """Load a prompt template from src/moonlight/reasoning/prompts/."""
    try:
        resource = files("moonlight.reasoning.prompts").joinpath(filename)
        return resource.read_text(encoding="utf-8")
    except Exception as exc:
        raise FileNotFoundError(
            f"Failed to load prompt template '{filename}': {exc}"
        ) from exc


def format_untrusted_evidence_block(
    evidence: (
        EvidenceBundle
        | ModelPayload
        | MinimizedBundle
        | Sequence[EvidenceBundle]
        | Sequence[MinimizedBundle]
    ),
    alias_map: EvidenceAliasMap,
) -> str:
    """Format and datamark untrusted evidence with short aliases for prompts.

    Every line is datamarked and clearly distinguished from instructions.
    """
    items: list[tuple[str, str, str, Any]] = []

    if isinstance(evidence, EvidenceBundle):
        for item in evidence.items:
            items.append((item.id, item.kind.value, item.availability, item.value))
    elif isinstance(evidence, ModelPayload):
        for bundle in evidence.untrusted_evidence:
            for m_item in bundle.items:
                items.append(
                    (m_item.id, m_item.kind.value, m_item.availability, m_item.value)
                )
    elif isinstance(evidence, MinimizedBundle):
        for m_item in evidence.items:
            items.append(
                (m_item.id, m_item.kind.value, m_item.availability, m_item.value)
            )
    elif isinstance(evidence, Sequence):
        for entry in evidence:
            if isinstance(entry, EvidenceBundle):
                for item in entry.items:
                    items.append(
                        (item.id, item.kind.value, item.availability, item.value)
                    )
            elif isinstance(entry, MinimizedBundle):
                for m_item in entry.items:
                    items.append(
                        (
                            m_item.id,
                            m_item.kind.value,
                            m_item.availability,
                            m_item.value,
                        )
                    )

    lines: list[str] = []
    for ev_id, kind, availability, value in items:
        alias = alias_map.id_to_alias.get(ev_id, ev_id)
        val_str = (
            json.dumps(_plain_value(value), separators=(",", ":"))
            if value is not None
            else "null"
        )
        lines.append(
            f"DATA_ITEM: [{alias}] (id: {ev_id}) kind={kind} "
            f"availability={availability} value={val_str}"
        )

    return "\n".join(lines)


def build_investigation_prompt(
    evidence: (
        EvidenceBundle
        | ModelPayload
        | MinimizedBundle
        | Sequence[EvidenceBundle]
        | Sequence[MinimizedBundle]
    ),
    alias_map: EvidenceAliasMap | None = None,
) -> tuple[str, str, EvidenceAliasMap]:
    """Construct (system_prompt, user_prompt, alias_map) for an investigation."""
    from moonlight.reasoning.grounding import extract_known_evidence_ids

    if alias_map is None:
        known_ids = extract_known_evidence_ids(evidence)
        alias_map = EvidenceAliasMap.build(known_ids)

    evidence_block = format_untrusted_evidence_block(evidence, alias_map)

    system_template = load_prompt_template("system_prompt.txt")
    user_template = load_prompt_template("investigation_prompt.txt")

    user_prompt = user_template.replace("{evidence_block}", evidence_block)

    return system_template, user_prompt, alias_map


def build_repair_prompt(
    previous_report: str | dict[str, Any] | Report,
    validation_errors: Sequence[str],
    evidence: (
        EvidenceBundle
        | ModelPayload
        | MinimizedBundle
        | Sequence[EvidenceBundle]
        | Sequence[MinimizedBundle]
    ),
    alias_map: EvidenceAliasMap,
) -> str:
    """Construct a repair prompt providing feedback on validation failures."""
    repair_template = load_prompt_template("repair_prompt.txt")
    evidence_block = format_untrusted_evidence_block(evidence, alias_map)

    if isinstance(previous_report, Report):
        report_str = previous_report.model_dump_json(indent=2)
    elif isinstance(previous_report, dict):
        report_str = json.dumps(previous_report, indent=2)
    else:
        report_str = str(previous_report)

    errors_str = "\n".join(f"- {err}" for err in validation_errors)

    prompt = repair_template.replace("{validation_errors}", errors_str)
    prompt = prompt.replace("{previous_report}", report_str)
    prompt = prompt.replace("{evidence_block}", evidence_block)
    return prompt


def remap_report_citations(report: Report, alias_map: EvidenceAliasMap) -> Report:
    """Remap short aliases (E1, E2, ...) in a Report back to stable evidence IDs."""
    new_facts: list[ObservedFact] = []
    for fact in report.observed_facts:
        new_ids = alias_map.remap_citations(fact.evidence_ids)
        new_facts.append(ObservedFact(text=fact.text, evidence_ids=new_ids))

    new_hypotheses: list[Hypothesis] = []
    for hyp in report.hypotheses:
        new_ids = alias_map.remap_citations(hyp.evidence_ids)
        new_hypotheses.append(
            Hypothesis(text=hyp.text, evidence_ids=new_ids, likelihood=hyp.likelihood)
        )

    new_actions: list[RecommendedAction] = []
    for act in report.recommended_actions:
        new_ids = alias_map.remap_citations(act.evidence_ids)
        new_actions.append(
            RecommendedAction(
                action_id=act.action_id, reason=act.reason, evidence_ids=new_ids
            )
        )

    return Report(
        summary=report.summary,
        risk_tier=report.risk_tier,
        confidence=report.confidence,
        observed_facts=tuple(new_facts),
        hypotheses=tuple(new_hypotheses),
        benign_explanations=report.benign_explanations,
        missing_evidence=report.missing_evidence,
        recommended_actions=tuple(new_actions),
        uncertainty_notes=report.uncertainty_notes,
        metadata=report.metadata,
        is_fallback=report.is_fallback,
        fallback_reason=report.fallback_reason,
    )


def remap_raw_report_dict(
    data: dict[str, Any], alias_map: EvidenceAliasMap
) -> dict[str, Any]:
    """Remap short aliases in raw dictionary before Pydantic validation."""
    data_copy: dict[str, Any] = cast(dict[str, Any], json.loads(json.dumps(data)))

    if "observed_facts" in data_copy and isinstance(data_copy["observed_facts"], list):
        for fact in data_copy["observed_facts"]:
            if (
                isinstance(fact, dict)
                and "evidence_ids" in fact
                and isinstance(fact["evidence_ids"], list)
            ):
                fact["evidence_ids"] = [
                    alias_map.remap_citation(c) for c in fact["evidence_ids"]
                ]

    if "hypotheses" in data_copy and isinstance(data_copy["hypotheses"], list):
        for hyp in data_copy["hypotheses"]:
            if (
                isinstance(hyp, dict)
                and "evidence_ids" in hyp
                and isinstance(hyp["evidence_ids"], list)
            ):
                hyp["evidence_ids"] = [
                    alias_map.remap_citation(c) for c in hyp["evidence_ids"]
                ]

    if "recommended_actions" in data_copy and isinstance(
        data_copy["recommended_actions"], list
    ):
        for act in data_copy["recommended_actions"]:
            if (
                isinstance(act, dict)
                and "evidence_ids" in act
                and isinstance(act["evidence_ids"], list)
            ):
                act["evidence_ids"] = [
                    alias_map.remap_citation(c) for c in act["evidence_ids"]
                ]

    return data_copy
