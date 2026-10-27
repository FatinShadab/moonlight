"""Schema-validated report reasoning and offline scaffold for Moonlight."""

from __future__ import annotations

from moonlight.reasoning.fallback import build_rules_fallback_report
from moonlight.reasoning.grounding import (
    EmptyCitationError,
    GroundingError,
    GroundingValidationResult,
    OffAllowlistActionError,
    UngroundedCitationError,
    extract_known_evidence_ids,
    validate_grounding,
    validate_grounding_or_raise,
)
from moonlight.reasoning.models import (
    Hypothesis,
    Likelihood,
    ObservedFact,
    RecommendedAction,
    Report,
    ReportMetadata,
    RiskTier,
)
from moonlight.reasoning.orchestrator import ReasoningOrchestrator
from moonlight.reasoning.prompting import (
    EvidenceAliasMap,
    build_investigation_prompt,
    build_repair_prompt,
    format_untrusted_evidence_block,
    load_prompt_template,
    remap_report_citations,
)
from moonlight.reasoning.provider import (
    MetaProvider,
    MockProvider,
    OllamaCloudProvider,
    ProviderType,
    ReasoningConfig,
    ReportProvider,
    get_provider,
)

__all__ = [
    "EmptyCitationError",
    "EvidenceAliasMap",
    "GroundingError",
    "GroundingValidationResult",
    "Hypothesis",
    "Likelihood",
    "MetaProvider",
    "MockProvider",
    "ObservedFact",
    "OffAllowlistActionError",
    "OllamaCloudProvider",
    "ProviderType",
    "ReasoningConfig",
    "ReasoningOrchestrator",
    "RecommendedAction",
    "Report",
    "ReportMetadata",
    "ReportProvider",
    "RiskTier",
    "UngroundedCitationError",
    "build_investigation_prompt",
    "build_repair_prompt",
    "build_rules_fallback_report",
    "extract_known_evidence_ids",
    "format_untrusted_evidence_block",
    "get_provider",
    "load_prompt_template",
    "remap_report_citations",
    "validate_grounding",
    "validate_grounding_or_raise",
]
