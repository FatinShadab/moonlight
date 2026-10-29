"""Schema-validated investigation report models for the reasoning layer.

These models define the structured output contract for AI reasoning,
grounding validation, local rules fallback, and UI presentation.
"""

from __future__ import annotations

from typing import Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
)

RiskTier = Literal["low", "review", "high", "inconclusive"]
Likelihood = Literal["low", "medium", "high"] | str
REPORT_SCHEMA_VERSION = "1.0.0"


class ObservedFact(BaseModel):
    """An observed factual finding grounded in cited evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    text: str = Field(
        min_length=1,
        description="Factual description of the observation.",
    )
    evidence_ids: tuple[str, ...] = Field(
        min_length=1,
        description="Non-empty tuple of cited evidence IDs supporting this fact.",
    )


class Hypothesis(BaseModel):
    """A plausible explanation or hypothesis regarding observed behaviors."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    text: str = Field(
        min_length=1,
        description="Hypothesis explaining the activity.",
    )
    evidence_ids: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Cited evidence IDs supporting or informing this hypothesis.",
    )
    likelihood: str = Field(
        description="Assessed likelihood of this hypothesis (e.g., low, medium, high).",
    )


class RecommendedAction(BaseModel):
    """A recommended remediation or investigation step."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action_id: str = Field(
        min_length=1,
        description="Action type identifier; must be on the policy allowlist.",
    )
    reason: str = Field(
        min_length=1,
        description="Justification for why this action is recommended.",
    )
    evidence_ids: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Cited evidence IDs justifying this action recommendation.",
    )


class ReportMetadata(BaseModel):
    """Provenance and execution metadata for the investigation report."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    provider: str = Field(
        min_length=1,
        description=(
            "Provider that generated this report (e.g. 'mock', 'meta', "
            "'rules_only_fallback')."
        ),
    )
    model: str = Field(
        min_length=1,
        description="Model identifier or engine name used for generation.",
    )
    prompt_version: str = Field(
        min_length=1,
        description="Semantic version of prompt templates used.",
    )
    timestamp: AwareDatetime = Field(
        description="Timezone-aware timestamp when this report was produced.",
    )
    structured_output_mode: str | None = Field(
        default=None,
        description="Structured output format mode used ('schema' or 'json').",
    )


class Report(BaseModel):
    """Schema-validated investigation report for processes and storage."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    summary: str = Field(
        min_length=1,
        description="Concise executive summary of findings and risk assessment.",
    )
    risk_tier: RiskTier = Field(
        description="Overall assessed risk tier: low, review, high, or inconclusive.",
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence score in [0.0, 1.0] for the assessed risk tier.",
    )
    observed_facts: tuple[ObservedFact, ...] = Field(
        default_factory=tuple,
        description=(
            "Observed factual claims, each citing at least one valid evidence ID."
        ),
    )
    hypotheses: tuple[Hypothesis, ...] = Field(
        default_factory=tuple,
        description="Hypotheses explaining the observed process or disk activity.",
    )
    benign_explanations: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Plausible benign alternatives to avoid false positives.",
    )
    missing_evidence: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Key evidence kinds or queries that were unavailable or missing.",
    )
    recommended_actions: tuple[RecommendedAction, ...] = Field(
        default_factory=tuple,
        description="Recommended safe next steps from the policy allowlist.",
    )
    uncertainty_notes: str = Field(
        default="",
        description="Discussion of uncertainties, gaps, or caveats in the evidence.",
    )
    metadata: ReportMetadata = Field(
        description=(
            "Provenance metadata including provider, model, prompt version, "
            "and timestamp."
        ),
    )
    is_fallback: bool = Field(
        default=False,
        description=("Visible flag indicating a local rules-only fallback report."),
    )
    fallback_reason: str | None = Field(
        default=None,
        description="Reason for falling back to local rules-only mode, if applicable.",
    )
