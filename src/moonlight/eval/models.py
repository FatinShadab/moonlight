"""Evaluation result models recording model provider provenance."""

from __future__ import annotations

from typing import Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class EvaluationResult(BaseModel):
    """Schema-validated evaluation result capturing model and provider provenance."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    eval_name: str = Field(
        min_length=1,
        description="Name or identifier of the evaluation benchmark or scenario.",
    )
    provider: str = Field(
        min_length=1,
        description=(
            "Reasoning provider used during evaluation "
            "(e.g. 'ollama-cloud', 'mock', 'meta')."
        ),
    )
    model: str = Field(
        min_length=1,
        description="Model identifier or engine name used during evaluation.",
    )
    timestamp: AwareDatetime = Field(
        description="Timezone-aware timestamp when this evaluation was executed.",
    )
    passed: bool = Field(
        description="Whether the evaluation criteria were satisfied.",
    )
    metrics: dict[str, Any] = Field(
        default_factory=dict,
        description="Numeric or categorical evaluation metrics and scores.",
    )
    notes: str = Field(
        default="",
        description="Optional evaluation commentary, details, or reproduction notes.",
    )


class ScenarioEvaluationRow(BaseModel):
    """Granular per-scenario evaluation record with provider and model provenance."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_id: str = Field(
        min_length=1, description="Unique scenario or test case identifier."
    )
    suite: str = Field(min_length=1, description="Evaluation suite or category name.")
    provider: str = Field(
        min_length=1, description="Evaluator provider or engine name."
    )
    model: str = Field(
        min_length=1,
        description="Model identifier or engine version (mock results labeled).",
    )
    is_mock: bool = Field(
        default=False,
        description="Whether this result was produced by a mock provider or fixture.",
    )
    passed: bool = Field(description="Whether this specific test passed.")
    expected: str = Field(
        default="", description="Expected verdict, tier, or behavior."
    )
    actual: str = Field(default="", description="Observed verdict, tier, or behavior.")
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Detailed scenario indicators, scores, and diagnostics.",
    )


class OfflineEvaluationReport(BaseModel):
    """Aggregated offline evaluation output document."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    timestamp: AwareDatetime = Field(
        description="Timezone-aware execution timestamp in UTC."
    )
    overall_passed: bool = Field(
        description="Whether all mandatory evaluation assertions succeeded."
    )
    total_scenarios_evaluated: int = Field(
        ge=0, description="Total count of scenarios and test cases executed."
    )
    total_passed: int = Field(ge=0, description="Total passed cases.")
    total_failed: int = Field(ge=0, description="Total failed cases.")
    suite_summaries: list[EvaluationResult] = Field(
        default_factory=list, description="Per-suite aggregated evaluation metrics."
    )
    scenario_rows: list[ScenarioEvaluationRow] = Field(
        default_factory=list,
        description="Row-level evaluation results capturing provider/model provenance.",
    )
    metrics: dict[str, Any] = Field(
        default_factory=dict,
        description="Global summary metrics dictionary for machine readability.",
    )
