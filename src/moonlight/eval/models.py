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
