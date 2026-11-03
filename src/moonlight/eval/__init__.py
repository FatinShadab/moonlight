"""Evaluation helpers, benchmarks, metrics, and labeled scenarios."""

from __future__ import annotations

from moonlight.eval.harness import KNOWN_ENGINE_DISAGREEMENTS, run_offline_eval
from moonlight.eval.models import (
    EvaluationResult,
    OfflineEvaluationReport,
    ScenarioEvaluationRow,
)
from moonlight.eval.scenarios import (
    ApiFailureScenario,
    ProcessCategory,
    ProcessScenario,
    ProcessTier,
    ScenarioType,
    StorageCategory,
    StorageScenario,
    load_all_scenarios,
    load_api_failure_scenarios,
    load_expected_reports,
    load_injection_scenarios,
    load_process_scenarios,
    load_storage_scenarios,
)

__all__ = [
    "ApiFailureScenario",
    "EvaluationResult",
    "KNOWN_ENGINE_DISAGREEMENTS",
    "OfflineEvaluationReport",
    "ProcessCategory",
    "ProcessScenario",
    "ProcessTier",
    "ScenarioEvaluationRow",
    "ScenarioType",
    "StorageCategory",
    "StorageScenario",
    "load_all_scenarios",
    "load_api_failure_scenarios",
    "load_expected_reports",
    "load_injection_scenarios",
    "load_process_scenarios",
    "load_storage_scenarios",
    "run_offline_eval",
]
