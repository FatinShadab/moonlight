"""Reproducible labeled test scenario models and loaders.

Supports:
- Process scenarios (common benign, benign-but-odd, simulated suspicious)
- Storage scenarios (clearly safe, review first, do not touch)
- Injection scenarios (untrusted prompt injection defenses)
- API failure scenarios (timeouts, malformed outputs, ungrounded citations)
- Expected report fixtures for offline and mock reasoning validation
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from moonlight.core.evidence import EvidenceBundle
from moonlight.reasoning.models import Report

ProcessCategory = Literal["common_benign", "benign_but_odd", "simulated_suspicious"]
ProcessTier = Literal["low", "review", "high", "inconclusive"]
StorageCategory = Literal["clearly_safe", "review_first", "do_not_touch"]
ApiFailureType = Literal[
    "timeout", "malformed_output", "ungrounded_output", "off_allowlist_action"
]

_DEFAULT_SCENARIOS_DIR = Path(__file__).resolve().parents[3] / "fixtures" / "scenarios"
_DEFAULT_REPORTS_DIR = Path(__file__).resolve().parents[3] / "fixtures" / "reports"


class ProcessScenario(BaseModel):
    """A labeled process scenario with synthetic evidence and expected risk tier."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(min_length=1, description="Unique identifier for the scenario.")
    category: ProcessCategory = Field(
        description=(
            "Process category: common_benign, benign_but_odd, or simulated_suspicious."
        )
    )
    description: str = Field(
        min_length=1, description="Human-readable description of the scenario."
    )
    expected_tier: ProcessTier = Field(
        description="Expected risk tier verdict: low, review, high, or inconclusive."
    )
    expected_findings: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Rule IDs expected to trigger during rule evaluation.",
    )
    bundle: EvidenceBundle = Field(
        description="Synthetic evidence bundle for this process."
    )
    is_injection: bool = Field(
        default=False,
        description=(
            "Whether this scenario contains prompt injection attempts in evidence."
        ),
    )
    injection_text: str | None = Field(
        default=None,
        description="The instruction-like injection string present in the evidence.",
    )
    notes: str = Field(
        default="", description="Optional analyst notes and classification rationale."
    )


class StorageScenario(BaseModel):
    """A labeled storage scenario with synthetic evidence and expected category."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(min_length=1, description="Unique identifier for the scenario.")
    category: StorageCategory = Field(
        description=(
            "Expected storage category: clearly_safe, review_first, or do_not_touch."
        )
    )
    description: str = Field(
        min_length=1, description="Human-readable description of the scenario."
    )
    target_path: str = Field(
        min_length=1, description="Target filesystem path for the scenario."
    )
    bundle: EvidenceBundle = Field(
        description="Synthetic evidence bundle for this storage location."
    )
    is_injection: bool = Field(
        default=False,
        description=(
            "Whether this scenario contains prompt injection attempts in evidence."
        ),
    )
    injection_text: str | None = Field(
        default=None,
        description="The instruction-like injection string present in the evidence.",
    )
    notes: str = Field(
        default="", description="Optional analyst notes and classification rationale."
    )


class ApiFailureScenario(BaseModel):
    """A scenario simulating AI provider failures and testing fallback reports."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(min_length=1, description="Unique identifier for the scenario.")
    failure_type: ApiFailureType = Field(
        description=(
            "Type of simulated failure: timeout, malformed_output, "
            "ungrounded_output, or off_allowlist_action."
        )
    )
    description: str = Field(
        min_length=1, description="Human-readable description of the failure test."
    )
    bundle: EvidenceBundle = Field(
        description="Synthetic evidence bundle fed into the reasoning layer."
    )
    simulated_response: Any = Field(
        default=None,
        description=(
            "Canned raw provider response or exception for MockProvider replay."
        ),
    )
    expected_fallback: bool = Field(
        default=True,
        description="Whether the orchestrator must fall back to rules-only mode.",
    )
    expected_fallback_reason_substring: str = Field(
        default="",
        description="Substring expected in Report.fallback_reason.",
    )


ScenarioType = ProcessScenario | StorageScenario | ApiFailureScenario


def load_process_scenarios(
    scenarios_dir: Path | str | None = None,
) -> list[ProcessScenario]:
    """Load all labeled process scenarios from fixtures/scenarios/process/."""
    base_dir = Path(scenarios_dir) if scenarios_dir else _DEFAULT_SCENARIOS_DIR
    target_dir = base_dir / "process"
    if not target_dir.exists():
        return []

    scenarios: list[ProcessScenario] = []
    for file_path in sorted(target_dir.glob("*.json")):
        content = file_path.read_text(encoding="utf-8")
        data = json.loads(content)
        scenarios.append(ProcessScenario.model_validate(data))
    return scenarios


def load_storage_scenarios(
    scenarios_dir: Path | str | None = None,
) -> list[StorageScenario]:
    """Load all labeled storage scenarios from fixtures/scenarios/storage/."""
    base_dir = Path(scenarios_dir) if scenarios_dir else _DEFAULT_SCENARIOS_DIR
    target_dir = base_dir / "storage"
    if not target_dir.exists():
        return []

    scenarios: list[StorageScenario] = []
    for file_path in sorted(target_dir.glob("*.json")):
        content = file_path.read_text(encoding="utf-8")
        data = json.loads(content)
        scenarios.append(StorageScenario.model_validate(data))
    return scenarios


def load_injection_scenarios(
    scenarios_dir: Path | str | None = None,
) -> list[ProcessScenario | StorageScenario]:
    """Load all prompt injection test scenarios from fixtures/scenarios/injection/."""
    base_dir = Path(scenarios_dir) if scenarios_dir else _DEFAULT_SCENARIOS_DIR
    target_dir = base_dir / "injection"
    if not target_dir.exists():
        return []

    scenarios: list[ProcessScenario | StorageScenario] = []
    for file_path in sorted(target_dir.glob("*.json")):
        content = file_path.read_text(encoding="utf-8")
        data = json.loads(content)
        if "category" in data and data["category"] in (
            "common_benign",
            "benign_but_odd",
            "simulated_suspicious",
        ):
            scenarios.append(ProcessScenario.model_validate(data))
        else:
            scenarios.append(StorageScenario.model_validate(data))
    return scenarios


def load_api_failure_scenarios(
    scenarios_dir: Path | str | None = None,
) -> list[ApiFailureScenario]:
    """Load all API failure test scenarios from fixtures/scenarios/api_failure/."""
    base_dir = Path(scenarios_dir) if scenarios_dir else _DEFAULT_SCENARIOS_DIR
    target_dir = base_dir / "api_failure"
    if not target_dir.exists():
        return []

    scenarios: list[ApiFailureScenario] = []
    for file_path in sorted(target_dir.glob("*.json")):
        content = file_path.read_text(encoding="utf-8")
        data = json.loads(content)
        scenarios.append(ApiFailureScenario.model_validate(data))
    return scenarios


def load_all_scenarios(
    scenarios_dir: Path | str | None = None,
) -> list[ProcessScenario | StorageScenario | ApiFailureScenario]:
    """Load all scenarios across process, storage, injection, and API failure sets."""
    all_items: list[ProcessScenario | StorageScenario | ApiFailureScenario] = []
    all_items.extend(load_process_scenarios(scenarios_dir))
    all_items.extend(load_storage_scenarios(scenarios_dir))
    all_items.extend(load_injection_scenarios(scenarios_dir))
    all_items.extend(load_api_failure_scenarios(scenarios_dir))
    return all_items


def load_expected_reports(
    reports_dir: Path | str | None = None,
) -> dict[str, Report]:
    """Load all expected report fixtures keyed by scenario ID / file stem."""
    target_dir = Path(reports_dir) if reports_dir else _DEFAULT_REPORTS_DIR
    if not target_dir.exists():
        return {}

    reports: dict[str, Report] = {}
    for file_path in sorted(target_dir.glob("*.json")):
        # Skip special test report files
        if file_path.name in (
            "malformed_report.json",
            "off_allowlist_report.json",
            "repair_report.json",
            "ungrounded_report.json",
        ):
            continue
        try:
            content = file_path.read_text(encoding="utf-8")
            reports[file_path.stem] = Report.model_validate_json(content)
        except Exception:
            pass
    return reports
