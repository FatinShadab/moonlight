"""ReportProvider protocol and implementations: Mock, OllamaCloud, Meta."""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from moonlight.minimizer.models import ModelPayload
from moonlight.reasoning.models import Report
from moonlight.reasoning.prompting import PROMPT_VERSION

ProviderType = Literal["mock", "ollama-cloud", "meta"]

_DEFAULT_FIXTURES_DIR = Path(__file__).resolve().parents[3] / "fixtures" / "reports"


@runtime_checkable
class ReportProvider(Protocol):
    """Protocol for providers that perform reasoning over minimized payloads."""

    def investigate(
        self,
        minimized_payload: ModelPayload | dict[str, Any] | str,
        *,
        repair_instruction: str | None = None,
    ) -> Report:
        """Produce an investigation report from a minimized evidence payload.

        Args:
            minimized_payload: The minimized evidence payload.
            repair_instruction: Optional feedback from prior failed validation.

        Returns:
            A schema-validated Report.
        """
        ...


class MockProvider:
    """Offline mock provider that replays reports from fixtures/reports/."""

    def __init__(
        self,
        fixtures_dir: Path | str | None = None,
        default_fixture: str = "default.json",
        replay_sequence: (
            Sequence[Report | dict[str, Any] | str | Exception] | None
        ) = None,
    ) -> None:
        self.fixtures_dir = (
            Path(fixtures_dir) if fixtures_dir else _DEFAULT_FIXTURES_DIR
        )
        self.default_fixture = default_fixture
        self._replay_queue: list[Report | dict[str, Any] | str | Exception] = (
            list(replay_sequence) if replay_sequence is not None else []
        )

    def queue_response(
        self, response: Report | dict[str, Any] | str | Exception
    ) -> None:
        """Enqueue a canned response or exception for successive calls."""
        self._replay_queue.append(response)

    def investigate(
        self,
        minimized_payload: ModelPayload | dict[str, Any] | str,
        *,
        repair_instruction: str | None = None,
    ) -> Report:
        """Replay a report from the replay queue or fixtures directory."""
        if self._replay_queue:
            item = self._replay_queue.pop(0)
            if isinstance(item, Exception):
                raise item
            if isinstance(item, Report):
                return item
            if isinstance(item, dict):
                return Report.model_validate(item)
            if isinstance(item, str):
                return Report.model_validate_json(item)

        if not self.fixtures_dir.exists():
            raise FileNotFoundError(
                f"Mock reports directory not found: {self.fixtures_dir}"
            )

        target_file: Path | None = None

        if repair_instruction:
            candidate_repair = self.fixtures_dir / "repair_report.json"
            if candidate_repair.exists():
                target_file = candidate_repair

        if target_file is None:
            subject: str | None = None
            if (
                isinstance(minimized_payload, ModelPayload)
                and minimized_payload.untrusted_evidence
            ):
                subject = minimized_payload.untrusted_evidence[0].subject
            elif (
                isinstance(minimized_payload, dict)
                and "untrusted_evidence" in minimized_payload
            ):
                bundles = minimized_payload["untrusted_evidence"]
                if (
                    isinstance(bundles, list)
                    and bundles
                    and isinstance(bundles[0], dict)
                ):
                    subject = str(bundles[0].get("subject", ""))

            if subject:
                candidate_subject = self.fixtures_dir / f"{subject}.json"
                if candidate_subject.exists():
                    target_file = candidate_subject

        if target_file is None:
            target_file = self.fixtures_dir / self.default_fixture

        if not target_file.exists():
            json_files = list(self.fixtures_dir.glob("*.json"))
            if json_files:
                target_file = json_files[0]
            else:
                raise FileNotFoundError(
                    f"No fixture report found in {self.fixtures_dir} "
                    f"(looked for {self.default_fixture})"
                )

        content = target_file.read_text(encoding="utf-8")
        return Report.model_validate_json(content)


class OllamaCloudProvider:
    """Offline placeholder for Ollama Cloud provider."""

    def investigate(
        self,
        minimized_payload: ModelPayload | dict[str, Any] | str,
        *,
        repair_instruction: str | None = None,
    ) -> Report:
        raise NotImplementedError(
            "OllamaCloudProvider is not implemented in offline mode"
        )


class MetaProvider:
    """Offline placeholder for Meta Model API provider."""

    def investigate(
        self,
        minimized_payload: ModelPayload | dict[str, Any] | str,
        *,
        repair_instruction: str | None = None,
    ) -> Report:
        raise NotImplementedError("MetaProvider is not implemented in offline mode")


class ReasoningConfig(BaseModel):
    """Configuration for AI reasoning layer and provider selection."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    provider: ProviderType = Field(
        default="mock",
        description="Reasoning provider to use: 'mock', 'ollama-cloud', or 'meta'.",
    )
    model: str = Field(
        default="mock-model",
        description="Model name or identifier.",
    )
    fixtures_dir: Path | None = Field(
        default=None,
        description="Optional override directory for MockProvider reports.",
    )
    default_fixture: str = Field(
        default="default.json",
        description="Default fixture file name for MockProvider.",
    )
    prompt_version: str = Field(
        default=PROMPT_VERSION,
        description="Semantic version of prompt templates.",
    )


def get_provider(
    config: ReasoningConfig | None = None,
    provider: ProviderType | str | None = None,
    **kwargs: Any,
) -> ReportProvider:
    """Select and instantiate a ReportProvider based on configuration or environment.

    Precedence:
    1. Explicit `provider` argument
    2. `config.provider`
    3. `PROVIDER` environment variable
    4. Default: "mock"
    """
    selected: str = (
        provider
        or (config.provider if config else None)
        or os.environ.get("PROVIDER")
        or "mock"
    ).lower()

    if selected == "mock":
        fixtures_dir = kwargs.get("fixtures_dir") or (
            config.fixtures_dir if config else None
        )
        default_fixture = kwargs.get("default_fixture") or (
            config.default_fixture if config else "default.json"
        )
        return MockProvider(fixtures_dir=fixtures_dir, default_fixture=default_fixture)
    if selected == "ollama-cloud":
        return OllamaCloudProvider()
    if selected == "meta":
        return MetaProvider()

    raise ValueError(
        f"Unknown reasoning provider '{selected}'. "
        "Supported providers: mock, ollama-cloud, meta."
    )
