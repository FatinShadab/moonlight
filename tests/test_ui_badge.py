"""Tests for UI provider badge and evaluation models."""

from __future__ import annotations

import os
from datetime import UTC, datetime

# Ensure PySide6 runs headlessly in offscreen mode
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtWidgets import QApplication

from moonlight.core.evidence import EvidenceKind, make_evidence_id
from moonlight.eval.models import EvaluationResult
from moonlight.reasoning.models import (
    ObservedFact,
    RecommendedAction,
    Report,
    ReportMetadata,
)
from moonlight.ui.badge import (
    CLOUD_PLACEHOLDER_BADGE_TEXT,
    ProviderBadgeWidget,
    get_provider_badge,
)
from moonlight.ui.review import ReportReviewWidget


def test_get_provider_badge_logic() -> None:
    # Non-meta providers must always display the cloud placeholder model badge
    assert get_provider_badge("ollama-cloud") == CLOUD_PLACEHOLDER_BADGE_TEXT
    assert get_provider_badge("mock") == CLOUD_PLACEHOLDER_BADGE_TEXT
    assert get_provider_badge("rules_only_fallback") == CLOUD_PLACEHOLDER_BADGE_TEXT
    assert get_provider_badge("unknown") == CLOUD_PLACEHOLDER_BADGE_TEXT
    assert get_provider_badge(None) == CLOUD_PLACEHOLDER_BADGE_TEXT

    # The final production system uses MetaProvider; only meta has no placeholder badge
    assert get_provider_badge("meta") is None
    assert get_provider_badge("Meta") is None
    assert get_provider_badge("META") is None


def test_provider_badge_widget(qapp: QApplication) -> None:
    badge = ProviderBadgeWidget(provider="ollama-cloud")
    assert badge.text() == CLOUD_PLACEHOLDER_BADGE_TEXT
    assert badge.isVisible() is True

    # Switching to meta hides the badge
    badge.update_provider("meta")
    assert badge.text() == ""
    assert badge.isVisible() is False

    # Switching back to mock or ollama-cloud displays the badge again
    badge.update_provider("mock")
    assert badge.text() == CLOUD_PLACEHOLDER_BADGE_TEXT
    assert badge.isVisible() is True

    badge.close()
    badge.deleteLater()
    qapp.processEvents()


def test_report_review_widget_with_badge(qapp: QApplication) -> None:
    ev_id = make_evidence_id("process", "1", "collector", EvidenceKind.EXECUTABLE_PATH)
    timestamp = datetime.now(UTC)

    # Report from ollama-cloud
    ollama_report = Report(
        summary="Test investigation summary",
        risk_tier="low",
        confidence=0.9,
        observed_facts=(ObservedFact(text="Fact 1", evidence_ids=(ev_id,)),),
        recommended_actions=(
            RecommendedAction(
                action_id="mark_reviewed", reason="Looks safe", evidence_ids=(ev_id,)
            ),
        ),
        metadata=ReportMetadata(
            provider="ollama-cloud",
            model="gemma4:31b",
            prompt_version="1.0.0",
            timestamp=timestamp,
        ),
    )

    review_widget = ReportReviewWidget(ollama_report)
    review_widget.show()
    assert review_widget.badge_widget.isVisible() is True
    assert review_widget.badge_widget.text() == CLOUD_PLACEHOLDER_BADGE_TEXT

    # Report from meta provider
    meta_report = Report(
        summary="Meta production investigation summary",
        risk_tier="low",
        confidence=0.95,
        observed_facts=(ObservedFact(text="Fact 1", evidence_ids=(ev_id,)),),
        recommended_actions=(
            RecommendedAction(
                action_id="mark_reviewed", reason="Looks safe", evidence_ids=(ev_id,)
            ),
        ),
        metadata=ReportMetadata(
            provider="meta",
            model="meta-llama-3.3-70b-instruct",
            prompt_version="1.0.0",
            timestamp=timestamp,
        ),
    )

    review_widget.set_report(meta_report)
    assert review_widget.badge_widget.isVisible() is False
    assert review_widget.badge_widget.text() == ""

    review_widget.close()
    review_widget.deleteLater()
    qapp.processEvents()


def test_evaluation_result_records_provider_and_model() -> None:
    timestamp = datetime.now(UTC)
    eval_res = EvaluationResult(
        eval_name="p7a_reasoning_benchmark",
        provider="ollama-cloud",
        model="gemma4:31b",
        timestamp=timestamp,
        passed=True,
        metrics={"grounding_rate": 1.0, "schema_validity": 1.0},
        notes="Evaluated against temporary development placeholder provider",
    )

    assert eval_res.provider == "ollama-cloud"
    assert eval_res.model == "gemma4:31b"
    assert eval_res.passed is True
    assert eval_res.metrics["grounding_rate"] == 1.0

    # Verify JSON serialization preserves provider and model
    data = eval_res.model_dump()
    assert data["provider"] == "ollama-cloud"
    assert data["model"] == "gemma4:31b"
