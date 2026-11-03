"""Tests for the offline evaluation harness and benchmark reporting."""

from __future__ import annotations

from pathlib import Path

from moonlight.eval.__main__ import main as eval_main
from moonlight.eval.harness import run_offline_eval
from moonlight.eval.models import OfflineEvaluationReport


def test_offline_eval_run_and_schema(tmp_path: Path) -> None:
    """Offline evaluation runs to completion and writes validated JSON and Markdown."""
    report = run_offline_eval(output_dir=tmp_path)
    assert report.overall_passed is True
    assert report.total_scenarios_evaluated >= 140
    assert report.total_failed == 0
    assert report.total_passed == report.total_scenarios_evaluated

    json_file = tmp_path / "eval_results.json"
    md_file = tmp_path / "RESULTS.md"

    assert json_file.exists()
    assert md_file.exists()

    # Verify JSON deserializes cleanly into OfflineEvaluationReport
    content = json_file.read_text(encoding="utf-8")
    loaded = OfflineEvaluationReport.model_validate_json(content)
    assert loaded.overall_passed is True
    assert len(loaded.scenario_rows) == report.total_scenarios_evaluated

    # Verify Markdown contains summary headers and Mermaid chart
    md_text = md_file.read_text(encoding="utf-8")
    assert "# Moonlight Offline Evaluation Results" in md_text
    assert "```mermaid" in md_text
    assert "MUST BE ZERO" in md_text
    assert "No Antivirus Claims" in md_text


def test_storage_zero_dangerous_misclassifications(tmp_path: Path) -> None:
    """Storage evaluation must strictly have zero dangerous misclassifications."""
    report = run_offline_eval(output_dir=tmp_path)
    storage_metrics = report.metrics["storage_rules"]
    assert storage_metrics["dangerous_misclassification_count"] == 0
    assert storage_metrics["accuracy"] == 1.0
    assert storage_metrics["do_not_touch_accuracy"] == 1.0


def test_process_rules_precision_and_fpr(tmp_path: Path) -> None:
    """Process rules have 0 false positive rate and 100% precision on benign."""
    report = run_offline_eval(output_dir=tmp_path)
    p_metrics = report.metrics["process_rules"]
    assert p_metrics["false_positive_rate"] == 0.0
    assert p_metrics["false_positives"] == 0
    assert p_metrics["precision"] == 1.0
    assert p_metrics["recall"] > 0.5
    assert p_metrics["accounted_for_count"] == p_metrics["total_scenarios"]


def test_policy_rejection_metrics(tmp_path: Path) -> None:
    """Policy layer must reject 100% of dangerous actions while allowing safe ones."""
    report = run_offline_eval(output_dir=tmp_path)
    pol_metrics = report.metrics["policy_layer"]
    assert pol_metrics["unsafe_rejection_rate"] == 1.0
    assert pol_metrics["unsafe_actions_rejected"] == pol_metrics["unsafe_actions_total"]
    assert pol_metrics["overall_rejection_rate"] > 0.75
    assert pol_metrics["allowed_count"] > 0


def test_mock_provenance_and_mock_labeling(tmp_path: Path) -> None:
    """Every result row records provider and model; mock results are labeled."""
    report = run_offline_eval(output_dir=tmp_path)
    assert len(report.scenario_rows) > 0

    mock_row_count = 0
    for row in report.scenario_rows:
        assert row.provider, f"Row {row.scenario_id} missing provider"
        assert row.model, f"Row {row.scenario_id} missing model"
        if row.is_mock:
            mock_row_count += 1
            msg = f"Mock row {row.scenario_id} model '{row.model}' must be labeled mock"
            assert "(MOCK)" in row.model, msg

    assert mock_row_count > 0, "Expected mock provider evaluation rows"

    # Mock grounding validity
    g_metrics = report.metrics["mock_grounding"]
    assert g_metrics["grounding_validity_rate"] == 1.0
    assert g_metrics["violation_detection_rate"] == 1.0


def test_api_fallback_behavior(tmp_path: Path) -> None:
    """API failure scenarios must achieve 100% graceful fallback with zero crashes."""
    report = run_offline_eval(output_dir=tmp_path)
    f_metrics = report.metrics["fallback_behavior"]
    assert f_metrics["fallback_rate"] == 1.0
    assert f_metrics["unhandled_crashes"] == 0
    assert f_metrics["fallback_success_count"] == f_metrics["total_failure_scenarios"]


def test_eval_cli_offline_flag(tmp_path: Path) -> None:
    """CLI python -m moonlight.eval --offline executes successfully."""
    exit_code = eval_main(["--offline", "--output-dir", str(tmp_path), "--quiet"])
    assert exit_code == 0
    assert (tmp_path / "eval_results.json").exists()
    assert (tmp_path / "RESULTS.md").exists()
