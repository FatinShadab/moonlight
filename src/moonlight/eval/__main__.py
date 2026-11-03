"""Command-line entry point for running offline Moonlight evaluations.

Usage:
    python -m moonlight.eval --offline
    python -m moonlight.eval --offline --output-dir results
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from moonlight.eval.harness import run_offline_eval


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m moonlight.eval",
        description="Offline evaluation benchmarks without live model calls.",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        default=True,
        help="Run all scenarios offline using local engines (default: True).",
    )
    parser.add_argument(
        "--provider",
        choices=["mock", "ollama", "meta"],
        default="mock",
        help="Reasoning provider to evaluate: mock (default), ollama, or meta.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results"),
        help="Directory to write results (default: results/).",
    )
    parser.add_argument(
        "--json-file",
        default="eval_results.json",
        help="Output filename for JSON results (default: eval_results.json).",
    )
    parser.add_argument(
        "--markdown-file",
        default="RESULTS.md",
        help="Output filename for Markdown report (default: RESULTS.md).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress summary output to stdout.",
    )

    args = parser.parse_args(argv)

    if not args.offline:
        print(
            "Error: Currently only --offline evaluation is supported.",
            file=sys.stderr,
        )
        return 1

    report = run_offline_eval(
        output_dir=args.output_dir,
        json_filename=args.json_file,
        markdown_filename=args.markdown_file,
        provider=args.provider,
    )

    if not args.quiet:
        p_m = report.metrics.get("process_rules", {})
        s_m = report.metrics.get("storage_rules", {})
        pol_m = report.metrics.get("policy_layer", {})
        g_m = report.metrics.get("mock_grounding", {})
        f_m = report.metrics.get("fallback_behavior", {})

        verdict = "PASSED" if report.overall_passed else "FAILED"
        print("=" * 60)
        print("Moonlight Offline Evaluation Suite Summary")
        print("=" * 60)
        print(f"Total Scenarios Evaluated : {report.total_scenarios_evaluated}")
        print(f"Total Passed              : {report.total_passed}")
        print(f"Total Failed              : {report.total_failed}")
        print(f"Overall Status            : {verdict}")
        print("-" * 60)
        print(f"Process Precision         : {p_m.get('precision', 0.0):.2%}")
        print(f"Process Recall            : {p_m.get('recall', 0.0):.2%}")
        print(f"Process FPR               : {p_m.get('false_positive_rate', 0.0):.2%}")
        print(f"Process FNR               : {p_m.get('false_negative_rate', 0.0):.2%}")
        dang = s_m.get("dangerous_misclassification_count", -1)
        print(f"Storage Dangerous Misclass: {dang} (target: 0)")
        pol_rej = pol_m.get("overall_rejection_rate", 0.0)
        print(f"Policy Rejection Rate     : {pol_rej:.2%}")
        pol_uns = pol_m.get("unsafe_rejection_rate", 0.0)
        print(f"Policy Unsafe Block Rate  : {pol_uns:.2%}")
        grnd = g_m.get("grounding_validity_rate", 0.0)
        print(f"Mock Grounding Validity   : {grnd:.2%}")
        fb_rate = f_m.get("fallback_rate", 0.0)
        print(f"API Fallback Rate         : {fb_rate:.2%}")
        print("=" * 60)
        out_json = args.output_dir / args.json_file
        out_md = args.output_dir / args.markdown_file
        print(f"Results written to: {out_json} and {out_md}")

    return 0 if report.overall_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
