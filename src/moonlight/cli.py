"""JSON process collection, local storage investigation, and AI reasoning scaffold."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

import httpx
from pydantic import TypeAdapter

from moonlight.collectors.bundle import collect_evidence
from moonlight.collectors.process import CollectionError
from moonlight.core.evidence import EvidenceBundle
from moonlight.minimizer import MinimizerSettings, PrivacyContext, minimize_evidence
from moonlight.minimizer.models import ModelPayload
from moonlight.policy import PolicyLayer, ProposedAction
from moonlight.reasoning import ReasoningConfig, ReasoningOrchestrator
from moonlight.rules.process import evaluate_process
from moonlight.storage.attribution import attribute_disk_growth
from moonlight.storage.attribution_models import (
    AttributionSettings,
    DiskSnapshot,
    P3Finding,
)
from moonlight.storage.disk_snapshot import capture_disk_snapshot
from moonlight.storage.investigator import investigate_storage


def _pid(value: str) -> int:
    try:
        pid = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("PID must be an integer") from error
    if pid < 0:
        raise argparse.ArgumentTypeError("PID must be non-negative")
    return pid


def check_provider(
    provider: str = "meta",
    model: str | None = None,
    base_url: str | None = None,
    timeout: float = 15.0,
    client: httpx.Client | None = None,
    api_key: str | None = None,
) -> int:
    """Run a small check call against the specified provider."""
    import time

    import httpx

    prov = provider.lower()
    if prov == "meta":
        key = (
            api_key
            or os.environ.get("MODEL_API_KEY")
            or os.environ.get("META_API_KEY")
            or os.environ.get("BASETEN_API_KEY", "")
        ).strip()
        if not key:
            print(
                "Error: MODEL_API_KEY environment variable is missing or empty.\n\n"
                "To configure the Meta Model API provider, set your API key:\n"
                "  1. In .env file:    MODEL_API_KEY=your_key_here\n"
                "  2. In environment:  export MODEL_API_KEY=your_key_here\n"
                "                      (or $env:MODEL_API_KEY='your_key_here')\n"
                "  3. In Moonlight UI: Settings -> AI Reasoning & Model Providers\n"
                "                      -> Meta Configuration -> Save Settings\n\n"
                "For OpenAI-compatible partner endpoints (e.g. Baseten):\n"
                "  MODEL_API_KEY=your_baseten_key\n"
                "  MOONLIGHT_META_BASE_URL=https://inference.baseten.co/v1\n"
                "  MOONLIGHT_META_MODEL=meta-models/muse-spark-open-1026",
                file=sys.stderr,
            )
            return 1

        target_model = (
            model
            or os.environ.get("MOONLIGHT_META_MODEL")
            or os.environ.get("META_MODEL")
            or "muse-spark-1.3"
        )
        target_base = (
            base_url
            or os.environ.get("MOONLIGHT_META_BASE_URL")
            or os.environ.get("META_BASE_URL")
            or "https://api.meta.ai/v1"
        ).rstrip("/")

        endpoint = f"{target_base}/chat/completions"
        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        }
        body = {
            "model": target_model,
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 1,
        }

        owns_client = client is None
        http_client = client or httpx.Client(timeout=timeout, follow_redirects=False)
        start = time.perf_counter()
        try:
            resp = http_client.post(endpoint, headers=headers, json=body)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            if resp.status_code == 200:
                print("Provider : meta")
                print("Status   : OK (connected)")
                print(f"Model    : {target_model}")
                print(f"Latency  : {elapsed_ms:.1f} ms")
                return 0
            err_msg = ""
            try:
                err_data = resp.json()
                if isinstance(err_data, dict):
                    err_msg = str(
                        err_data.get("error", err_data.get("message", resp.text[:200]))
                    )
            except Exception:
                err_msg = resp.text[:200]
            from moonlight.core.config import _sanitize_error_text

            safe_err = _sanitize_error_text(err_msg)
            print("Provider : meta", file=sys.stderr)
            print(
                f"Status   : FAILED ({resp.status_code}) - {safe_err}",
                file=sys.stderr,
            )
            print(f"Model    : {target_model}", file=sys.stderr)
            print(f"Latency  : {elapsed_ms:.1f} ms", file=sys.stderr)
            return 1
        except Exception as exc:
            from moonlight.core.config import _sanitize_error_text

            elapsed_ms = (time.perf_counter() - start) * 1000.0
            safe_exc = _sanitize_error_text(str(exc))
            print("Provider : meta", file=sys.stderr)
            print(f"Status   : FAILED - {safe_exc}", file=sys.stderr)
            print(f"Model    : {target_model}", file=sys.stderr)
            print(f"Latency  : {elapsed_ms:.1f} ms", file=sys.stderr)
            return 1
        finally:
            if owns_client:
                http_client.close()

    elif prov in ("ollama", "ollama-cloud"):
        from moonlight.core.config import verify_ollama_connection

        ollama_key = (api_key or os.environ.get("OLLAMA_API_KEY", "")).strip()
        target_base = (
            base_url or os.environ.get("OLLAMA_BASE_URL", "https://ollama.com")
        ).rstrip("/")
        target_model = model or os.environ.get("OLLAMA_MODEL", "gemma4:31b")
        start = time.perf_counter()
        ok, msg, _ = verify_ollama_connection(
            base_url=target_base,
            api_key=ollama_key,
            timeout=timeout,
            client=client,
        )
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        status_text = "OK (connected)" if ok else f"FAILED - {msg}"
        out = sys.stdout if ok else sys.stderr
        print(f"Provider : {prov}", file=out)
        print(f"Status   : {status_text}", file=out)
        print(f"Model    : {target_model}", file=out)
        print(f"Latency  : {elapsed_ms:.1f} ms", file=out)
        return 0 if ok else 1

    elif prov == "mock":
        print("Provider : mock")
        print("Status   : OK (offline)")
        print("Model    : mock-model")
        print("Latency  : 0.0 ms")
        return 0

    print(
        f"Unknown provider '{prov}'. Supported: meta, ollama, mock",
        file=sys.stderr,
    )
    return 1


def launch_ui(
    argv: Sequence[str] | None = None,
    mode: str | None = None,
) -> int:
    """Launch Moonlight desktop review interface."""
    from PySide6.QtWidgets import QApplication

    from moonlight.ui.window import MoonlightMainWindow

    app = QApplication.instance()
    if not isinstance(app, QApplication):
        app = QApplication(list(argv) if argv is not None else sys.argv)
    win = MoonlightMainWindow()
    if mode:
        win._set_mode(mode)
    win.show()
    return int(app.exec())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="moonlight")
    commands = parser.add_subparsers(dest="command", required=True)
    collect = commands.add_parser("collect", help="collect read-only process evidence")
    collect.add_argument("--pid", type=_pid, required=True)
    rules = commands.add_parser("rules", help="evaluate local process rules as JSON")
    rules.add_argument("--pid", type=_pid, required=True)
    storage = commands.add_parser(
        "storage", help="explain selected disk usage read-only"
    )
    storage.add_argument("--root", action="append", required=True)
    storage.add_argument(
        "--snapshots", required=True, help="SQLite path outside scan roots"
    )
    snapshot = commands.add_parser(
        "disk-snapshot", help="sample selected roots and PIDs as JSON on stdout"
    )
    snapshot.add_argument("--root", action="append", required=True)
    snapshot.add_argument("--pid", action="append", type=_pid, required=True)
    link = commands.add_parser(
        "disk-link", help="attribute growth between two JSON snapshots"
    )
    link.add_argument("--before", required=True)
    link.add_argument("--after", required=True)
    link.add_argument("--p3-findings", help="JSON array of supplied P3 findings")
    link.add_argument("--min-growth-rate", type=float, default=1024 * 1024)
    minimize = commands.add_parser(
        "minimize", help="preview minimized model JSON and a local redaction log"
    )
    minimize.add_argument(
        "--input", required=True, help="evidence bundle, array, or report JSON"
    )
    minimize.add_argument(
        "--context", help="local JSON with explicit username/hostname aliases"
    )
    minimize.add_argument("--evidence-id", action="append")
    minimize.add_argument("--max-command-chars", type=int, default=512)
    minimize.add_argument("--max-evidence-items", type=int, default=256)
    investigate_cmd = commands.add_parser(
        "investigate", help="run schema-validated investigation reasoning report"
    )
    investigate_cmd.add_argument(
        "--input", required=True, help="evidence bundle, model payload, or report JSON"
    )
    investigate_cmd.add_argument(
        "--provider", choices=["mock", "ollama", "ollama-cloud", "meta"], default=None
    )
    investigate_cmd.add_argument(
        "--fixtures-dir", help="override directory for mock fixture reports"
    )
    investigate_cmd.add_argument("--fixture", help="specific fixture report file name")
    investigate_cmd.add_argument(
        "--model", help="model name or identifier (overrides OLLAMA_MODEL)"
    )
    investigate_cmd.add_argument(
        "--base-url", help="API base URL (overrides OLLAMA_BASE_URL)"
    )
    investigate_cmd.add_argument(
        "--allow-real-evidence",
        action="store_true",
        default=False,
        help="explicitly permit sending non-fixture evidence to a non-meta provider",
    )
    investigate_cmd.add_argument(
        "--allow-custom-host",
        action="store_true",
        default=False,
        help="permit Ollama base URL with host other than ollama.com",
    )
    policy_val = commands.add_parser(
        "policy-validate", help="validate proposed action against safety policy"
    )
    policy_val.add_argument("--action-type", required=True)
    policy_val.add_argument("--target-path")
    policy_val.add_argument("--target-process")
    policy_val.add_argument("--target-pid", type=_pid)
    policy_val.add_argument("--hash-value")
    policy_val.add_argument("--target-id")
    policy_val.add_argument("--audit-log")
    policy_prev = commands.add_parser(
        "policy-preview", help="preview proposed action dry-run"
    )
    policy_prev.add_argument("--action-type", required=True)
    policy_prev.add_argument("--target-path")
    policy_prev.add_argument("--target-process")
    policy_prev.add_argument("--target-pid", type=_pid)
    policy_prev.add_argument("--hash-value")
    policy_prev.add_argument("--target-id")
    policy_prev.add_argument("--audit-log")
    policy_exec = commands.add_parser(
        "policy-execute", help="execute confirmed action through policy gates"
    )
    policy_exec.add_argument("--action-type", required=True)
    policy_exec.add_argument("--target-path")
    policy_exec.add_argument("--target-process")
    policy_exec.add_argument("--target-pid", type=_pid)
    policy_exec.add_argument("--hash-value")
    policy_exec.add_argument("--target-id")
    policy_exec.add_argument("--confirm", action="store_true", default=False)
    policy_exec.add_argument("--token", help="confirmation token returned by preview")
    policy_exec.add_argument(
        "--extra-confirm",
        "--confirm-review-first",
        dest="extra_confirm",
        action="store_true",
        default=False,
        help="explicit extra confirmation for review-first storage paths",
    )
    policy_exec.add_argument("--audit-log")
    prov_check = commands.add_parser(
        "provider-check", help="check reasoning provider health, model, and latency"
    )
    prov_check.add_argument(
        "--provider",
        choices=["meta", "ollama", "ollama-cloud", "mock"],
        default="meta",
        help="reasoning provider to check (default: meta)",
    )
    prov_check.add_argument("--model", help="model name or identifier override")
    prov_check.add_argument("--base-url", help="provider base URL override")
    prov_check.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="request timeout in seconds (default: 15.0)",
    )
    eval_cmd = commands.add_parser(
        "eval", help="run offline evaluation harness across all labeled scenarios"
    )
    eval_cmd.add_argument(
        "--offline",
        action="store_true",
        default=True,
        help="run offline evaluation harness",
    )
    eval_cmd.add_argument(
        "--output-dir",
        default="results",
        help="output directory for eval results",
    )
    ui_cmd = commands.add_parser("ui", help="launch desktop review interface")
    ui_cmd.add_argument(
        "--mode",
        choices=["replay", "live"],
        default=None,
        help="initial investigation mode ('replay' or 'live')",
    )
    args = parser.parse_args(argv)
    if args.command == "ui":
        return launch_ui(argv=argv, mode=args.mode)
    if args.command == "provider-check":
        return check_provider(
            provider=args.provider,
            model=args.model,
            base_url=args.base_url,
            timeout=args.timeout,
        )
    if args.command == "eval":
        from moonlight.eval.harness import run_offline_eval

        eval_report = run_offline_eval(output_dir=args.output_dir)
        verdict = "PASSED" if eval_report.overall_passed else "FAILED"
        print(f"Offline evaluation complete: {verdict}")
        return 0 if eval_report.overall_passed else 1
    if args.command == "investigate":
        try:
            raw = json.loads(Path(args.input).read_text(encoding="utf-8-sig"))
            if isinstance(raw, dict) and "untrusted_evidence" in raw:
                target_evidence: ModelPayload | tuple[EvidenceBundle, ...] = (
                    ModelPayload.model_validate(raw)
                )
            elif isinstance(raw, dict) and "bundles" in raw:
                bundles_val = raw["bundles"]
                target_evidence = (
                    (EvidenceBundle.model_validate(bundles_val),)
                    if isinstance(bundles_val, dict)
                    else TypeAdapter(tuple[EvidenceBundle, ...]).validate_python(
                        bundles_val
                    )
                )
            elif isinstance(raw, dict) and "items" in raw:
                target_evidence = (EvidenceBundle.model_validate(raw),)
            else:
                target_evidence = TypeAdapter(
                    tuple[EvidenceBundle, ...]
                ).validate_python(raw)
        except Exception as error:
            parser.error(f"invalid or unreadable input evidence: {error}")

        provider_name = (args.provider or os.environ.get("PROVIDER") or "mock").lower()
        input_path = Path(args.input).resolve()
        is_fixture = "fixtures" in input_path.parts
        if provider_name not in ("meta", "mock") and not is_fixture:
            if not args.allow_real_evidence:
                parser.error(
                    "Sending non-fixture or real collected evidence to non-meta "
                    "provider requires explicit --allow-real-evidence flag"
                )
            print(
                "WARNING: Sending real collected evidence to non-meta provider!",
                file=sys.stderr,
            )

        cfg = ReasoningConfig(
            provider=args.provider or "mock",
            model=args.model or "mock-model",
            ollama_model=args.model,
            ollama_base_url=args.base_url or "https://ollama.com",
            allow_custom_host=args.allow_custom_host,
            fixtures_dir=Path(args.fixtures_dir) if args.fixtures_dir else None,
            default_fixture=args.fixture or "default.json",
        )
        orchestrator = ReasoningOrchestrator(config=cfg)
        rep = orchestrator.investigate(target_evidence)
        print(rep.model_dump_json(indent=2, ensure_ascii=True))
        return 0
    if args.command == "minimize":
        try:
            raw = json.loads(Path(args.input).read_text(encoding="utf-8-sig"))
            if isinstance(raw, dict) and "bundles" in raw:
                raw = raw["bundles"]
            bundles = (
                (EvidenceBundle.model_validate(raw),)
                if isinstance(raw, dict)
                else TypeAdapter(tuple[EvidenceBundle, ...]).validate_python(raw)
            )
            privacy = (
                PrivacyContext.model_validate_json(
                    Path(args.context).read_text(encoding="utf-8-sig")
                )
                if args.context
                else PrivacyContext()
            )
            minimized_result = minimize_evidence(
                bundles,
                context=privacy,
                settings=MinimizerSettings(
                    max_command_chars=args.max_command_chars,
                    max_evidence_items=args.max_evidence_items,
                ),
                evidence_ids=frozenset(args.evidence_id) if args.evidence_id else None,
            )
        except (ValueError, OSError):
            parser.error(
                "minimization failed; no payload produced; "
                "retain local rules-only results"
            )
        print(minimized_result.model_dump_json(indent=2, ensure_ascii=True))
        return 0
    if args.command in ("policy-validate", "policy-preview", "policy-execute"):
        layer = PolicyLayer(log_path=args.audit_log)
        proposed = ProposedAction(
            action_type=args.action_type,
            target_path=args.target_path,
            target_process=args.target_process,
            target_pid=args.target_pid,
            hash_value=args.hash_value,
            target_id=args.target_id,
        )
        if args.command == "policy-validate":
            decision = layer.validate_action(proposed)
            print(decision.model_dump_json(indent=2, ensure_ascii=True))
            return 0 if decision.allowed else 1
        elif args.command == "policy-preview":
            preview = layer.preview_action(proposed)
            print(preview.model_dump_json(indent=2, ensure_ascii=True))
            return 0 if preview.allowed else 1
        else:
            preview = layer.preview_action(proposed)
            exec_result = layer.execute_action(
                proposed,
                preview=preview,
                confirmed=args.confirm,
                confirmation_token=args.token,
                extra_confirmed=args.extra_confirm,
            )
            print(exec_result.model_dump_json(indent=2, ensure_ascii=True))
            return 0 if exec_result.success else 1
    if args.command == "disk-snapshot":
        try:
            snapshot_result = capture_disk_snapshot(args.root, args.pid)
        except ValueError as error:
            parser.error(str(error))
        print(snapshot_result.model_dump_json(indent=2, ensure_ascii=True))
        return 0
    if args.command == "disk-link":
        try:
            before = DiskSnapshot.model_validate_json(
                Path(args.before).read_text(encoding="utf-8-sig")
            )
            after = DiskSnapshot.model_validate_json(
                Path(args.after).read_text(encoding="utf-8-sig")
            )
            p3 = (
                TypeAdapter(tuple[P3Finding, ...]).validate_json(
                    Path(args.p3_findings).read_text(encoding="utf-8-sig")
                )
                if args.p3_findings
                else ()
            )
            link_result = attribute_disk_growth(
                before,
                after,
                p3_findings=p3,
                settings=AttributionSettings(
                    min_growth_bytes_per_second=args.min_growth_rate
                ),
            )
        except (ValueError, OSError):
            parser.error(
                "invalid or unreadable disk snapshots, settings, or P3 findings"
            )
        print(link_result.model_dump_json(indent=2, ensure_ascii=True))
        return 0
    if args.command == "storage":
        try:
            report = investigate_storage(args.root, args.snapshots)
        except ValueError as error:
            parser.error(str(error))
        print(report.model_dump_json(indent=2, ensure_ascii=True))
        return 0 if report.snapshot_saved else 1
    result = collect_evidence(args.pid)
    if args.command == "rules" and isinstance(result, EvidenceBundle):
        print(evaluate_process(result).model_dump_json(indent=2, ensure_ascii=True))
        return 0
    # ASCII JSON also works when Windows redirects stdout using a legacy codepage.
    print(result.model_dump_json(indent=2, ensure_ascii=True))
    return 1 if isinstance(result, CollectionError) else 0
