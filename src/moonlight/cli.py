"""JSON process collection and local storage investigation, without actions."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from pydantic import TypeAdapter

from moonlight.collectors.bundle import collect_evidence
from moonlight.collectors.process import CollectionError
from moonlight.core.evidence import EvidenceBundle
from moonlight.minimizer import MinimizerSettings, PrivacyContext, minimize_evidence
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
    args = parser.parse_args(argv)
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
