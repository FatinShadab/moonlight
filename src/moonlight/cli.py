"""JSON process collection and local storage investigation, without actions."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from moonlight.collectors.bundle import collect_evidence
from moonlight.collectors.process import CollectionError
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
    storage = commands.add_parser(
        "storage", help="explain selected disk usage read-only"
    )
    storage.add_argument("--root", action="append", required=True)
    storage.add_argument(
        "--snapshots", required=True, help="SQLite path outside scan roots"
    )
    args = parser.parse_args(argv)
    if args.command == "storage":
        try:
            report = investigate_storage(args.root, args.snapshots)
        except ValueError as error:
            parser.error(str(error))
        print(report.model_dump_json(indent=2, ensure_ascii=True))
        return 0 if report.snapshot_saved else 1
    result = collect_evidence(args.pid)
    # ASCII JSON also works when Windows redirects stdout using a legacy codepage.
    print(result.model_dump_json(indent=2, ensure_ascii=True))
    return 1 if isinstance(result, CollectionError) else 0
