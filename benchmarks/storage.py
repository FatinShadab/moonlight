"""Reproducible synthetic-tree benchmark; writes only a new explicit workspace."""

from __future__ import annotations

import argparse
import json
import platform
import statistics
from pathlib import Path
from time import perf_counter

from moonlight.core.evidence import EvidenceKind
from moonlight.storage.investigator import investigate_storage


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    args = parser.parse_args()
    workspace: Path = args.workspace.absolute()
    if workspace.exists():
        parser.error("benchmark workspace must not already exist")
    workspace.mkdir()
    root = workspace / "tree"
    root.mkdir()
    for bucket in range(40):
        folder = root / f"bucket-{bucket:03d}"
        folder.mkdir()
        for entry in range(25):
            index = bucket * 25 + entry
            (folder / f"file-{index:04d}.bin").write_bytes(
                bytes([index % 256]) * (1024 + index)
            )
    for index in range(8):
        (root / f"duplicate-{index:02d}.bin").write_bytes(b"x" * 32768)
    durations: list[float] = []
    for _ in range(3):
        start = perf_counter()
        report = investigate_storage([str(root)], str(workspace / "snapshots.sqlite3"))
        durations.append(perf_counter() - start)
        assert report.snapshot_saved
        assert report.hash_candidates == report.files_hashed == 8
        assert all(
            item.availability == "observed"
            for bundle in report.bundles
            for item in bundle.items
            if item.kind == EvidenceKind.FOLDER_SIZE
        )
    result = {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "files": 1008,
        "directories": 41,
        "logical_bytes": 1785644,
        "duplicate_candidates": report.hash_candidates,
        "files_hashed_per_scan": report.files_hashed,
        "seconds": durations,
        "median_seconds": statistics.median(durations),
        "includes": (
            "enumeration, metadata, helper startup/hashing, SQLite, classification"
        ),
        "excludes": "fixture creation and JSON serialization",
        "cache_note": "three consecutive scans; filesystem cache not cleared",
    }
    (workspace / "timing.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
