"""Harmless Windows disk-link decoy with bounded dummy writes."""

from __future__ import annotations

import argparse
import math
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Literal

Mode = Literal["hold", "reopen"]
CHUNK = b"0" * (1024 * 1024)
INTERVAL_SECONDS = 0.4
DURATION_SECONDS = 60.0
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MIN_FREE_BYTES = 1024 * 1024 * 1024


def run_decoy(parent: Path, mode: Mode, max_bytes: int, seconds: float) -> int:
    """Write bounded dummy data in a temporary folder and remove it on exit."""
    with tempfile.TemporaryDirectory(prefix="disk-link-decoy-", dir=parent) as name:
        folder = Path(name)
        if shutil.disk_usage(folder).free < MIN_FREE_BYTES:
            raise SystemExit(
                "Disk-link decoy needs at least 1 GiB free on the target drive."
            )

        target = folder / "dummy.bin"
        print(folder, flush=True)
        print(os.getpid(), flush=True)
        deadline = time.monotonic() + seconds
        total_bytes = 0

        if mode == "hold":
            with target.open("ab", buffering=0) as output:
                while total_bytes < max_bytes and time.monotonic() < deadline:
                    total_bytes += output.write(CHUNK[: max_bytes - total_bytes])
                    time.sleep(
                        min(INTERVAL_SECONDS, max(0.0, deadline - time.monotonic()))
                    )
        else:
            while total_bytes < max_bytes and time.monotonic() < deadline:
                with target.open("ab", buffering=0) as output:
                    total_bytes += output.write(CHUNK[: max_bytes - total_bytes])
                time.sleep(min(INTERVAL_SECONDS, max(0.0, deadline - time.monotonic())))
        return total_bytes


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent", type=Path, required=True)
    parser.add_argument("--mode", choices=("hold", "reopen"), required=True)
    parser.add_argument("--max-bytes", type=int, default=MAX_TOTAL_BYTES)
    parser.add_argument("--seconds", type=float, default=DURATION_SECONDS)
    args = parser.parse_args()
    if args.max_bytes <= 0:
        parser.error("--max-bytes must be positive")
    if not math.isfinite(args.seconds) or args.seconds <= 0:
        parser.error("--seconds must be a positive finite number")
    mode: Mode = args.mode
    run_decoy(args.parent, mode, args.max_bytes, args.seconds)


if __name__ == "__main__":
    main()
