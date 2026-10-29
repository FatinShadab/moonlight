"""Harmless Windows process decoy for live collection and rule checks.

Safety:
- Bounded execution duration (capped at 60 seconds).
- Strictly local temporary directory with guaranteed cleanup on exit.
- Zero network activity, zero persistence, zero registry modifications.
- Harmless synthetic dummy bytes only.
"""

from __future__ import annotations

import argparse
import math
import os
import tempfile
import time
from pathlib import Path
from typing import Literal

DecoyMode = Literal["idler", "temp_writer", "renamed_copy"]
MAX_DURATION_SECONDS = 60.0
MAX_WRITE_BYTES = 10 * 1024 * 1024  # 10 MiB safety cap


def run_process_decoy(
    parent: Path | None,
    mode: DecoyMode,
    seconds: float = 5.0,
    max_bytes: int = 64 * 1024,
) -> int:
    """Run a harmless bounded decoy process and clean up temporary files on exit."""
    bounded_seconds = min(max(0.1, seconds), MAX_DURATION_SECONDS)
    bounded_bytes = min(max(1024, max_bytes), MAX_WRITE_BYTES)

    with tempfile.TemporaryDirectory(prefix="harmless-decoy-", dir=parent) as tmp_name:
        folder = Path(tmp_name)
        pid = os.getpid()

        print(folder, flush=True)
        print(pid, flush=True)

        if mode == "idler":
            time.sleep(bounded_seconds)
            return 0

        if mode == "temp_writer":
            target = folder / "dummy_activity.bin"
            written = 0
            chunk = b"X" * min(4096, bounded_bytes)
            with target.open("wb") as f:
                while written < bounded_bytes:
                    to_write = min(len(chunk), bounded_bytes - written)
                    f.write(chunk[:to_write])
                    written += to_write
            time.sleep(bounded_seconds)
            return written

        if mode == "renamed_copy":
            # Harmless benign decoy file inside temp folder
            decoy_file = folder / "svchost_decoy.txt"
            decoy_file.write_text(
                "Harmless synthetic test decoy file for process path verification.\n",
                encoding="utf-8",
            )
            time.sleep(bounded_seconds)
            return 1

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=("idler", "temp_writer", "renamed_copy"),
        default="idler",
        help="Decoy behavior mode (default: idler).",
    )
    parser.add_argument(
        "--parent",
        type=Path,
        default=None,
        help="Optional parent directory for the temporary folder.",
    )
    parser.add_argument(
        "--seconds",
        type=float,
        default=5.0,
        help="Duration in seconds before exiting (max: 60s).",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=64 * 1024,
        help="Maximum dummy bytes to write (max: 10 MiB).",
    )
    args = parser.parse_args()

    if not math.isfinite(args.seconds) or args.seconds <= 0:
        parser.error("--seconds must be a positive finite number")
    if args.max_bytes <= 0:
        parser.error("--max-bytes must be positive")

    mode: DecoyMode = args.mode
    run_process_decoy(args.parent, mode, args.seconds, args.max_bytes)


if __name__ == "__main__":
    main()
