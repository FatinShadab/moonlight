"""Harmless Windows disk-link decoy: append dummy bytes for about one minute."""

from __future__ import annotations

import argparse
import os
import tempfile
import time
from pathlib import Path
from typing import Literal

Mode = Literal["hold", "reopen"]
CHUNK = b"0" * (1024 * 1024)
INTERVAL_SECONDS = 0.4
DURATION_SECONDS = 60.0


def _write_once(path: Path) -> None:
    with path.open("ab", buffering=0) as output:
        output.write(CHUNK)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent", type=Path, required=True)
    parser.add_argument("--mode", choices=("hold", "reopen"), required=True)
    args = parser.parse_args()
    mode: Mode = args.mode
    folder = Path(tempfile.mkdtemp(prefix="disk-link-decoy-", dir=args.parent))
    target = folder / "dummy.bin"
    print(folder, flush=True)
    print(os.getpid(), flush=True)
    deadline = time.monotonic() + DURATION_SECONDS
    if mode == "hold":
        with target.open("ab", buffering=0) as output:
            while time.monotonic() < deadline:
                output.write(CHUNK)
                time.sleep(INTERVAL_SECONDS)
    else:
        while time.monotonic() < deadline:
            _write_once(target)
            time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
