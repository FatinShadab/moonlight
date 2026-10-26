"""Argument-list subprocess boundary for bounded read-only helper queries."""

from __future__ import annotations

import os
import subprocess
from typing import Protocol


class CommandRunner(Protocol):
    def run(
        self, args: list[str], *, timeout: float, input_data: bytes | None = None
    ) -> bytes: ...


class SubprocessRunner:
    def run(
        self, args: list[str], *, timeout: float, input_data: bytes | None = None
    ) -> bytes:
        result = subprocess.run(
            args,
            input=input_data,
            capture_output=True,
            check=True,
            shell=False,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        return result.stdout
