"""Protected system directories, user document folders, and critical processes."""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

from moonlight.rules.storage import StorageLocations
from moonlight.storage.locations import KnownFolders, discover_locations

CRITICAL_PROCESS_NAMES: frozenset[str] = frozenset(
    {
        "system",
        "system idle process",
        "[system process]",
        "registry",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "lsm.exe",
        "winlogon.exe",
        "svchost.exe",
        "fontdrvhost.exe",
        "dwm.exe",
        "sihost.exe",
        "taskhostw.exe",
        "spoolsv.exe",
        "explorer.exe",
    }
)

CRITICAL_PIDS: frozenset[int] = frozenset({0, 4})

SYSTEM_VOLUME_DIRS: frozenset[str] = frozenset(
    {
        "$recycle.bin",
        "system volume information",
        "recovery",
    }
)


def is_critical_process(
    process_name: str | None = None,
    pid: int | None = None,
) -> tuple[bool, str | None]:
    """Check whether a process name or PID is a critical system process."""
    if pid is not None and pid in CRITICAL_PIDS:
        return (
            True,
            f"PID {pid} is a critical Windows system process and cannot be targeted.",
        )

    if process_name is not None:
        cleaned = process_name.strip().lower()
        base = os.path.basename(cleaned)
        if base in CRITICAL_PROCESS_NAMES:
            return (
                True,
                f"Process '{process_name}' is a critical Windows system process "
                "and cannot be targeted.",
            )
        if not base.endswith(".exe") and f"{base}.exe" in CRITICAL_PROCESS_NAMES:
            return (
                True,
                f"Process '{process_name}' is a critical Windows system process "
                "and cannot be targeted.",
            )

    return False, None


def get_protected_locations(folders: KnownFolders | None = None) -> StorageLocations:
    """Discover protected locations on the host or using mock folders."""
    return discover_locations(folders)


def _normalize_for_comparison(path: str | Path) -> str:
    return os.path.normcase(os.path.abspath(str(path)))


def is_protected_path(
    path: Path | str,
    locations: StorageLocations | None = None,
    extra_protected: Sequence[Path | str] | None = None,
) -> tuple[bool, str | None]:
    """Check whether a path falls inside protected system or user folders."""
    locs = locations if locations is not None else get_protected_locations()
    norm_target = _normalize_for_comparison(path)

    # Check against discover_locations protected list
    for protected_root in locs.protected:
        norm_root = _normalize_for_comparison(protected_root)
        if norm_target == norm_root or norm_target.startswith(norm_root + os.sep):
            return (
                True,
                f"Target path '{path}' is inside protected directory "
                f"'{protected_root}'.",
            )

    # Check extra protected roots if provided
    if extra_protected:
        for extra_root in extra_protected:
            norm_root = _normalize_for_comparison(extra_root)
            if norm_target == norm_root or norm_target.startswith(norm_root + os.sep):
                return (
                    True,
                    f"Target path '{path}' is inside protected directory "
                    f"'{extra_root}'.",
                )

    # Check for reserved system volume directory segments
    try:
        parts = [p.lower() for p in Path(norm_target).parts]
        for sys_dir in SYSTEM_VOLUME_DIRS:
            if sys_dir in parts:
                return (
                    True,
                    f"Target path '{path}' touches protected system directory "
                    f"'{sys_dir}'.",
                )
    except Exception:
        pass

    return False, None
