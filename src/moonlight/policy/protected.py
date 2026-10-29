"""Protected system directories, user document folders, and critical processes."""

from __future__ import annotations

import os
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from moonlight.core.evidence import EvidenceBundle, EvidenceItem, EvidenceKind
from moonlight.policy.paths import (
    resolve_final_path,
    strip_alternate_data_stream,
    strip_trailing_dots_and_spaces,
)
from moonlight.rules.storage import StorageLocations, classify_storage
from moonlight.storage.locations import KnownFolders, discover_locations
from moonlight.storage.models import (
    PathReference,
    SelectedRoot,
    StorageCategory,
    StorageReport,
    path_id,
)

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
    """Check whether a path falls inside protected system or user folders.

    Resolves path aliases (8.3 short names, alternate data streams, trailing
    dots and spaces, case differences, and junctions/symlinks) before checking.
    """
    locs = locations if locations is not None else get_protected_locations()

    base_path_str, _ = strip_alternate_data_stream(str(path))
    cleaned = strip_trailing_dots_and_spaces(base_path_str)
    resolved = resolve_final_path(Path(cleaned))

    norm_target = _normalize_for_comparison(resolved)
    norm_raw = _normalize_for_comparison(cleaned)

    # Check against discover_locations protected list
    for protected_root in locs.protected:
        norm_root = _normalize_for_comparison(resolve_final_path(Path(protected_root)))
        if norm_target == norm_root or norm_target.startswith(norm_root + os.sep):
            return (
                True,
                f"Target path '{path}' is inside protected directory "
                f"'{protected_root}'.",
            )
        if norm_raw == norm_root or norm_raw.startswith(norm_root + os.sep):
            return (
                True,
                f"Target path '{path}' is inside protected directory "
                f"'{protected_root}'.",
            )

    # Check extra protected roots if provided
    if extra_protected:
        for extra_root in extra_protected:
            norm_root = _normalize_for_comparison(resolve_final_path(Path(extra_root)))
            if norm_target == norm_root or norm_target.startswith(norm_root + os.sep):
                return (
                    True,
                    f"Target path '{path}' is inside protected directory "
                    f"'{extra_root}'.",
                )
            if norm_raw == norm_root or norm_raw.startswith(norm_root + os.sep):
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


def classify_path_storage(
    path: Path | str,
    locations: StorageLocations | None = None,
    extra_protected: Sequence[Path | str] | None = None,
) -> tuple[StorageCategory, str]:
    """Classify target path using Moonlight's storage classifier (rules/storage.py).

    Reuses classify_storage to determine clearly_safe, review_first, or
    do_not_touch.
    """
    base_locs = locations if locations is not None else get_protected_locations()
    if extra_protected:
        locs = StorageLocations(
            protected=base_locs.protected + tuple(str(x) for x in extra_protected),
            safe=base_locs.safe,
            discovery_complete=base_locs.discovery_complete,
        )
    else:
        locs = base_locs

    base_path_str, _ = strip_alternate_data_stream(str(path))
    cleaned = strip_trailing_dots_and_spaces(base_path_str)
    p = resolve_final_path(Path(cleaned))

    anchor = p.anchor or "C:/"
    root = SelectedRoot(root_id="root_0", path=anchor)
    try:
        rel = str(p.relative_to(anchor))
    except ValueError:
        rel = str(p)

    kind = EvidenceKind.FOLDER_SIZE if p.is_dir() else EvidenceKind.FILE_TYPE
    bundle = EvidenceBundle(
        subject_id=path_id(str(p)),
        subject_type="storage",
        items=(
            EvidenceItem(
                id=f"ev-storage-{kind.value}-{uuid4().hex[:8]}",
                source="storage_collector",
                kind=kind,
                value={
                    "path": PathReference(
                        root_id="root_0", relative_path=rel
                    ).model_dump(),
                    "size_bytes": 0,
                    "is_directory": p.is_dir() if p.exists() else False,
                },
                availability="observed",
                timestamp=datetime.now(UTC),
            ),
        ),
    )
    report = StorageReport(
        timestamp=datetime.now(UTC),
        roots=(root,),
        bundles=(bundle,),
    )
    classified = classify_storage(report, locs)
    classification = classified.classifications[0]
    return classification.category, classification.reason
