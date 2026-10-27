"""Path safety: normalization, traversal, UNC/device rejection, symlink checks."""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path, PurePath, PureWindowsPath
from typing import Self

from pydantic import BaseModel, ConfigDict

from moonlight.policy.protected import is_protected_path
from moonlight.rules.storage import StorageLocations

RESERVED_DEVICE_NAMES: frozenset[str] = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{i}" for i in range(1, 10)),
        *(f"lpt{i}" for i in range(1, 10)),
    }
)

DEVICE_PREFIXES: tuple[str, ...] = (
    "\\\\.\\",
    "//./",
    "\\\\?\\",
    "//?/",
    "\\??\\",
)


class PathValidationResult(BaseModel):
    """Result of path safety analysis."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    is_valid: bool
    resolved_path: str | None = None
    rejection_reason: str | None = None

    @classmethod
    def valid(cls, resolved: Path) -> Self:
        return cls(is_valid=True, resolved_path=str(resolved))

    @classmethod
    def invalid(cls, reason: str) -> Self:
        return cls(is_valid=False, rejection_reason=reason)


def detect_traversal(path_str: str) -> bool:
    """Detect path traversal attempts including '..' in parts or raw separators."""
    if not path_str or not path_str.strip():
        return False

    cleaned = path_str.strip()
    if ".." in cleaned:
        normalized_separators = cleaned.replace("/", "\\")
        if (
            normalized_separators.startswith("..\\")
            or normalized_separators.endswith("\\..")
            or "\\..\\" in normalized_separators
            or normalized_separators == ".."
        ):
            return True

    try:
        if ".." in PureWindowsPath(cleaned).parts:
            return True
        if ".." in PurePath(cleaned).parts:
            return True
    except Exception:
        return True

    return False


def detect_unc(path_str: str) -> bool:
    """Detect UNC / SMB network paths."""
    if not path_str or not path_str.strip():
        return False

    cleaned = path_str.strip()
    if cleaned.startswith(("\\\\?\\UNC\\", "//?/UNC/")):
        return True

    if detect_device_path(cleaned):
        return False

    if cleaned.startswith("\\\\") or cleaned.startswith("//"):
        return True

    try:
        drive = PureWindowsPath(cleaned).drive
        if drive.startswith("\\\\") or drive.startswith("//"):
            return True
    except Exception:
        pass

    return False


def detect_device_path(path_str: str) -> bool:
    """Detect Windows DOS device paths and reserved device names."""
    if not path_str or not path_str.strip():
        return False

    cleaned = path_str.strip()
    if cleaned.startswith(("\\\\?\\UNC\\", "//?/UNC/")):
        return False

    for prefix in DEVICE_PREFIXES:
        if cleaned.startswith(prefix):
            return True

    try:
        parts = PureWindowsPath(cleaned).parts
        for part in parts:
            name_lower = part.lower()
            stem_lower = PurePath(part).stem.lower()
            if (
                name_lower in RESERVED_DEVICE_NAMES
                or stem_lower in RESERVED_DEVICE_NAMES
            ):
                return True
    except Exception:
        pass

    return False


def detect_symlink_escape(
    path: Path,
    locations: StorageLocations | None = None,
    extra_protected: Sequence[Path | str] | None = None,
) -> tuple[bool, str | None]:
    """Check if a path or parent is a symlink pointing to a protected location."""
    try:
        current = path
        is_link = False
        if current.is_symlink() or os.path.islink(current):
            is_link = True
        else:
            for parent in current.parents:
                if parent.exists() and (parent.is_symlink() or os.path.islink(parent)):
                    is_link = True
                    break

        if is_link:
            resolved = path.resolve()
            prot, reason = is_protected_path(
                resolved, locations=locations, extra_protected=extra_protected
            )
            if prot:
                return (
                    True,
                    f"Symlink escape detected: '{path}' resolves to protected "
                    f"location '{resolved}' ({reason}).",
                )
    except OSError as err:
        return True, f"Symlink resolution failed: {err}"

    return False, None


def normalize_and_validate_path(
    path_str: str,
    locations: StorageLocations | None = None,
    extra_protected: Sequence[Path | str] | None = None,
    for_mutation: bool = True,
    check_exists: bool = False,
) -> PathValidationResult:
    """Normalize and strictly validate path safety according to Moonlight policy."""
    if not path_str or not isinstance(path_str, str) or not path_str.strip():
        return PathValidationResult.invalid("Path cannot be empty.")

    cleaned = path_str.strip()

    if detect_device_path(cleaned):
        return PathValidationResult.invalid(
            f"Device paths and reserved DOS names are not permitted: '{cleaned}'."
        )

    if detect_unc(cleaned):
        return PathValidationResult.invalid(
            f"UNC / network paths are not permitted for security reasons: '{cleaned}'."
        )

    if detect_traversal(cleaned):
        return PathValidationResult.invalid(
            f"Path traversal is not permitted: '..' detected in '{cleaned}'."
        )

    try:
        p = Path(cleaned)
        resolved = p.resolve()
    except Exception as err:
        return PathValidationResult.invalid(f"Invalid path syntax '{cleaned}': {err}")

    if detect_device_path(str(resolved)):
        return PathValidationResult.invalid(
            f"Device paths and reserved DOS names are not permitted: '{resolved}'."
        )

    # For mutating operations (e.g. move_to_recycle_bin), check protected locations
    if for_mutation:
        is_prot, prot_reason = is_protected_path(
            resolved, locations=locations, extra_protected=extra_protected
        )
        if is_prot:
            return PathValidationResult.invalid(
                f"Cannot perform mutating action on protected location: {prot_reason}"
            )

        if p.exists():
            esc, esc_reason = detect_symlink_escape(
                p, locations=locations, extra_protected=extra_protected
            )
            if esc:
                return PathValidationResult.invalid(
                    f"Cannot perform mutating action: {esc_reason}"
                )

    if check_exists and not resolved.exists():
        return PathValidationResult.invalid(f"Path does not exist: '{resolved}'.")

    return PathValidationResult.valid(resolved)
