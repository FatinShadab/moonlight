"""Path safety: normalization, traversal, UNC/device rejection, symlink checks."""

from __future__ import annotations

import os
import re
import stat
import sys
from collections.abc import Sequence
from pathlib import Path, PurePath, PureWindowsPath
from typing import Self

from pydantic import BaseModel, ConfigDict

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


def detect_alternate_data_stream(path_str: str) -> bool:
    """Detect Alternate Data Stream (ADS) syntax (:stream after drive)."""
    if not path_str or not path_str.strip():
        return False
    cleaned = path_str.strip()
    if len(cleaned) >= 2 and cleaned[1] == ":" and cleaned[0].isalpha():
        rest = cleaned[2:]
    else:
        rest = cleaned
    return ":" in rest


def strip_alternate_data_stream(path_str: str) -> tuple[str, str | None]:
    """Split path into (base_path, stream_name)."""
    cleaned = path_str.strip()
    if len(cleaned) >= 2 and cleaned[1] == ":" and cleaned[0].isalpha():
        drive = cleaned[:2]
        rest = cleaned[2:]
        if ":" in rest:
            base, stream = rest.split(":", 1)
            return f"{drive}{base}", stream
        return cleaned, None
    if ":" in cleaned:
        base, stream = cleaned.split(":", 1)
        return base, stream
    return cleaned, None


def strip_trailing_dots_and_spaces(path_str: str) -> str:
    """Strip Win32-ignored trailing dots and spaces from path components."""
    cleaned = path_str.strip()
    if not cleaned:
        return cleaned
    drive = ""
    rest = cleaned
    if len(cleaned) >= 2 and cleaned[1] == ":" and cleaned[0].isalpha():
        drive = cleaned[:2]
        rest = cleaned[2:]

    sep = "\\" if "\\" in cleaned else "/"
    leading_sep = rest.startswith(("/", "\\"))
    trailing_sep = rest.endswith(("/", "\\")) and len(rest) > 1

    parts = re.split(r"[/\\]+", rest)
    cleaned_parts = [p.rstrip(". ") for p in parts if p.rstrip(". ")]

    if not cleaned_parts:
        return drive + (sep if leading_sep else "")

    joined = sep.join(cleaned_parts)
    if leading_sep:
        joined = sep + joined
    if trailing_sep:
        joined = joined + sep
    return f"{drive}{joined}"


def is_reparse_point(path: Path | str) -> bool:
    """Check if the given path is a Windows reparse point (junction or symlink)."""
    p = Path(path)
    if not p.exists() and not p.is_symlink():
        return False
    try:
        st = os.lstat(str(p))
        if getattr(st, "st_reparse_tag", 0) != 0:
            return True
        attrs = getattr(st, "st_file_attributes", 0)
        if attrs and (attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            return True
        if p.is_symlink() or os.path.islink(str(p)):
            return True
    except (OSError, ValueError):
        pass
    return False


def resolve_final_path(p: Path) -> Path:
    """Resolve a path to its canonical final path on Windows.

    Expands 8.3 short names, resolves symlinks and junctions, normalizes case.
    """
    try:
        resolved = p.resolve()
    except (OSError, ValueError):
        resolved = p.absolute()

    if sys.platform == "win32":
        try:
            import ctypes

            buf = ctypes.create_unicode_buffer(1024)
            res = ctypes.windll.kernel32.GetLongPathNameW(str(resolved), buf, 1024)
            if res > 0:
                resolved = Path(buf.value)
        except Exception:
            pass
    return resolved


def detect_symlink_escape(
    path: Path,
    locations: StorageLocations | None = None,
    extra_protected: Sequence[Path | str] | None = None,
) -> tuple[bool, str | None]:
    """Check if a path or parent is a symlink pointing to a protected location."""
    try:
        current = path
        is_link = False
        if current.is_symlink() or os.path.islink(current) or is_reparse_point(current):
            is_link = True
        else:
            for parent in current.parents:
                if parent.exists() and (
                    parent.is_symlink()
                    or os.path.islink(parent)
                    or is_reparse_point(parent)
                ):
                    is_link = True
                    break

        if is_link:
            from moonlight.policy.protected import is_protected_path

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

    # Alternate Data Stream detection
    if detect_alternate_data_stream(cleaned):
        if for_mutation:
            return PathValidationResult.invalid(
                f"Alternate data streams cannot be targeted for mutation: '{cleaned}'."
            )

    base_cleaned, _ = strip_alternate_data_stream(cleaned)
    normalized_cleaned = strip_trailing_dots_and_spaces(base_cleaned)

    try:
        p = Path(normalized_cleaned)
        resolved = resolve_final_path(p)
    except Exception as err:
        return PathValidationResult.invalid(f"Invalid path syntax '{cleaned}': {err}")

    if detect_device_path(str(resolved)):
        return PathValidationResult.invalid(
            f"Device paths and reserved DOS names are not permitted: '{resolved}'."
        )

    # For mutating operations (e.g. move_to_recycle_bin), check protected locations
    if for_mutation:
        # Reparse point rejection: reject junctions and symlinks as recycle targets
        if is_reparse_point(normalized_cleaned) or (p.exists() and is_reparse_point(p)):
            return PathValidationResult.invalid(
                f"Cannot perform mutating action: Target path '{cleaned}' is a "
                "reparse point (junction or symlink), which is not permitted as a "
                "recycle target."
            )

        from moonlight.policy.protected import is_protected_path

        is_prot, prot_reason = is_protected_path(
            cleaned, locations=locations, extra_protected=extra_protected
        )
        if is_prot:
            return PathValidationResult.invalid(
                f"Cannot perform mutating action on protected location: {prot_reason}"
            )

        if p.exists() or Path(cleaned).exists():
            esc, esc_reason = detect_symlink_escape(
                p if p.exists() else Path(cleaned),
                locations=locations,
                extra_protected=extra_protected,
            )
            if esc:
                return PathValidationResult.invalid(
                    f"Cannot perform mutating action: {esc_reason}"
                )

    if check_exists and not resolved.exists():
        return PathValidationResult.invalid(f"Path does not exist: '{resolved}'.")

    return PathValidationResult.valid(resolved)
