"""Check live collection without requiring Windows trust queries to finish."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from moonlight.collectors.hashing import FileHash
from moonlight.collectors.process import PROCESS_KINDS
from moonlight.core.evidence import EvidenceBundle, EvidenceKind

_EXPECTED_KINDS = {*PROCESS_KINDS, EvidenceKind.SHA256, EvidenceKind.SIGNATURE_STATUS}
_SIGNATURE_UNAVAILABLE_REASONS = frozenset(
    {"timeout", "access_denied", "signature_verification_unavailable"}
)


def validate_collection_smoke(bundle: EvidenceBundle, pid: int) -> str:
    """Accept documented missing trust evidence, never malformed/error results."""
    if (
        pid < 0
        or bundle.subject_type != "process"
        or not bundle.subject_id.startswith(f"{pid}:")
    ):
        raise ValueError("unexpected_process_identity")
    if (
        len(bundle.items) != len(_EXPECTED_KINDS)
        or {item.kind for item in bundle.items} != _EXPECTED_KINDS
    ):
        raise ValueError("unexpected_collection_kinds")
    if any(item.availability == "error" for item in bundle.items):
        raise ValueError("collector_error")
    items = {item.kind: item for item in bundle.items}
    executable = items[EvidenceKind.EXECUTABLE_PATH]
    if (
        executable.availability != "observed"
        or not isinstance(executable.value, str)
        or not executable.value
    ):
        raise ValueError("executable_path_not_observed")
    hashed = items[EvidenceKind.SHA256]
    if hashed.availability != "observed":
        raise ValueError("executable_hash_not_observed")
    FileHash.model_validate(hashed.value)
    signature = items[EvidenceKind.SIGNATURE_STATUS]
    if signature.availability == "observed" and signature.value in (
        {"state": "signed_valid"},
        {"state": "signed_invalid"},
        {"state": "unsigned"},
    ):
        return "collection smoke passed: SHA-256 and signature observed"
    if (
        signature.availability == "unavailable"
        and signature.value == {"state": "unavailable"}
        and signature.reason in _SIGNATURE_UNAVAILABLE_REASONS
    ):
        return (
            "collection smoke passed: SHA-256 observed; "
            f"signature unavailable ({signature.reason})"
        )
    raise ValueError("unexpected_signature_result")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        bundle = EvidenceBundle.model_validate_json(sys.stdin.read())
        summary = validate_collection_smoke(bundle, args.pid)
    except ValueError:
        # Validation errors can contain raw evidence. Keep diagnostics fixed.
        print(
            "collection smoke failed: invalid or unexpected collector result",
            file=sys.stderr,
        )
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
