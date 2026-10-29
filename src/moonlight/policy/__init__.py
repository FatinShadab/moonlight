"""Local policy checks and consent flow for proposed Moonlight actions.

Enforces:
1. Strict allowlist of safe action types (no process termination or permanent
   file deletion).
2. Protected system paths, user personal document folders, and critical
   processes.
3. Path safety: normalization, traversal rejection, UNC rejection, device path
   rejection, symlink escape checks.
4. Mandatory dry-run previews listing changes; explicit confirmation required
   for Recycle Bin (via send2trash only).
5. Append-only JSON lines audit logging for every attempted action.
6. Exported action ID allowlist for report and schema validators.
"""

from __future__ import annotations

from moonlight.policy.actions import (
    ALLOWED_ACTION_IDS,
    ALLOWED_ACTION_TYPES,
    ActionPreview,
    ActionType,
    ExecutionResult,
    ProposedAction,
    ValidationDecision,
)
from moonlight.policy.audit import (
    AuditRecord,
    PolicyAuditLogger,
)
from moonlight.policy.engine import (
    PolicyLayer,
    PolicyViolationError,
    execute_action,
    filter_recommendations,
    generate_confirmation_token,
    launch_file_location,
    preview_action,
    validate_proposed_action,
)
from moonlight.policy.paths import (
    PathValidationResult,
    detect_alternate_data_stream,
    detect_device_path,
    detect_symlink_escape,
    detect_traversal,
    detect_unc,
    is_reparse_point,
    normalize_and_validate_path,
    resolve_final_path,
    strip_alternate_data_stream,
    strip_trailing_dots_and_spaces,
)
from moonlight.policy.protected import (
    CRITICAL_PIDS,
    CRITICAL_PROCESS_NAMES,
    classify_path_storage,
    get_protected_locations,
    is_critical_process,
    is_protected_path,
)

__all__ = [
    "ALLOWED_ACTION_IDS",
    "ALLOWED_ACTION_TYPES",
    "ActionPreview",
    "ActionType",
    "AuditRecord",
    "CRITICAL_PIDS",
    "CRITICAL_PROCESS_NAMES",
    "ExecutionResult",
    "PathValidationResult",
    "PolicyAuditLogger",
    "PolicyLayer",
    "PolicyViolationError",
    "ProposedAction",
    "ValidationDecision",
    "classify_path_storage",
    "detect_alternate_data_stream",
    "detect_device_path",
    "detect_symlink_escape",
    "detect_traversal",
    "detect_unc",
    "execute_action",
    "filter_recommendations",
    "generate_confirmation_token",
    "get_protected_locations",
    "is_critical_process",
    "is_protected_path",
    "is_reparse_point",
    "launch_file_location",
    "normalize_and_validate_path",
    "preview_action",
    "resolve_final_path",
    "strip_alternate_data_stream",
    "strip_trailing_dots_and_spaces",
    "validate_proposed_action",
]
