"""Policy engine: validation, recommendations, dry-run previews, and execution."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import send2trash  # type: ignore[import-untyped]

from moonlight.policy.actions import (
    ALLOWED_ACTION_TYPES,
    ActionPreview,
    ActionType,
    ExecutionResult,
    ProposedAction,
    ValidationDecision,
)
from moonlight.policy.audit import PolicyAuditLogger
from moonlight.policy.paths import (
    detect_symlink_escape,
    normalize_and_validate_path,
)
from moonlight.policy.protected import (
    is_critical_process,
)
from moonlight.rules.storage import StorageLocations

HEX_HASH_REGEX = re.compile(r"^[0-9a-fA-F]{32,128}$")


class PolicyViolationError(Exception):
    """Raised when an action violates safety policy."""


class PolicyLayer:
    """The local safety policy layer gating all proposed actions."""

    def __init__(
        self,
        locations: StorageLocations | None = None,
        extra_protected_paths: Sequence[Path | str] | None = None,
        audit_logger: PolicyAuditLogger | None = None,
        log_path: Path | str | None = None,
    ) -> None:
        self._locations = locations
        self._extra_protected = (
            tuple(extra_protected_paths) if extra_protected_paths else ()
        )
        self._audit_logger = (
            audit_logger if audit_logger is not None else PolicyAuditLogger(log_path)
        )

    @property
    def audit_logger(self) -> PolicyAuditLogger:
        return self._audit_logger

    def _ensure_action(self, action: ProposedAction | dict[str, Any]) -> ProposedAction:
        if isinstance(action, ProposedAction):
            return action
        return ProposedAction.model_validate(action)

    def validate_action(
        self,
        action: ProposedAction | dict[str, Any],
        raise_on_reject: bool = False,
    ) -> ValidationDecision:
        """Validate a proposed action against allowlist and protected lists."""
        act = self._ensure_action(action)
        action_type = act.action_type

        # 1. Allowlist check
        if action_type not in ALLOWED_ACTION_TYPES:
            if action_type in ("kill_process", "terminate_process"):
                reason = (
                    f"Action '{action_type}' is strictly prohibited. Process "
                    "termination is not permitted in Moonlight; collectors "
                    "and actions are non-terminating."
                )
            elif action_type in ("delete_file", "permanent_delete", "rmdir", "remove"):
                reason = (
                    f"Action '{action_type}' is strictly prohibited. Permanent file "
                    "deletion is not permitted. The only permitted file action is "
                    "move_to_recycle_bin."
                )
            else:
                permitted = ", ".join(sorted(ALLOWED_ACTION_TYPES))
                reason = (
                    f"Action '{action_type}' is not in the allowlist. "
                    f"Permitted actions: {permitted}."
                )

            self._audit_logger.log_event(
                event_type="validation",
                action_type=action_type,
                status="rejected",
                allowed=False,
                target=act.target_path or act.target_process or act.target_id,
                reason=reason,
            )
            decision = ValidationDecision(
                action=act, allowed=False, rejection_reason=reason
            )
            if raise_on_reject:
                raise PolicyViolationError(reason)
            return decision

        # 2. Critical process check
        is_crit, crit_reason = is_critical_process(
            process_name=act.target_process, pid=act.target_pid
        )
        if is_crit:
            reason = (
                crit_reason or "Critical Windows system process cannot be targeted."
            )
            self._audit_logger.log_event(
                event_type="validation",
                action_type=action_type,
                status="rejected",
                allowed=False,
                target=act.target_process or str(act.target_pid),
                reason=reason,
            )
            decision = ValidationDecision(
                action=act, allowed=False, rejection_reason=reason
            )
            if raise_on_reject:
                raise PolicyViolationError(reason)
            return decision

        # 3. Action-specific validation
        if action_type == ActionType.MOVE_TO_RECYCLE_BIN:
            if not act.target_path:
                reason = "Action 'move_to_recycle_bin' requires a valid 'target_path'."
                self._audit_logger.log_event(
                    event_type="validation",
                    action_type=action_type,
                    status="rejected",
                    allowed=False,
                    reason=reason,
                )
                decision = ValidationDecision(
                    action=act, allowed=False, rejection_reason=reason
                )
                if raise_on_reject:
                    raise PolicyViolationError(reason)
                return decision

            val_res = normalize_and_validate_path(
                act.target_path,
                locations=self._locations,
                extra_protected=self._extra_protected,
                for_mutation=True,
            )
            if not val_res.is_valid:
                reason = val_res.rejection_reason or "Target path validation failed."
                self._audit_logger.log_event(
                    event_type="validation",
                    action_type=action_type,
                    status="rejected",
                    allowed=False,
                    target=act.target_path,
                    reason=reason,
                )
                decision = ValidationDecision(
                    action=act, allowed=False, rejection_reason=reason
                )
                if raise_on_reject:
                    raise PolicyViolationError(reason)
                return decision

            self._audit_logger.log_event(
                event_type="validation",
                action_type=action_type,
                status="allowed",
                allowed=True,
                target=val_res.resolved_path,
            )
            return ValidationDecision(
                action=act, allowed=True, resolved_path=val_res.resolved_path
            )

        elif action_type == ActionType.OPEN_FILE_LOCATION:
            if not act.target_path:
                reason = "Action 'open_file_location' requires a valid 'target_path'."
                self._audit_logger.log_event(
                    event_type="validation",
                    action_type=action_type,
                    status="rejected",
                    allowed=False,
                    reason=reason,
                )
                decision = ValidationDecision(
                    action=act, allowed=False, rejection_reason=reason
                )
                if raise_on_reject:
                    raise PolicyViolationError(reason)
                return decision

            val_res = normalize_and_validate_path(
                act.target_path,
                locations=self._locations,
                extra_protected=self._extra_protected,
                for_mutation=False,
            )
            if not val_res.is_valid:
                reason = val_res.rejection_reason or "Target path validation failed."
                self._audit_logger.log_event(
                    event_type="validation",
                    action_type=action_type,
                    status="rejected",
                    allowed=False,
                    target=act.target_path,
                    reason=reason,
                )
                decision = ValidationDecision(
                    action=act, allowed=False, rejection_reason=reason
                )
                if raise_on_reject:
                    raise PolicyViolationError(reason)
                return decision

            self._audit_logger.log_event(
                event_type="validation",
                action_type=action_type,
                status="allowed",
                allowed=True,
                target=val_res.resolved_path,
            )
            return ValidationDecision(
                action=act, allowed=True, resolved_path=val_res.resolved_path
            )

        elif action_type == ActionType.COPY_HASH_TO_CLIPBOARD:
            if not act.hash_value or not HEX_HASH_REGEX.match(act.hash_value.strip()):
                reason = (
                    "Action 'copy_hash_to_clipboard' requires a valid hex hash "
                    "string (32-128 hexadecimal characters)."
                )
                self._audit_logger.log_event(
                    event_type="validation",
                    action_type=action_type,
                    status="rejected",
                    allowed=False,
                    target=act.hash_value,
                    reason=reason,
                )
                decision = ValidationDecision(
                    action=act, allowed=False, rejection_reason=reason
                )
                if raise_on_reject:
                    raise PolicyViolationError(reason)
                return decision

            self._audit_logger.log_event(
                event_type="validation",
                action_type=action_type,
                status="allowed",
                allowed=True,
                target=act.hash_value,
            )
            return ValidationDecision(action=act, allowed=True)

        elif action_type == ActionType.MARK_REVIEWED:
            target = act.target_id or act.target_path or act.target_process
            if not target:
                reason = "Action 'mark_reviewed' requires a target subject or ID."
                self._audit_logger.log_event(
                    event_type="validation",
                    action_type=action_type,
                    status="rejected",
                    allowed=False,
                    reason=reason,
                )
                decision = ValidationDecision(
                    action=act, allowed=False, rejection_reason=reason
                )
                if raise_on_reject:
                    raise PolicyViolationError(reason)
                return decision

            self._audit_logger.log_event(
                event_type="validation",
                action_type=action_type,
                status="allowed",
                allowed=True,
                target=target,
            )
            return ValidationDecision(action=act, allowed=True)

        reason = f"Unhandled action type '{action_type}'."
        decision = ValidationDecision(
            action=act, allowed=False, rejection_reason=reason
        )
        if raise_on_reject:
            raise PolicyViolationError(reason)
        return decision

    def filter_recommendations(
        self,
        recommendations: Sequence[ProposedAction | dict[str, Any]],
    ) -> tuple[ValidationDecision, ...]:
        """Filter model recommendations before presentation in UI or report."""
        return tuple(self.validate_action(rec) for rec in recommendations)

    def preview_action(
        self,
        action: ProposedAction | dict[str, Any],
    ) -> ActionPreview:
        """Create a dry-run preview listing exactly what would change."""
        act = self._ensure_action(action)
        decision = self.validate_action(act)
        now = datetime.now(UTC)
        preview_id = f"prev-{uuid4().hex[:12]}"

        if not decision.allowed:
            preview = ActionPreview(
                preview_id=preview_id,
                action=act,
                allowed=False,
                rejection_reason=decision.rejection_reason,
                description=f"Action blocked by policy: {decision.rejection_reason}",
                requires_confirmation=False,
                timestamp=now,
            )
            self._audit_logger.log_event(
                event_type="preview",
                action_type=act.action_type,
                status="rejected",
                allowed=False,
                preview_id=preview_id,
                reason=decision.rejection_reason,
            )
            return preview

        if act.action_type == ActionType.MOVE_TO_RECYCLE_BIN:
            resolved_str = decision.resolved_path or ""
            target_path = Path(resolved_str)
            if not target_path.exists():
                reason = f"Target path does not exist on disk: '{resolved_str}'."
                self._audit_logger.log_event(
                    event_type="preview",
                    action_type=act.action_type,
                    status="rejected",
                    allowed=False,
                    target=resolved_str,
                    preview_id=preview_id,
                    reason=reason,
                )
                return ActionPreview(
                    preview_id=preview_id,
                    action=act,
                    allowed=False,
                    rejection_reason=reason,
                    description=f"Action blocked: {reason}",
                    requires_confirmation=False,
                    timestamp=now,
                )

            is_dir = target_path.is_dir()
            if is_dir:
                try:
                    all_files = [f for f in target_path.rglob("*") if f.is_file()]
                    size_bytes = sum(f.stat().st_size for f in all_files)
                    item_count = sum(1 for _ in target_path.rglob("*")) + 1
                except OSError:
                    size_bytes = 0
                    item_count = 1
            else:
                try:
                    size_bytes = target_path.stat().st_size
                except OSError:
                    size_bytes = 0
                item_count = 1

            try:
                mtime_ns = target_path.stat().st_mtime_ns
                target_mtime = datetime.fromtimestamp(
                    target_path.stat().st_mtime, tz=UTC
                )
            except OSError:
                mtime_ns = 0
                target_mtime = now

            fingerprint_raw = f"{resolved_str}:{size_bytes}:{mtime_ns}"
            fingerprint = hashlib.sha256(fingerprint_raw.encode("utf-8")).hexdigest()

            item_type = "directory" if is_dir else "file"
            description = (
                f"Move {item_type} '{resolved_str}' ({size_bytes:,} bytes, "
                f"{item_count} items) to the Windows Recycle Bin."
            )
            changes = (
                f"Remove {item_type} '{resolved_str}' from active filesystem.",
                "Send item to Windows Recycle Bin via send2trash.",
                f"Reclaim approximately {size_bytes:,} bytes of storage space.",
            )

            preview = ActionPreview(
                preview_id=preview_id,
                action=act,
                allowed=True,
                resolved_target_path=resolved_str,
                description=description,
                requires_confirmation=True,
                target_size_bytes=size_bytes,
                target_item_count=item_count,
                target_mtime=target_mtime,
                destination="Windows Recycle Bin",
                changes=changes,
                fingerprint=fingerprint,
                timestamp=now,
            )
            self._audit_logger.log_event(
                event_type="preview",
                action_type=act.action_type,
                status="previewed",
                allowed=True,
                target=resolved_str,
                preview_id=preview_id,
                details={
                    "size_bytes": size_bytes,
                    "item_count": item_count,
                    "fingerprint": fingerprint,
                },
            )
            return preview

        elif act.action_type == ActionType.OPEN_FILE_LOCATION:
            resolved_str = decision.resolved_path or ""
            description = f"Open file location of '{resolved_str}' in Windows Explorer."
            preview = ActionPreview(
                preview_id=preview_id,
                action=act,
                allowed=True,
                resolved_target_path=resolved_str,
                description=description,
                requires_confirmation=False,
                changes=(f"Launch Windows Explorer selecting '{resolved_str}'.",),
                timestamp=now,
            )
            self._audit_logger.log_event(
                event_type="preview",
                action_type=act.action_type,
                status="previewed",
                allowed=True,
                target=resolved_str,
                preview_id=preview_id,
            )
            return preview

        elif act.action_type == ActionType.COPY_HASH_TO_CLIPBOARD:
            description = f"Copy hash '{act.hash_value}' to system clipboard."
            preview = ActionPreview(
                preview_id=preview_id,
                action=act,
                allowed=True,
                description=description,
                requires_confirmation=False,
                changes=(
                    f"Place hash '{act.hash_value}' into system clipboard buffer.",
                ),
                timestamp=now,
            )
            self._audit_logger.log_event(
                event_type="preview",
                action_type=act.action_type,
                status="previewed",
                allowed=True,
                target=act.hash_value,
                preview_id=preview_id,
            )
            return preview

        elif act.action_type == ActionType.MARK_REVIEWED:
            target = act.target_id or act.target_path or act.target_process or ""
            description = (
                f"Mark item '{target}' as reviewed in local investigation state."
            )
            preview = ActionPreview(
                preview_id=preview_id,
                action=act,
                allowed=True,
                description=description,
                requires_confirmation=False,
                changes=(f"Update investigation status of '{target}' to reviewed.",),
                timestamp=now,
            )
            self._audit_logger.log_event(
                event_type="preview",
                action_type=act.action_type,
                status="previewed",
                allowed=True,
                target=target,
                preview_id=preview_id,
            )
            return preview

        return ActionPreview(
            preview_id=preview_id,
            action=act,
            allowed=False,
            rejection_reason="Unsupported preview type",
            description="Unsupported preview type",
            timestamp=now,
        )

    def execute_action(
        self,
        action: ProposedAction | dict[str, Any],
        preview: ActionPreview | None = None,
        confirmed: bool = False,
        hooks: dict[str, Callable[..., Any]] | None = None,
    ) -> ExecutionResult:
        """Execute a permitted action with re-validation and mandatory confirmation."""
        act = self._ensure_action(action)
        now = datetime.now(UTC)
        target_name = (
            act.target_path
            or act.target_process
            or act.target_id
            or act.hash_value
            or ""
        )

        # Re-validate policy at execution time
        live_decision = self.validate_action(act)
        if not live_decision.allowed:
            err = (
                f"Execution blocked: live policy rejection: "
                f"{live_decision.rejection_reason}"
            )
            self._audit_logger.log_event(
                event_type="execution",
                action_type=act.action_type,
                status="rejected",
                allowed=False,
                target=target_name,
                reason=err,
            )
            return ExecutionResult(
                success=False,
                action_type=act.action_type,
                target=target_name,
                message="Execution rejected by policy.",
                error=err,
                timestamp=now,
            )

        if act.action_type == ActionType.MOVE_TO_RECYCLE_BIN:
            # 1. Preview required
            if preview is None:
                err = (
                    "Execution rejected: A dry-run preview is required "
                    "before moving to Recycle Bin."
                )
                self._audit_logger.log_event(
                    event_type="execution",
                    action_type=act.action_type,
                    status="rejected",
                    allowed=False,
                    target=target_name,
                    reason=err,
                )
                return ExecutionResult(
                    success=False,
                    action_type=act.action_type,
                    target=target_name,
                    message="Execution rejected.",
                    error=err,
                    timestamp=now,
                )

            if not preview.allowed:
                err = (
                    f"Execution rejected: Cannot execute a rejected preview: "
                    f"{preview.rejection_reason}"
                )
                self._audit_logger.log_event(
                    event_type="execution",
                    action_type=act.action_type,
                    status="rejected",
                    allowed=False,
                    target=target_name,
                    preview_id=preview.preview_id,
                    reason=err,
                )
                return ExecutionResult(
                    success=False,
                    action_type=act.action_type,
                    target=target_name,
                    message="Execution rejected.",
                    error=err,
                    timestamp=now,
                )

            # 2. Confirmation required
            if not confirmed:
                err = "Execution rejected: Explicit user confirmation is required."
                self._audit_logger.log_event(
                    event_type="execution",
                    action_type=act.action_type,
                    status="rejected",
                    allowed=False,
                    target=target_name,
                    preview_id=preview.preview_id,
                    reason=err,
                )
                return ExecutionResult(
                    success=False,
                    action_type=act.action_type,
                    target=target_name,
                    message="Execution rejected.",
                    error=err,
                    timestamp=now,
                )

            # 3. Detect changed path between preview and execution
            if act.target_path != preview.action.target_path:
                err = (
                    f"Execution rejected: Target path changed between preview "
                    f"('{preview.action.target_path}') and execution "
                    f"('{act.target_path}')."
                )
                self._audit_logger.log_event(
                    event_type="execution",
                    action_type=act.action_type,
                    status="rejected",
                    allowed=False,
                    target=target_name,
                    preview_id=preview.preview_id,
                    reason=err,
                )
                return ExecutionResult(
                    success=False,
                    action_type=act.action_type,
                    target=target_name,
                    message="Execution rejected.",
                    error=err,
                    timestamp=now,
                )

            # 4. Re-check live filesystem target
            target_path = Path(live_decision.resolved_path or "")
            if not target_path.exists():
                err = (
                    f"Execution rejected: Target file no longer exists: "
                    f"'{target_path}'."
                )
                self._audit_logger.log_event(
                    event_type="execution",
                    action_type=act.action_type,
                    status="rejected",
                    allowed=False,
                    target=str(target_path),
                    preview_id=preview.preview_id,
                    reason=err,
                )
                return ExecutionResult(
                    success=False,
                    action_type=act.action_type,
                    target=str(target_path),
                    message="Execution rejected.",
                    error=err,
                    timestamp=now,
                )

            # 5. Re-check symlink escapes on live target
            esc, esc_reason = detect_symlink_escape(
                target_path,
                locations=self._locations,
                extra_protected=self._extra_protected,
            )
            if esc:
                err = f"Execution rejected: Live symlink escape detected: {esc_reason}"
                self._audit_logger.log_event(
                    event_type="execution",
                    action_type=act.action_type,
                    status="rejected",
                    allowed=False,
                    target=str(target_path),
                    preview_id=preview.preview_id,
                    reason=err,
                )
                return ExecutionResult(
                    success=False,
                    action_type=act.action_type,
                    target=str(target_path),
                    message="Execution rejected.",
                    error=err,
                    timestamp=now,
                )

            # 6. Verify fingerprint (TOCTOU guard)
            is_dir = target_path.is_dir()
            if is_dir:
                try:
                    all_files = [f for f in target_path.rglob("*") if f.is_file()]
                    size_bytes = sum(f.stat().st_size for f in all_files)
                except OSError:
                    size_bytes = 0
            else:
                try:
                    size_bytes = target_path.stat().st_size
                except OSError:
                    size_bytes = 0

            try:
                mtime_ns = target_path.stat().st_mtime_ns
            except OSError:
                mtime_ns = 0

            live_fingerprint_raw = f"{target_path}:{size_bytes}:{mtime_ns}"
            live_fingerprint = hashlib.sha256(
                live_fingerprint_raw.encode("utf-8")
            ).hexdigest()

            if preview.fingerprint and live_fingerprint != preview.fingerprint:
                err = (
                    "Execution rejected: Target item was modified between preview "
                    "and execution (fingerprint mismatch)."
                )
                self._audit_logger.log_event(
                    event_type="execution",
                    action_type=act.action_type,
                    status="rejected",
                    allowed=False,
                    target=str(target_path),
                    preview_id=preview.preview_id,
                    reason=err,
                )
                return ExecutionResult(
                    success=False,
                    action_type=act.action_type,
                    target=str(target_path),
                    message="Execution rejected.",
                    error=err,
                    timestamp=now,
                )

            # 7. Execute via send2trash ONLY (never permanent deletion)
            trash_func = (
                hooks.get("send2trash", send2trash.send2trash)
                if hooks
                else send2trash.send2trash
            )
            try:
                trash_func(str(target_path))
            except Exception as exc:
                err = f"send2trash failed: {exc}"
                self._audit_logger.log_event(
                    event_type="execution",
                    action_type=act.action_type,
                    status="rejected",
                    allowed=False,
                    target=str(target_path),
                    preview_id=preview.preview_id,
                    reason=err,
                )
                return ExecutionResult(
                    success=False,
                    action_type=act.action_type,
                    target=str(target_path),
                    message="Recycle Bin operation failed.",
                    error=err,
                    timestamp=now,
                )

            msg = f"Successfully moved '{target_path}' to the Windows Recycle Bin."
            self._audit_logger.log_event(
                event_type="execution",
                action_type=act.action_type,
                status="executed",
                allowed=True,
                target=str(target_path),
                preview_id=preview.preview_id,
                details={"destination": "Windows Recycle Bin", "bytes": size_bytes},
            )
            return ExecutionResult(
                success=True,
                action_type=act.action_type,
                target=str(target_path),
                message=msg,
                timestamp=now,
                details={"destination": "Windows Recycle Bin", "bytes": size_bytes},
            )

        elif act.action_type == ActionType.OPEN_FILE_LOCATION:
            resolved_str = live_decision.resolved_path or ""
            open_func = hooks.get("open_file_location") if hooks else None
            if open_func:
                open_func(resolved_str)

            msg = f"Opened file location for '{resolved_str}'."
            self._audit_logger.log_event(
                event_type="execution",
                action_type=act.action_type,
                status="executed",
                allowed=True,
                target=resolved_str,
            )
            return ExecutionResult(
                success=True,
                action_type=act.action_type,
                target=resolved_str,
                message=msg,
                timestamp=now,
            )

        elif act.action_type == ActionType.COPY_HASH_TO_CLIPBOARD:
            hash_str = act.hash_value or ""
            clip_func = hooks.get("copy_hash_to_clipboard") if hooks else None
            if clip_func:
                clip_func(hash_str)

            msg = f"Copied hash '{hash_str}' to clipboard."
            self._audit_logger.log_event(
                event_type="execution",
                action_type=act.action_type,
                status="executed",
                allowed=True,
                target=hash_str,
            )
            return ExecutionResult(
                success=True,
                action_type=act.action_type,
                target=hash_str,
                message=msg,
                timestamp=now,
            )

        elif act.action_type == ActionType.MARK_REVIEWED:
            target = act.target_id or act.target_path or act.target_process or ""
            mark_func = hooks.get("mark_reviewed") if hooks else None
            if mark_func:
                mark_func(target)

            msg = f"Marked '{target}' as reviewed."
            self._audit_logger.log_event(
                event_type="execution",
                action_type=act.action_type,
                status="executed",
                allowed=True,
                target=target,
            )
            return ExecutionResult(
                success=True,
                action_type=act.action_type,
                target=target,
                message=msg,
                timestamp=now,
            )

        err = f"Unsupported execution action '{act.action_type}'."
        return ExecutionResult(
            success=False,
            action_type=act.action_type,
            target=target_name,
            message="Execution rejected.",
            error=err,
            timestamp=now,
        )


def validate_proposed_action(
    action: ProposedAction | dict[str, Any],
    locations: StorageLocations | None = None,
    extra_protected_paths: Sequence[Path | str] | None = None,
    audit_logger: PolicyAuditLogger | None = None,
) -> ValidationDecision:
    """Validate a proposed action using a default PolicyLayer instance."""
    layer = PolicyLayer(
        locations=locations,
        extra_protected_paths=extra_protected_paths,
        audit_logger=audit_logger,
    )
    return layer.validate_action(action)


def filter_recommendations(
    recommendations: Sequence[ProposedAction | dict[str, Any]],
    locations: StorageLocations | None = None,
    extra_protected_paths: Sequence[Path | str] | None = None,
    audit_logger: PolicyAuditLogger | None = None,
) -> tuple[ValidationDecision, ...]:
    """Filter model recommendations before presentation."""
    layer = PolicyLayer(
        locations=locations,
        extra_protected_paths=extra_protected_paths,
        audit_logger=audit_logger,
    )
    return layer.filter_recommendations(recommendations)


def preview_action(
    action: ProposedAction | dict[str, Any],
    locations: StorageLocations | None = None,
    extra_protected_paths: Sequence[Path | str] | None = None,
    audit_logger: PolicyAuditLogger | None = None,
) -> ActionPreview:
    """Preview a proposed action with dry-run details."""
    layer = PolicyLayer(
        locations=locations,
        extra_protected_paths=extra_protected_paths,
        audit_logger=audit_logger,
    )
    return layer.preview_action(action)


def execute_action(
    action: ProposedAction | dict[str, Any],
    preview: ActionPreview | None = None,
    confirmed: bool = False,
    locations: StorageLocations | None = None,
    extra_protected_paths: Sequence[Path | str] | None = None,
    audit_logger: PolicyAuditLogger | None = None,
    hooks: dict[str, Callable[..., Any]] | None = None,
) -> ExecutionResult:
    """Execute a proposed action gated by confirmation and dry-run preview."""
    layer = PolicyLayer(
        locations=locations,
        extra_protected_paths=extra_protected_paths,
        audit_logger=audit_logger,
    )
    return layer.execute_action(
        action, preview=preview, confirmed=confirmed, hooks=hooks
    )
