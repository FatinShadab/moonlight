"""Comprehensive tests for Moonlight policy layer.

Verifies:
- Strict allowlist (no process termination, no permanent file deletion).
- Protected system paths, user personal documents, and critical processes.
- Path safety: traversal rejection, UNC paths, DOS device names, symlink escapes.
- Dry-run preview listing exact changes; confirmation required.
- send2trash-only execution.
- TOCTOU guards: changed path or modified target between preview and execution.
- Append-only JSON lines audit logging.
- Model recommendation filtering.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import Mock

import pytest

from moonlight.policy import (
    ALLOWED_ACTION_IDS,
    ALLOWED_ACTION_TYPES,
    PolicyAuditLogger,
    PolicyLayer,
    PolicyViolationError,
    ProposedAction,
    execute_action,
    filter_recommendations,
    is_critical_process,
    is_protected_path,
    preview_action,
    validate_proposed_action,
)
from moonlight.policy.paths import (
    detect_device_path,
    detect_symlink_escape,
    detect_traversal,
    detect_unc,
    normalize_and_validate_path,
)
from moonlight.rules.storage import StorageLocations

# Sample valid SHA-256 hash for tests
VALID_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# =====================================================================
# 1. Allowlist Tests
# =====================================================================


def test_exported_allowlist() -> None:
    """Verify exported allowlist matches required safe action types."""
    expected = {
        "open_file_location",
        "copy_hash_to_clipboard",
        "move_to_recycle_bin",
        "mark_reviewed",
    }
    assert ALLOWED_ACTION_TYPES == expected
    assert ALLOWED_ACTION_IDS == expected


@pytest.mark.parametrize(
    "off_list_action",
    [
        "kill_process",
        "terminate_process",
        "delete_file",
        "permanent_delete",
        "rmdir",
        "format_drive",
        "modify_registry",
        "execute_code",
        "powershell_eval",
        "drop_payload",
        "unknown_action",
    ],
)
def test_off_list_actions_are_strictly_rejected(off_list_action: str) -> None:
    """Any action not on the allowlist is rejected with a descriptive reason."""
    policy = PolicyLayer()
    action = ProposedAction(action_type=off_list_action, target_process="calc.exe")
    decision = policy.validate_action(action)
    assert not decision.allowed
    assert decision.rejection_reason is not None
    assert off_list_action in decision.rejection_reason

    with pytest.raises(PolicyViolationError):
        policy.validate_action(action, raise_on_reject=True)


def test_rejected_kill_process_proposal() -> None:
    """A model or caller proposing to kill a process is unconditionally rejected."""
    policy = PolicyLayer()
    proposal = ProposedAction(
        action_type="kill_process",
        target_pid=1234,
        target_process="suspicious.exe",
        reason="Model recommended terminating suspicious process",
    )
    decision = policy.validate_action(proposal)
    assert not decision.allowed
    assert "Process termination is not permitted" in (decision.rejection_reason or "")


def test_rejected_permanent_delete_proposal(tmp_path: Path) -> None:
    """Permanent file deletion is rejected; only move_to_recycle_bin is permitted."""
    policy = PolicyLayer()
    target = tmp_path / "junk.tmp"
    target.write_text("junk")
    proposal = ProposedAction(
        action_type="delete_file",
        target_path=str(target),
    )
    decision = policy.validate_action(proposal)
    assert not decision.allowed
    assert "Permanent file deletion is not permitted" in (
        decision.rejection_reason or ""
    )


# =====================================================================
# 2. Critical Processes and PIDs
# =====================================================================


@pytest.mark.parametrize(
    "proc_name",
    [
        "System",
        "system",
        "SYSTEM",
        "System Idle Process",
        "[system process]",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "LSASS.EXE",
        "winlogon.exe",
        "svchost.exe",
        "explorer.exe",
        "dwm.exe",
    ],
)
def test_critical_processes_are_protected(proc_name: str) -> None:
    """Critical Windows processes cannot be targeted by any action."""
    is_crit, reason = is_critical_process(process_name=proc_name)
    assert is_crit
    assert reason is not None
    assert "critical Windows system process" in reason

    policy = PolicyLayer()
    action = ProposedAction(action_type="mark_reviewed", target_process=proc_name)
    decision = policy.validate_action(action)
    assert not decision.allowed
    assert "critical Windows system process" in (decision.rejection_reason or "")


@pytest.mark.parametrize("pid", [0, 4])
def test_critical_pids_are_protected(pid: int) -> None:
    """PIDs 0 (System Idle) and 4 (System) cannot be targeted."""
    is_crit, reason = is_critical_process(pid=pid)
    assert is_crit
    assert reason is not None
    assert f"PID {pid}" in reason

    policy = PolicyLayer()
    action = ProposedAction(action_type="mark_reviewed", target_pid=pid)
    decision = policy.validate_action(action)
    assert not decision.allowed
    assert f"PID {pid}" in (decision.rejection_reason or "")


def test_non_critical_process_allowed_for_review() -> None:
    """Non-critical processes may be targeted by safe actions like mark_reviewed."""
    is_crit, reason = is_critical_process(process_name="notepad.exe", pid=5678)
    assert not is_crit
    assert reason is None

    policy = PolicyLayer()
    action = ProposedAction(
        action_type="mark_reviewed",
        target_process="notepad.exe",
        target_pid=5678,
    )
    decision = policy.validate_action(action)
    assert decision.allowed


# =====================================================================
# 3. Path Safety (Traversal, UNC, Device Paths, Symlinks)
# =====================================================================


@pytest.mark.parametrize(
    "traversal_path",
    [
        "../../Windows/System32/cmd.exe",
        "..\\..\\Windows\\System32\\cmd.exe",
        "C:/safe/temp/../../Windows/System32",
        "C:\\safe\\temp\\..\\..\\Windows\\System32",
        "/foo/bar/../..",
        "..",
        "foo/../bar",
    ],
)
def test_path_traversal_is_rejected(traversal_path: str) -> None:
    """Any traversal attempt using '..' is detected and rejected."""
    assert detect_traversal(traversal_path)
    res = normalize_and_validate_path(traversal_path)
    assert not res.is_valid
    assert "traversal" in (res.rejection_reason or "").lower()

    policy = PolicyLayer()
    decision = policy.validate_action(
        ProposedAction(
            action_type="move_to_recycle_bin",
            target_path=traversal_path,
        )
    )
    assert not decision.allowed
    assert "traversal" in (decision.rejection_reason or "").lower()


@pytest.mark.parametrize(
    "unc_path",
    [
        r"\\attacker\share\payload.dll",
        r"\\192.168.1.50\c$\Windows\System32",
        "//server/share/file.txt",
        r"\\?\UNC\server\share\file",
        "//?/UNC/server/share/file",
    ],
)
def test_unc_paths_are_rejected(unc_path: str) -> None:
    """UNC network paths are rejected to prevent NTLM leak and remote exploits."""
    assert detect_unc(unc_path)
    res = normalize_and_validate_path(unc_path)
    assert not res.is_valid
    assert "UNC" in (res.rejection_reason or "")

    policy = PolicyLayer()
    decision = policy.validate_action(
        ProposedAction(
            action_type="open_file_location",
            target_path=unc_path,
        )
    )
    assert not decision.allowed
    assert "UNC" in (decision.rejection_reason or "")


@pytest.mark.parametrize(
    "device_path",
    [
        r"\\.\PhysicalDrive0",
        r"\\.\C:",
        r"\\?\C:\Windows",
        r"\??\C:\Windows",
        "CON",
        "prn",
        "aux",
        "nul",
        "com1",
        "lpt1",
        "con.txt",
        "nul.dat",
        r"C:\temp\CON.txt",
    ],
)
def test_device_paths_and_reserved_names_are_rejected(device_path: str) -> None:
    """DOS device names and raw volume devices are rejected."""
    assert detect_device_path(device_path)
    res = normalize_and_validate_path(device_path)
    assert not res.is_valid
    assert (
        "device" in (res.rejection_reason or "").lower()
        or "reserved" in (res.rejection_reason or "").lower()
    )


def test_symlink_escape_rejection(tmp_path: Path) -> None:
    """A symlink located in a safe folder pointing to a protected folder is blocked."""
    protected_dir = tmp_path / "ProtectedDocs"
    protected_dir.mkdir()
    secret_file = protected_dir / "secret.docx"
    secret_file.write_text("confidential")

    safe_dir = tmp_path / "SafeTemp"
    safe_dir.mkdir()
    symlink_file = safe_dir / "link_to_secret.docx"

    locations = StorageLocations(protected=(str(protected_dir),), safe=(str(safe_dir),))

    try:
        symlink_file.symlink_to(secret_file)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation requires elevated permissions on this system")

    # Detect escape
    is_esc, reason = detect_symlink_escape(symlink_file, locations=locations)
    assert is_esc
    assert reason is not None
    assert "Symlink escape detected" in reason

    policy = PolicyLayer(locations=locations)
    decision = policy.validate_action(
        ProposedAction(
            action_type="move_to_recycle_bin",
            target_path=str(symlink_file),
        )
    )
    assert not decision.allowed
    assert "protected" in (decision.rejection_reason or "").lower()


# =====================================================================
# 4. Protected Paths Tests
# =====================================================================


@pytest.mark.parametrize(
    "protected_folder_name",
    [
        "Windows",
        "Program Files",
        "Program Files (x86)",
        "ProgramData",
        "Documents",
        "Desktop",
        "Pictures",
        "Music",
        "Videos",
        "$Recycle.Bin",
        "System Volume Information",
        "Recovery",
    ],
)
def test_protected_folders_are_blocked_from_recycle_bin(
    tmp_path: Path, protected_folder_name: str
) -> None:
    """Files inside system and personal folders cannot be moved to Recycle Bin."""
    folder = tmp_path / protected_folder_name
    folder.mkdir(parents=True)
    target_file = folder / "test.file"
    target_file.write_text("important data")

    locations = StorageLocations(
        protected=(str(tmp_path / protected_folder_name),),
        safe=(),
    )
    is_prot, reason = is_protected_path(target_file, locations=locations)
    assert is_prot
    assert reason is not None

    policy = PolicyLayer(locations=locations)
    decision = policy.validate_action(
        ProposedAction(
            action_type="move_to_recycle_bin",
            target_path=str(target_file),
        )
    )
    assert not decision.allowed
    assert "protected" in (decision.rejection_reason or "").lower()


def test_systemroot_is_protected() -> None:
    """The actual host Windows SystemRoot is unconditionally protected."""
    sys_root = os.environ.get("SystemRoot", "C:/Windows")
    policy = PolicyLayer()
    decision = policy.validate_action(
        ProposedAction(
            action_type="move_to_recycle_bin",
            target_path=f"{sys_root}/System32/cmd.exe",
        )
    )
    assert not decision.allowed
    assert "protected" in (decision.rejection_reason or "").lower()


# =====================================================================
# 5. Dry-Run Preview Tests
# =====================================================================


def test_dry_run_preview_lists_exact_changes(tmp_path: Path) -> None:
    """Dry-run preview details path, size, count, and destination without deleting."""
    safe_dir = tmp_path / "SafeTemp"
    safe_dir.mkdir()
    target_file = safe_dir / "cache.bin"
    content = b"x" * 2048
    target_file.write_bytes(content)

    locations = StorageLocations(protected=(), safe=(str(safe_dir),))
    audit_log = tmp_path / "audit.jsonl"
    policy = PolicyLayer(locations=locations, log_path=audit_log)

    proposal = ProposedAction(
        action_type="move_to_recycle_bin",
        target_path=str(target_file),
    )
    preview = policy.preview_action(proposal)

    assert preview.allowed
    assert preview.requires_confirmation is True
    assert preview.target_size_bytes == 2048
    assert preview.target_item_count == 1
    assert preview.destination == "Windows Recycle Bin"
    assert "2,048 bytes" in preview.description
    assert len(preview.changes) >= 2
    assert preview.fingerprint != ""

    # Crucial guarantee: file still exists untouched on disk after preview!
    assert target_file.exists()
    assert target_file.read_bytes() == content


def test_dry_run_preview_directory(tmp_path: Path) -> None:
    """Dry-run preview of a directory recursively computes total size and file count."""
    safe_dir = tmp_path / "SafeCacheDir"
    safe_dir.mkdir()
    (safe_dir / "f1.tmp").write_bytes(b"a" * 500)
    (safe_dir / "f2.tmp").write_bytes(b"b" * 700)
    sub = safe_dir / "sub"
    sub.mkdir()
    (sub / "f3.tmp").write_bytes(b"c" * 300)

    policy = PolicyLayer(
        locations=StorageLocations(protected=(), safe=(str(safe_dir),))
    )
    preview = policy.preview_action(
        ProposedAction(
            action_type="move_to_recycle_bin",
            target_path=str(safe_dir),
        )
    )
    assert preview.allowed
    assert preview.target_size_bytes == 1500
    assert preview.target_item_count == 5  # root dir + 1 subdir + 3 files


def test_preview_nonexistent_file_rejected(tmp_path: Path) -> None:
    """Previewing a file that does not exist fails with an informative error."""
    policy = PolicyLayer(locations=StorageLocations(protected=(), safe=()))
    preview = policy.preview_action(
        ProposedAction(
            action_type="move_to_recycle_bin",
            target_path=str(tmp_path / "does_not_exist.tmp"),
        )
    )
    assert not preview.allowed
    assert "does not exist" in (preview.rejection_reason or "")


# =====================================================================
# 6. Gated Execution and Re-validation Tests
# =====================================================================


def test_execution_without_confirmation_rejected(tmp_path: Path) -> None:
    """Attempting execution without explicit confirmation is rejected."""
    safe_file = tmp_path / "cache.tmp"
    safe_file.write_text("temp data")

    policy = PolicyLayer(locations=StorageLocations(protected=(), safe=()))
    preview = policy.preview_action(
        ProposedAction(
            action_type="move_to_recycle_bin",
            target_path=str(safe_file),
        )
    )
    assert preview.allowed

    # Execute with confirmed=False
    res = policy.execute_action(
        ProposedAction(
            action_type="move_to_recycle_bin",
            target_path=str(safe_file),
        ),
        preview=preview,
        confirmed=False,
    )
    assert not res.success
    assert "confirmation is required" in (res.error or "").lower()
    assert safe_file.exists()


def test_execution_without_preview_rejected(tmp_path: Path) -> None:
    """Attempting execution without a prior preview is rejected."""
    safe_file = tmp_path / "cache.tmp"
    safe_file.write_text("temp data")

    policy = PolicyLayer(locations=StorageLocations(protected=(), safe=()))
    res = policy.execute_action(
        ProposedAction(
            action_type="move_to_recycle_bin",
            target_path=str(safe_file),
        ),
        preview=None,
        confirmed=True,
    )
    assert not res.success
    assert "preview is required" in (res.error or "").lower()


def test_changed_path_between_preview_and_execution_rejected(tmp_path: Path) -> None:
    """If the target path changes between preview and execution, it is rejected."""
    file_a = tmp_path / "file_a.tmp"
    file_a.write_text("safe A")
    file_b = tmp_path / "file_b.tmp"
    file_b.write_text("safe B")

    policy = PolicyLayer(locations=StorageLocations(protected=(), safe=()))
    preview_a = policy.preview_action(
        ProposedAction(
            action_type="move_to_recycle_bin",
            target_path=str(file_a),
        )
    )
    assert preview_a.allowed

    # Attempt to execute on file_b using preview_a!
    res = policy.execute_action(
        ProposedAction(
            action_type="move_to_recycle_bin",
            target_path=str(file_b),
        ),
        preview=preview_a,
        confirmed=True,
    )
    assert not res.success
    assert "Target path changed between preview" in (res.error or "")
    assert file_a.exists()
    assert file_b.exists()


def test_toctou_modification_between_preview_and_execution_rejected(
    tmp_path: Path,
) -> None:
    """If file content/size changes between preview and execution, reject it."""
    target_file = tmp_path / "tampered.tmp"
    target_file.write_bytes(b"initial content")

    policy = PolicyLayer(locations=StorageLocations(protected=(), safe=()))
    preview = policy.preview_action(
        ProposedAction(
            action_type="move_to_recycle_bin",
            target_path=str(target_file),
        )
    )
    assert preview.allowed

    # Modify file after preview
    target_file.write_bytes(b"modified altered content with different size")

    mock_send2trash = Mock()
    res = policy.execute_action(
        ProposedAction(
            action_type="move_to_recycle_bin",
            target_path=str(target_file),
        ),
        preview=preview,
        confirmed=True,
        hooks={"send2trash": mock_send2trash},
    )
    assert not res.success
    assert "Target item was modified between preview and execution" in (res.error or "")
    mock_send2trash.assert_not_called()


def test_successful_execution_via_send2trash(tmp_path: Path) -> None:
    """When confirmed with valid preview, send2trash is invoked and logged."""
    safe_file = tmp_path / "cache.tmp"
    safe_file.write_text("delete me safely")

    mock_send2trash = Mock()
    audit_log = tmp_path / "audit.jsonl"
    policy = PolicyLayer(
        locations=StorageLocations(protected=(), safe=()),
        log_path=audit_log,
    )

    action = ProposedAction(
        action_type="move_to_recycle_bin",
        target_path=str(safe_file),
    )
    preview = policy.preview_action(action)
    assert preview.allowed

    res = policy.execute_action(
        action,
        preview=preview,
        confirmed=True,
        hooks={"send2trash": mock_send2trash},
    )
    assert res.success
    assert "Successfully moved" in res.message
    mock_send2trash.assert_called_once_with(str(safe_file.resolve()))


# =====================================================================
# 7. Other Allowed Action Types
# =====================================================================


def test_open_file_location_allowed(tmp_path: Path) -> None:
    """open_file_location on a safe path is allowed and executed."""
    file = tmp_path / "decoy.exe"
    file.write_text("binary")

    mock_open = Mock()
    policy = PolicyLayer()
    action = ProposedAction(action_type="open_file_location", target_path=str(file))

    decision = policy.validate_action(action)
    assert decision.allowed

    preview = policy.preview_action(action)
    assert preview.allowed
    assert preview.requires_confirmation is False

    res = policy.execute_action(
        action, preview=preview, hooks={"open_file_location": mock_open}
    )
    assert res.success
    mock_open.assert_called_once_with(str(file.resolve()))


def test_open_file_location_missing_path() -> None:
    """open_file_location without target_path is rejected."""
    policy = PolicyLayer()
    decision = policy.validate_action(ProposedAction(action_type="open_file_location"))
    assert not decision.allowed
    assert "requires a valid 'target_path'" in (decision.rejection_reason or "")


def test_copy_hash_to_clipboard_allowed() -> None:
    """copy_hash_to_clipboard with valid hex hash is allowed."""
    mock_clip = Mock()
    policy = PolicyLayer()
    action = ProposedAction(
        action_type="copy_hash_to_clipboard",
        hash_value=VALID_SHA256,
    )
    decision = policy.validate_action(action)
    assert decision.allowed

    preview = policy.preview_action(action)
    assert preview.allowed
    assert preview.requires_confirmation is False

    res = policy.execute_action(
        action, preview=preview, hooks={"copy_hash_to_clipboard": mock_clip}
    )
    assert res.success
    mock_clip.assert_called_once_with(VALID_SHA256)


@pytest.mark.parametrize(
    "invalid_hash",
    [
        "",
        "not-a-hash",
        "xyz123",
        "12345",  # too short
        "g" * 64,  # invalid hex char 'g'
    ],
)
def test_copy_hash_to_clipboard_invalid_hash(invalid_hash: str) -> None:
    """copy_hash_to_clipboard with malformed hash is rejected."""
    policy = PolicyLayer()
    action = ProposedAction(
        action_type="copy_hash_to_clipboard",
        hash_value=invalid_hash,
    )
    decision = policy.validate_action(action)
    assert not decision.allowed
    assert "valid hex hash" in (decision.rejection_reason or "")


def test_mark_reviewed_allowed() -> None:
    """mark_reviewed on a legitimate finding is allowed."""
    mock_mark = Mock()
    policy = PolicyLayer()
    action = ProposedAction(
        action_type="mark_reviewed",
        target_id="finding-proc-1234",
    )
    decision = policy.validate_action(action)
    assert decision.allowed

    preview = policy.preview_action(action)
    assert preview.allowed
    assert preview.requires_confirmation is False

    res = policy.execute_action(
        action, preview=preview, hooks={"mark_reviewed": mock_mark}
    )
    assert res.success
    mock_mark.assert_called_once_with("finding-proc-1234")


# =====================================================================
# 8. Model Recommendation Filtering
# =====================================================================


def test_filter_model_recommendations(tmp_path: Path) -> None:
    """Model recommendations are suggestions gated before presentation."""
    safe_file = tmp_path / "cache.tmp"
    safe_file.write_text("cache")

    recommendations = [
        # 1. Safe open file location
        ProposedAction(action_type="open_file_location", target_path=str(safe_file)),
        # 2. Unsafe: kill process
        ProposedAction(action_type="kill_process", target_pid=1234),
        # 3. Unsafe: permanent delete
        ProposedAction(action_type="delete_file", target_path=str(safe_file)),
        # 4. Unsafe: critical process targeting
        ProposedAction(action_type="mark_reviewed", target_process="lsass.exe"),
        # 5. Safe: copy hash
        ProposedAction(action_type="copy_hash_to_clipboard", hash_value=VALID_SHA256),
    ]

    decisions = filter_recommendations(recommendations)
    assert len(decisions) == 5

    assert decisions[0].allowed is True
    assert decisions[1].allowed is False
    assert "Process termination is not permitted" in (
        decisions[1].rejection_reason or ""
    )
    assert decisions[2].allowed is False
    assert "Permanent file deletion is not permitted" in (
        decisions[2].rejection_reason or ""
    )
    assert decisions[3].allowed is False
    assert "critical Windows system process" in (decisions[3].rejection_reason or "")
    assert decisions[4].allowed is True


# =====================================================================
# 9. Audit Logging (JSON Lines) Tests
# =====================================================================


def test_audit_logging_writes_json_lines(tmp_path: Path) -> None:
    """Every attempted validation, preview, and execution is appended as valid JSON."""
    log_file = tmp_path / "audit.jsonl"
    logger = PolicyAuditLogger(log_file)
    policy = PolicyLayer(audit_logger=logger)

    safe_file = tmp_path / "cache.tmp"
    safe_file.write_text("data")

    # 1. Validation of off-list action
    policy.validate_action(ProposedAction(action_type="kill_process", target_pid=999))

    # 2. Preview of safe action
    act = ProposedAction(action_type="move_to_recycle_bin", target_path=str(safe_file))
    preview = policy.preview_action(act)

    # 3. Execution of safe action
    policy.execute_action(
        act, preview=preview, confirmed=True, hooks={"send2trash": Mock()}
    )

    # Verify log content
    assert log_file.exists()
    records = logger.read_records()
    assert len(records) >= 3

    # Check that each line is valid JSON with required schema fields
    with open(log_file, encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    assert len(lines) == len(records)
    for line in lines:
        data = json.loads(line)
        assert "timestamp" in data
        assert "event_type" in data
        assert "action_type" in data
        assert "status" in data
        assert "allowed" in data

    # Check specific events
    assert records[0].action_type == "kill_process"
    assert records[0].allowed is False
    assert records[0].status == "rejected"

    assert any(r.event_type == "execution" and r.status == "executed" for r in records)


# =====================================================================
# 10. Module Helpers Tests
# =====================================================================


def test_convenience_module_helpers(tmp_path: Path) -> None:
    """Convenience module-level helpers work as expected."""
    file = tmp_path / "helper.tmp"
    file.write_text("test")

    action = ProposedAction(action_type="move_to_recycle_bin", target_path=str(file))
    decision = validate_proposed_action(action)
    assert decision.allowed

    prev = preview_action(action)
    assert prev.allowed

    res = execute_action(
        action, preview=prev, confirmed=True, hooks={"send2trash": Mock()}
    )
    assert res.success
