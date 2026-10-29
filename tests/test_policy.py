"""Comprehensive tests for Moonlight policy layer.

Verifies:
- Strict allowlist (no process termination, no permanent file deletion).
- Protected system paths, user personal documents, and critical processes.
- Path safety: traversal rejection, UNC paths, DOS device names, symlink escapes.
- Dry-run preview listing exact changes; confirmation token required.
- send2trash-only execution.
- TOCTOU guards: changed path or modified target between preview and execution.
- Append-only JSON lines audit logging.
- Model recommendation filtering.
- Explorer file location launch via argument list (never executes target file).
- Confirmation token bound to path identity, size, mtime, and action.
- Storage classifier gating: clearly_safe, review_first with extra confirmation,
  do_not_touch blocked. User file on non-system drive.
- mark_reviewed not blocked by process name; PID 0 and 4 blocked.
- Path aliases: 8.3 short names, ADS, trailing dots/spaces, case differences,
  junctions, symlinks, and reparse point rejection.
"""

from __future__ import annotations

from collections.abc import Sequence
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
    classify_path_storage,
    detect_alternate_data_stream,
    detect_device_path,
    detect_symlink_escape,
    detect_traversal,
    detect_unc,
    execute_action,
    filter_recommendations,
    generate_confirmation_token,
    is_critical_process,
    is_protected_path,
    is_reparse_point,
    launch_file_location,
    normalize_and_validate_path,
    preview_action,
    resolve_final_path,
    strip_alternate_data_stream,
    strip_trailing_dots_and_spaces,
    validate_proposed_action,
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
        target_process="malware.exe",
        target_pid=1234,
        reason="Suspicious network beacon detected",
    )
    decision = policy.validate_action(proposal)
    assert not decision.allowed
    assert "Process termination is not permitted in Moonlight" in (
        decision.rejection_reason or ""
    )


def test_rejected_permanent_delete_proposal() -> None:
    """A model or caller proposing permanent deletion is unconditionally rejected."""
    policy = PolicyLayer()
    proposal = ProposedAction(
        action_type="permanent_delete",
        target_path="C:/Users/alice/AppData/Local/Temp/bad.bin",
        reason="Malicious file cleanup",
    )
    decision = policy.validate_action(proposal)
    assert not decision.allowed
    assert "Permanent file deletion is not permitted" in (
        decision.rejection_reason or ""
    )
    assert "move_to_recycle_bin" in (decision.rejection_reason or "")


def test_rejected_registry_modification_proposal() -> None:
    """Registry modification actions are rejected."""
    policy = PolicyLayer()
    decision = policy.validate_action(
        ProposedAction(
            action_type="modify_registry",
            target_id="HKCU\\Software\\Run",
        )
    )
    assert not decision.allowed


# =====================================================================
# 2. Critical Processes and mark_reviewed Tests
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
def test_critical_processes_detection(proc_name: str) -> None:
    """Critical Windows processes cannot be targeted by process actions."""
    is_crit, reason = is_critical_process(process_name=proc_name)
    assert is_crit
    assert reason is not None
    assert "critical Windows system process" in reason

    policy = PolicyLayer()
    # For actions other than mark_reviewed, targeting a critical process is blocked
    action = ProposedAction(action_type="open_file_location", target_process=proc_name)
    decision = policy.validate_action(action)
    assert not decision.allowed
    assert "critical Windows system process" in (decision.rejection_reason or "")


@pytest.mark.parametrize(
    "proc_name",
    [
        "System",
        "smss.exe",
        "csrss.exe",
        "services.exe",
        "lsass.exe",
        "svchost.exe",
        "explorer.exe",
    ],
)
def test_mark_reviewed_not_blocked_by_process_name(proc_name: str) -> None:
    """mark_reviewed must NOT be blocked by process name."""
    policy = PolicyLayer()
    action = ProposedAction(action_type="mark_reviewed", target_process=proc_name)
    decision = policy.validate_action(action)
    assert decision.allowed
    assert decision.rejection_reason is None

    preview = policy.preview_action(action)
    assert preview.allowed


def test_mark_reviewed_masquerading_svchost_allowed() -> None:
    """A masquerading svchost.exe running from a temp path can be marked reviewed."""
    policy = PolicyLayer()
    action = ProposedAction(
        action_type="mark_reviewed",
        target_process="svchost.exe",
        target_path="C:/Users/alice/AppData/Local/Temp/svchost.exe",
        target_pid=4412,
        reason="Analyst inspected binary; identified as benign developer utility.",
    )
    decision = policy.validate_action(action)
    assert decision.allowed
    assert decision.rejection_reason is None

    preview = policy.preview_action(action)
    assert preview.allowed
    assert "svchost.exe" in preview.description

    mock_mark = Mock()
    res = policy.execute_action(
        action, preview=preview, hooks={"mark_reviewed": mock_mark}
    )
    assert res.success
    mock_mark.assert_called_once()


@pytest.mark.parametrize("pid", [0, 4])
def test_critical_pids_are_protected_including_mark_reviewed(pid: int) -> None:
    """PIDs 0 (System Idle) and 4 (System) cannot be targeted by any action."""
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
    """Non-critical processes may be targeted by mark_reviewed."""
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
# 3. Path Safety & Aliases (8.3, ADS, Reparse, Traversal, UNC)
# =====================================================================


def test_path_traversal_detection() -> None:
    """Path traversal sequences (..) in any component are detected and blocked."""
    assert detect_traversal("..")
    assert detect_traversal("../secret.txt")
    assert detect_traversal("C:/Users/../Windows/System32")
    assert detect_traversal("subdir/../../Windows")
    assert detect_traversal("foo\\..\\bar")
    assert not detect_traversal("C:/Users/alice/AppData/Local/Temp/file.tmp")
    assert not detect_traversal("safe_file_name..txt")  # Double dot in filename ok


def test_path_traversal_rejected_by_policy() -> None:
    """Proposed actions attempting path traversal are rejected."""
    policy = PolicyLayer()
    decision = policy.validate_action(
        ProposedAction(
            action_type="move_to_recycle_bin",
            target_path="C:/Users/alice/../../Windows/System32/calc.exe",
        )
    )
    assert not decision.allowed
    assert "Path traversal is not permitted" in (decision.rejection_reason or "")


def test_unc_path_detection() -> None:
    """UNC network paths (SMB/NetBIOS) are detected and blocked."""
    assert detect_unc("\\\\attacker-server\\share\\malware.exe")
    assert detect_unc("//192.168.1.100/c$/windows/calc.exe")
    assert detect_unc("\\\\?\\UNC\\server\\share\\file.txt")
    assert not detect_unc("C:/Users/alice/Temp/file.txt")


def test_unc_path_rejected_by_policy() -> None:
    """UNC paths are rejected to prevent credential-leak attacks."""
    policy = PolicyLayer()
    decision = policy.validate_action(
        ProposedAction(
            action_type="move_to_recycle_bin",
            target_path="\\\\attacker-smb\\share\\file.bin",
        )
    )
    assert not decision.allowed
    assert "UNC / network paths are not permitted" in (decision.rejection_reason or "")


@pytest.mark.parametrize(
    "device_name",
    [
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "COM9",
        "LPT1",
        "LPT9",
        "con.txt",
        "NUL.dat",
        "C:/Temp/CON",
        "\\\\.\\PhysicalDrive0",
        "//./C:",
        "\\\\?\\Volume{12345678-1234-1234-1234-123456789abc}",
    ],
)
def test_device_paths_and_dos_names_rejected(device_name: str) -> None:
    """Windows device namespaces and reserved DOS names are strictly rejected."""
    assert detect_device_path(device_name)
    policy = PolicyLayer()
    decision = policy.validate_action(
        ProposedAction(
            action_type="move_to_recycle_bin",
            target_path=device_name,
        )
    )
    assert not decision.allowed
    assert "Device paths and reserved DOS names are not permitted" in (
        decision.rejection_reason or ""
    )


def test_alternate_data_stream_detection() -> None:
    """Alternate data streams are detected and handled safely."""
    assert detect_alternate_data_stream("C:/temp/file.txt:stream")
    assert detect_alternate_data_stream("C:/Windows/System32:hidden")
    assert detect_alternate_data_stream("relative/path.bin:$DATA")
    assert not detect_alternate_data_stream("C:/temp/file.txt")
    assert not detect_alternate_data_stream("D:/Data/archive.zip")

    base, stream = strip_alternate_data_stream("C:/temp/file.txt:zone.identifier")
    assert base == "C:/temp/file.txt"
    assert stream == "zone.identifier"


def test_alternate_data_stream_on_protected_location_is_protected() -> None:
    """Targeting an alternate data stream on a protected folder is protected."""
    locations = StorageLocations(protected=("C:/Windows",), safe=())
    is_prot, reason = is_protected_path(
        "C:/Windows/System32:stream", locations=locations
    )
    assert is_prot
    assert reason is not None
    assert "protected" in reason.lower()


def test_alternate_data_stream_rejected_for_mutation() -> None:
    """Alternate data streams cannot be targeted for recycling."""
    res = normalize_and_validate_path("C:/temp/file.txt:stream", for_mutation=True)
    assert not res.is_valid
    assert "Alternate data streams" in (res.rejection_reason or "")


def test_trailing_dots_and_spaces_stripped() -> None:
    """Win32 trailing dots and spaces are stripped during normalization."""
    assert (
        strip_trailing_dots_and_spaces("C:/Windows/System32.") == "C:/Windows/System32"
    )
    assert (
        strip_trailing_dots_and_spaces("C:/Windows /System32") == "C:/Windows/System32"
    )
    assert (
        strip_trailing_dots_and_spaces("C:/Windows/System32/cmd.exe. ")
        == "C:/Windows/System32/cmd.exe"
    )

    locations = StorageLocations(protected=("C:/Windows",), safe=())
    is_prot, _ = is_protected_path("C:/Windows/System32.", locations=locations)
    assert is_prot
    is_prot2, _ = is_protected_path("C:/Windows /System32", locations=locations)
    assert is_prot2


def test_case_differences_normalized() -> None:
    """Case differences in paths are normalized for comparison."""
    locations = StorageLocations(protected=("C:/Windows",), safe=())
    is_prot, reason = is_protected_path("c:/wInDoWs/sYsTeM32", locations=locations)
    assert is_prot
    assert reason is not None


def test_8dot3_short_names_resolved() -> None:
    """8.3 short names are resolved to long names before checking protection."""
    # On Windows, C:/PROGRA~1 resolves to C:/Program Files
    progra = Path("C:/PROGRA~1")
    if progra.exists():
        resolved = resolve_final_path(progra)
        assert "Program Files" in str(resolved)
        locations = StorageLocations(protected=("C:/Program Files",), safe=())
        is_prot, _ = is_protected_path(str(progra), locations=locations)
        assert is_prot


def test_reparse_point_rejected_as_recycle_target(tmp_path: Path) -> None:
    """Reparse points (junctions or symlinks) are rejected as recycle targets."""
    target_dir = tmp_path / "actual_dir"
    target_dir.mkdir()
    (target_dir / "item.txt").write_text("hello")

    link_dir = tmp_path / "junction_link"
    try:
        link_dir.symlink_to(target_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation requires elevated permissions on this system")

    assert is_reparse_point(link_dir)
    res = normalize_and_validate_path(str(link_dir), for_mutation=True)
    assert not res.is_valid
    assert "reparse point" in (res.rejection_reason or "").lower()

    policy = PolicyLayer()
    decision = policy.validate_action(
        ProposedAction(action_type="move_to_recycle_bin", target_path=str(link_dir))
    )
    assert not decision.allowed
    assert "reparse point" in (decision.rejection_reason or "").lower()


def test_symlink_escape_rejection(tmp_path: Path) -> None:
    """A symlink pointing inside a protected folder is detected and rejected."""
    secret_dir = tmp_path / "protected_secret"
    secret_dir.mkdir()
    secret_file = secret_dir / "secret.key"
    secret_file.write_text("super secret")

    locations = StorageLocations(
        protected=(str(secret_dir),),
        safe=(),
    )

    escape_dir = tmp_path / "safe_user_dir"
    escape_dir.mkdir()
    symlink_file = escape_dir / "link_to_secret.txt"

    try:
        symlink_file.symlink_to(secret_file)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation requires elevated permissions on this system")

    is_esc, reason = detect_symlink_escape(symlink_file, locations=locations)
    assert is_esc
    assert reason is not None
    assert "escape detected" in reason.lower()

    policy = PolicyLayer(locations=locations)
    decision = policy.validate_action(
        ProposedAction(
            action_type="move_to_recycle_bin",
            target_path=str(symlink_file),
        )
    )
    assert not decision.allowed
    err = (decision.rejection_reason or "").lower()
    assert "protected" in err or "reparse point" in err or "escape" in err


# =====================================================================
# 4. Storage Classifier Gating Tests
# =====================================================================


def test_move_to_recycle_bin_clearly_safe(tmp_path: Path) -> None:
    """Paths marked clearly_safe by the classifier can be previewed and executed."""
    safe_folder = tmp_path / "SafeTemp"
    safe_folder.mkdir()
    target = safe_folder / "cache.tmp"
    target.write_text("cache data")

    locations = StorageLocations(protected=(), safe=(str(safe_folder),))
    cat, _ = classify_path_storage(target, locations=locations)
    assert cat == "clearly_safe"

    policy = PolicyLayer(locations=locations)
    action = ProposedAction(action_type="move_to_recycle_bin", target_path=str(target))
    decision = policy.validate_action(action)
    assert decision.allowed

    preview = policy.preview_action(action)
    assert preview.allowed
    assert preview.requires_confirmation is True
    assert preview.requires_extra_confirmation is False
    assert preview.storage_category == "clearly_safe"
    assert preview.confirmation_token is not None

    # Execution with confirmation token succeeds
    mock_trash = Mock()
    res = policy.execute_action(
        action,
        preview=preview,
        confirmed=True,
        confirmation_token=preview.confirmation_token,
        hooks={"send2trash": mock_trash},
    )
    assert res.success
    mock_trash.assert_called_once()


def test_move_to_recycle_bin_review_first_requires_extra_confirmation(
    tmp_path: Path,
) -> None:
    """Paths marked review_first require explicit extra confirmation."""
    unrecognized = tmp_path / "staging_build"
    unrecognized.mkdir()
    target = unrecognized / "output.bin"
    target.write_text("build binary")

    locations = StorageLocations(protected=(), safe=())
    cat, reason = classify_path_storage(target, locations=locations)
    assert cat == "review_first"

    policy = PolicyLayer(locations=locations)
    action = ProposedAction(action_type="move_to_recycle_bin", target_path=str(target))
    preview = policy.preview_action(action)
    assert preview.allowed
    assert preview.requires_confirmation is True
    assert preview.requires_extra_confirmation is True
    assert preview.storage_category == "review_first"

    # 1. Execution with confirmed=True and token, but WITHOUT extra_confirmed fails
    mock_trash = Mock()
    res_fail = policy.execute_action(
        action,
        preview=preview,
        confirmed=True,
        confirmation_token=preview.confirmation_token,
        extra_confirmed=False,
        hooks={"send2trash": mock_trash},
    )
    assert not res_fail.success
    assert "extra confirmation" in (res_fail.error or "").lower()
    mock_trash.assert_not_called()

    # 2. Execution WITH extra_confirmed=True succeeds
    res_success = policy.execute_action(
        action,
        preview=preview,
        confirmed=True,
        confirmation_token=preview.confirmation_token,
        extra_confirmed=True,
        hooks={"send2trash": mock_trash},
    )
    assert res_success.success
    mock_trash.assert_called_once()


def test_move_to_recycle_bin_do_not_touch_never_allowed(tmp_path: Path) -> None:
    """Paths marked do_not_touch are never allowed to be moved to Recycle Bin."""
    doc_folder = tmp_path / "Documents"
    doc_folder.mkdir()
    doc_file = doc_folder / "notes.txt"
    doc_file.write_text("personal notes")

    locations = StorageLocations(protected=(str(doc_folder),), safe=())
    cat, _ = classify_path_storage(doc_file, locations=locations)
    assert cat == "do_not_touch"

    policy = PolicyLayer(locations=locations)
    action = ProposedAction(
        action_type="move_to_recycle_bin", target_path=str(doc_file)
    )
    decision = policy.validate_action(action)
    assert not decision.allowed
    err = (decision.rejection_reason or "").lower()
    assert "do_not_touch" in err or "protected" in err

    preview = policy.preview_action(action)
    assert not preview.allowed
    prev_err = (preview.rejection_reason or "").lower()
    assert "do_not_touch" in prev_err or "protected" in prev_err


def test_user_file_on_non_system_drive_not_marked_safe() -> None:
    """A user file on a non-system drive is not marked safe by the classifier."""
    # Emulate a path on D: drive
    non_sys_tool = Path("D:/UserData/tools/utility.bin")
    locations = StorageLocations(
        protected=("C:/Windows", "C:/Program Files"),
        safe=("C:/Users/alice/AppData/Local/Temp",),
    )
    cat, reason = classify_path_storage(non_sys_tool, locations=locations)
    # Not safe, not system root: classified as review_first (unrecognized)
    assert cat == "review_first"
    assert "unrecognized" in reason

    # A document file on D: drive is classified as do_not_touch
    non_sys_doc = Path("D:/UserData/finance/taxes.xlsx")
    cat_doc, reason_doc = classify_path_storage(non_sys_doc, locations=locations)
    assert cat_doc == "do_not_touch"
    assert "personal_document" in reason_doc


# =====================================================================
# 5. Confirmation Token and Execution Safety Tests
# =====================================================================


def test_execution_requires_token_not_just_confirmed(tmp_path: Path) -> None:
    """A bare confirmed=True must not be enough; confirmation_token is required."""
    safe_dir = tmp_path / "SafeTemp"
    safe_dir.mkdir()
    file = safe_dir / "cache.tmp"
    file.write_text("data")

    locations = StorageLocations(protected=(), safe=(str(safe_dir),))
    policy = PolicyLayer(locations=locations)
    action = ProposedAction(action_type="move_to_recycle_bin", target_path=str(file))
    preview = policy.preview_action(action)
    assert preview.allowed
    assert preview.confirmation_token is not None

    # Bare confirmed=True without token is rejected
    res = policy.execute_action(
        action,
        preview=preview,
        confirmed=True,
        confirmation_token=None,
    )
    assert not res.success
    assert "confirmation token is required" in (res.error or "").lower()


def test_mismatched_confirmation_token_rejected(tmp_path: Path) -> None:
    """Mismatched confirmation token is rejected."""
    safe_dir = tmp_path / "SafeTemp"
    safe_dir.mkdir()
    file = safe_dir / "cache.tmp"
    file.write_text("data")

    locations = StorageLocations(protected=(), safe=(str(safe_dir),))
    policy = PolicyLayer(locations=locations)
    action = ProposedAction(action_type="move_to_recycle_bin", target_path=str(file))
    preview = policy.preview_action(action)

    res = policy.execute_action(
        action,
        preview=preview,
        confirmed=True,
        confirmation_token="cfm_invalid_fake_token_12345",
    )
    assert not res.success
    assert "invalid or mismatched confirmation token" in (res.error or "").lower()


def test_token_bound_to_size_mtime_action(tmp_path: Path) -> None:
    """Confirmation token is strictly bound to path, size, mtime, and action."""
    tok1 = generate_confirmation_token(
        "move_to_recycle_bin", "C:/temp/f.tmp", 100, 1000
    )
    tok2 = generate_confirmation_token(
        "move_to_recycle_bin", "C:/temp/f.tmp", 200, 1000
    )
    tok3 = generate_confirmation_token(
        "move_to_recycle_bin", "C:/temp/f.tmp", 100, 2000
    )
    tok4 = generate_confirmation_token("open_file_location", "C:/temp/f.tmp", 100, 1000)
    tok5 = generate_confirmation_token(
        "move_to_recycle_bin", "C:/other/f.tmp", 100, 1000
    )

    # Any change changes the token
    assert tok1 != tok2
    assert tok1 != tok3
    assert tok1 != tok4
    assert tok1 != tok5


def test_toctou_modification_between_preview_and_execution_rejected(
    tmp_path: Path,
) -> None:
    """If target item is modified between preview and execution, it is rejected."""
    safe_dir = tmp_path / "SafeTemp"
    safe_dir.mkdir()
    target_file = safe_dir / "file.tmp"
    target_file.write_text("initial content")

    locations = StorageLocations(protected=(), safe=(str(safe_dir),))
    policy = PolicyLayer(locations=locations)
    action = ProposedAction(
        action_type="move_to_recycle_bin", target_path=str(target_file)
    )
    preview = policy.preview_action(action)
    assert preview.allowed

    # Modify file content on disk (changing size and mtime)
    target_file.write_text("tampered content with different length")

    mock_send2trash = Mock()
    res = policy.execute_action(
        action,
        preview=preview,
        confirmed=True,
        confirmation_token=preview.confirmation_token,
        hooks={"send2trash": mock_send2trash},
    )
    assert not res.success
    assert "modified between preview and execution" in (res.error or "")
    mock_send2trash.assert_not_called()


# =====================================================================
# 6. open_file_location Safety Tests
# =====================================================================


def test_open_file_location_never_executes_target(tmp_path: Path) -> None:
    """open_file_location must never execute or open the target file.

    Uses Explorer with file selected via argument list (no shell string or startfile).
    """
    fake_exe = tmp_path / "suspicious_decoy.exe"
    fake_exe.write_bytes(b"\x90\x90\x90\xcc")

    policy = PolicyLayer()
    action = ProposedAction(
        action_type="open_file_location",
        target_path=str(fake_exe),
    )
    decision = policy.validate_action(action)
    assert decision.allowed

    preview = policy.preview_action(action)
    assert preview.allowed
    assert preview.requires_confirmation is False

    runner_calls: list[list[str]] = []

    def fake_runner(cmd: Sequence[str]) -> None:
        runner_calls.append(list(cmd))

    res = policy.execute_action(
        action,
        preview=preview,
        hooks={"process_runner": fake_runner},
    )
    assert res.success
    assert len(runner_calls) == 1
    cmd = runner_calls[0]
    # Explorer must be invoked with argument list selecting target
    assert cmd[0] == "explorer.exe"
    assert cmd[1] == f"/select,{fake_exe.resolve()}"
    # Target executable is NEVER invoked
    assert cmd[0] != str(fake_exe.resolve())


def test_launch_file_location_helper(tmp_path: Path) -> None:
    """launch_file_location helper formats argument list correctly."""
    file = tmp_path / "item.txt"
    file.write_text("hello")

    captured: list[list[str]] = []
    args = launch_file_location(file, runner=lambda cmd: captured.append(list(cmd)))
    assert args == ["explorer.exe", f"/select,{file.resolve()}"]
    assert captured == [args]


def test_open_file_location_directory(tmp_path: Path) -> None:
    """Opening location of a directory passes directory directly."""
    dir_path = tmp_path / "my_dir"
    dir_path.mkdir()

    captured: list[list[str]] = []
    args = launch_file_location(dir_path, runner=lambda cmd: captured.append(list(cmd)))
    assert args == ["explorer.exe", str(dir_path.resolve())]
    assert captured == [args]


# =====================================================================
# 7. Model Recommendation Filtering & Audit Logging
# =====================================================================


def test_filter_model_recommendations(tmp_path: Path) -> None:
    """Model recommendations are filtered before presentation."""
    safe_file = tmp_path / "cache.tmp"
    safe_file.write_text("cache")

    recommendations = [
        ProposedAction(action_type="open_file_location", target_path=str(safe_file)),
        ProposedAction(action_type="kill_process", target_pid=1234),
        ProposedAction(action_type="delete_file", target_path=str(safe_file)),
        ProposedAction(action_type="copy_hash_to_clipboard", hash_value=VALID_SHA256),
        ProposedAction(action_type="mark_reviewed", target_pid=4),
        ProposedAction(action_type="unknown_action", target_id="item-1"),
    ]

    decisions = filter_recommendations(recommendations)
    assert len(decisions) == 6
    allowed = [d.allowed for d in decisions]
    assert allowed == [True, False, False, True, False, False]


def test_audit_logging_writes_json_lines(tmp_path: Path) -> None:
    """Every attempted validation, preview, and execution is appended as valid JSON."""
    safe_dir = tmp_path / "SafeTemp"
    safe_dir.mkdir()
    safe_file = safe_dir / "cache.tmp"
    safe_file.write_text("data")

    log_file = tmp_path / "audit.jsonl"
    logger = PolicyAuditLogger(log_file)
    locations = StorageLocations(protected=(), safe=(str(safe_dir),))
    policy = PolicyLayer(locations=locations, audit_logger=logger)

    # 1. Validation of off-list action
    policy.validate_action(ProposedAction(action_type="kill_process", target_pid=999))

    # 2. Preview of safe action
    act = ProposedAction(action_type="move_to_recycle_bin", target_path=str(safe_file))
    preview = policy.preview_action(act)

    # 3. Execution of safe action
    policy.execute_action(
        act,
        preview=preview,
        confirmed=True,
        confirmation_token=preview.confirmation_token,
        hooks={"send2trash": Mock()},
    )

    assert log_file.exists()
    records = logger.read_records()
    assert len(records) >= 3

    assert records[0].action_type == "kill_process"
    assert records[0].allowed is False
    assert any(r.event_type == "execution" and r.status == "executed" for r in records)


def test_convenience_module_helpers(tmp_path: Path) -> None:
    """Convenience module-level helpers work as expected."""
    safe_dir = tmp_path / "SafeDir"
    safe_dir.mkdir()
    file = safe_dir / "helper.tmp"
    file.write_text("test")

    locations = StorageLocations(protected=(), safe=(str(safe_dir),))
    action = ProposedAction(action_type="move_to_recycle_bin", target_path=str(file))
    decision = validate_proposed_action(action, locations=locations)
    assert decision.allowed

    prev = preview_action(action, locations=locations)
    assert prev.allowed

    res = execute_action(
        action,
        preview=prev,
        confirmed=True,
        confirmation_token=prev.confirmation_token,
        locations=locations,
        hooks={"send2trash": Mock()},
    )
    assert res.success
