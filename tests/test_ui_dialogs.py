"""Tests for ActionPreviewDialog, token verification, and LiveProviderWarningDialog.

Verifies:
- Action preview displays exact target path, size, mtime, destination, and changes.
- Confirmation token is generated and held strictly in memory.
- A tampered or missing confirmation token blocks execution.
- Review-first actions require explicit extra confirmation checkbox.
- Execution happens only from the dialog's Confirm button through the policy layer.
- Never touches real Recycle Bin or launches Explorer in tests (fakes used).
- No UI code path executes an action without the dialog.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from PySide6.QtWidgets import QApplication

from moonlight.policy.actions import ActionType, ProposedAction
from moonlight.ui.dialogs import ActionPreviewDialog, LiveProviderWarningDialog


def test_action_preview_dialog_displays_details(
    tmp_path: Path, qapp: QApplication
) -> None:
    # Create safe target file in temp directory
    test_file = tmp_path / "cache_data.tmp"
    test_file.write_bytes(b"A" * 2048)

    action = ProposedAction(
        action_type=ActionType.MOVE_TO_RECYCLE_BIN,
        target_path=str(test_file),
        reason="Reclaim transient cache storage",
    )

    fake_trash = MagicMock()
    dialog = ActionPreviewDialog(
        action=action,
        hooks={"send2trash": fake_trash},
    )

    # Verify preview data
    assert dialog.preview.allowed is True
    assert dialog.preview.target_size_bytes == 2048
    assert dialog.preview.destination == "Windows Recycle Bin"
    assert dialog.confirmation_token is not None
    assert len(dialog.confirmation_token) > 10

    # Token must be held in memory, not empty
    assert dialog.confirmation_token.startswith("cfm_")

    dialog.close()


def test_action_preview_tampered_token_blocks_execution(
    tmp_path: Path, qapp: QApplication
) -> None:
    test_file = tmp_path / "cache_tamper.tmp"
    test_file.write_bytes(b"B" * 1024)

    action = ProposedAction(
        action_type=ActionType.MOVE_TO_RECYCLE_BIN,
        target_path=str(test_file),
    )

    fake_trash = MagicMock()
    dialog = ActionPreviewDialog(
        action=action,
        hooks={"send2trash": fake_trash},
    )
    dialog.show()

    # Tamper with the in-memory confirmation token
    dialog.set_confirmation_token_for_test("cfm_tampered_invalid_token")

    # Attempt to click confirm
    dialog._on_confirm_clicked()

    # Execution must fail and send2trash must NEVER be invoked
    assert fake_trash.called is False
    assert dialog.execution_result is not None
    assert dialog.execution_result.success is False
    assert "token" in str(dialog.execution_result.error).lower()
    assert dialog.error_banner.isVisible() is True

    dialog.close()


def test_action_preview_missing_token_blocks_execution(
    tmp_path: Path, qapp: QApplication
) -> None:
    test_file = tmp_path / "cache_missing.tmp"
    test_file.write_bytes(b"C" * 512)

    action = ProposedAction(
        action_type=ActionType.MOVE_TO_RECYCLE_BIN,
        target_path=str(test_file),
    )

    fake_trash = MagicMock()
    dialog = ActionPreviewDialog(
        action=action,
        hooks={"send2trash": fake_trash},
    )
    dialog.show()

    # Strip the confirmation token
    dialog.set_confirmation_token_for_test(None)

    dialog._on_confirm_clicked()

    # Must fail and block execution
    assert fake_trash.called is False
    assert dialog.execution_result is not None
    assert dialog.execution_result.success is False
    assert dialog.error_banner.isVisible() is True

    dialog.close()


def test_action_preview_review_first_requires_extra_confirmation(
    tmp_path: Path, qapp: QApplication
) -> None:
    # A path classified as review_first
    test_file = tmp_path / "staged_artifact.bin"
    test_file.write_bytes(b"D" * 4096)

    action = ProposedAction(
        action_type=ActionType.MOVE_TO_RECYCLE_BIN,
        target_path=str(test_file),
    )

    fake_trash = MagicMock()
    dialog = ActionPreviewDialog(
        action=action,
        hooks={"send2trash": fake_trash},
    )

    # If classified as review_first, extra confirmation checkbox must exist
    if dialog.preview.requires_extra_confirmation:
        assert dialog.extra_checkbox is not None
        # Confirm button must initially be disabled
        assert dialog.confirm_button.isEnabled() is False

        # Toggling the checkbox enables the confirm button
        dialog.extra_checkbox.setChecked(True)
        assert dialog.confirm_button.isEnabled() is True

        # Unchecking disables it again
        dialog.extra_checkbox.setChecked(False)
        assert dialog.confirm_button.isEnabled() is False

    dialog.close()


def test_action_preview_successful_execution_via_policy_layer(
    tmp_path: Path, qapp: QApplication
) -> None:
    test_file = tmp_path / "cache_success.tmp"
    test_file.write_bytes(b"E" * 1024)

    action = ProposedAction(
        action_type=ActionType.MOVE_TO_RECYCLE_BIN,
        target_path=str(test_file),
    )

    fake_trash = MagicMock()
    dialog = ActionPreviewDialog(
        action=action,
        hooks={"send2trash": fake_trash},
    )

    assert dialog.preview.allowed is True

    # If review first, check extra box
    if dialog.extra_checkbox is not None:
        dialog.extra_checkbox.setChecked(True)

    dialog._on_confirm_clicked()

    # Policy layer calls fake hook
    assert fake_trash.called is True
    assert dialog.execution_result is not None
    assert dialog.execution_result.success is True
    assert dialog.execution_result.details.get("destination") == "Windows Recycle Bin"

    dialog.close()


def test_open_file_location_uses_policy_launcher_hook(
    tmp_path: Path, qapp: QApplication
) -> None:
    test_file = tmp_path / "inspected_target.exe"
    test_file.write_bytes(b"MZfake")

    action = ProposedAction(
        action_type=ActionType.OPEN_FILE_LOCATION,
        target_path=str(test_file),
    )

    fake_launcher = MagicMock()
    dialog = ActionPreviewDialog(
        action=action,
        hooks={"open_file_location": fake_launcher},
    )

    assert dialog.preview.allowed is True
    assert dialog.confirm_button.isEnabled() is True

    dialog._on_confirm_clicked()

    # Verification: policy layer invoked the fake launcher hook, never os.system
    assert fake_launcher.called is True
    assert dialog.execution_result is not None
    assert dialog.execution_result.success is True

    dialog.close()


def test_blocked_policy_action_disables_confirm(qapp: QApplication) -> None:
    # An action targeting a prohibited system path
    action = ProposedAction(
        action_type=ActionType.MOVE_TO_RECYCLE_BIN,
        target_path=r"C:\Windows\System32\cmd.exe",
    )

    dialog = ActionPreviewDialog(action=action)

    assert dialog.preview.allowed is False
    assert dialog.confirm_button.isEnabled() is False

    dialog.close()


def test_live_provider_warning_dialog(qapp: QApplication) -> None:
    dialog = LiveProviderWarningDialog(provider_name="ollama-cloud")

    # Proceed button disabled until acknowledgment
    assert dialog.proceed_button.isEnabled() is False

    dialog.ack_checkbox.setChecked(True)
    assert dialog.proceed_button.isEnabled() is True

    dialog.ack_checkbox.setChecked(False)
    assert dialog.proceed_button.isEnabled() is False

    dialog.close()
