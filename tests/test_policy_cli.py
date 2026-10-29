"""Tests for the Moonlight policy CLI subcommands."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from moonlight.cli import main

VALID_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_cli_policy_validate_allowed(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    safe_file = tmp_path / "safe.bin"
    safe_file.write_text("ok")
    code = main(
        [
            "policy-validate",
            "--action-type",
            "open_file_location",
            "--target-path",
            str(safe_file),
        ]
    )
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["allowed"] is True
    assert data["action"]["action_type"] == "open_file_location"


def test_cli_policy_validate_rejected_kill_process(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(
        ["policy-validate", "--action-type", "kill_process", "--target-pid", "1234"]
    )
    assert code == 1
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["allowed"] is False
    assert "Process termination is not permitted" in data["rejection_reason"]


def test_cli_policy_preview(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    safe_file = tmp_path / "file.tmp"
    safe_file.write_bytes(b"hello world")
    audit_file = tmp_path / "audit.jsonl"

    code = main(
        [
            "policy-preview",
            "--action-type",
            "move_to_recycle_bin",
            "--target-path",
            str(safe_file),
            "--audit-log",
            str(audit_file),
        ]
    )
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["allowed"] is True
    assert data["requires_confirmation"] is True
    assert data["target_size_bytes"] == 11
    assert data["destination"] == "Windows Recycle Bin"
    assert data["confirmation_token"] is not None
    assert audit_file.exists()


def test_cli_policy_execute_unconfirmed(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    safe_file = tmp_path / "file.tmp"
    safe_file.write_text("data")

    code = main(
        [
            "policy-execute",
            "--action-type",
            "move_to_recycle_bin",
            "--target-path",
            str(safe_file),
        ]
    )
    assert code == 1
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["success"] is False
    assert "Explicit user confirmation is required" in data["error"]


def test_cli_policy_execute_missing_token(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    safe_file = tmp_path / "file.tmp"
    safe_file.write_text("data")

    code = main(
        [
            "policy-execute",
            "--action-type",
            "move_to_recycle_bin",
            "--target-path",
            str(safe_file),
            "--confirm",
        ]
    )
    assert code == 1
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["success"] is False
    assert "Confirmation token is required" in data["error"]


def test_cli_policy_execute_review_first_requires_extra_confirm(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    safe_file = tmp_path / "file.tmp"
    safe_file.write_text("data")

    from moonlight.rules.storage import StorageLocations

    # Emulate review_first by ensuring tmp_path is not in safe locations
    with patch(
        "moonlight.policy.protected.get_protected_locations",
        return_value=StorageLocations(protected=(), safe=()),
    ):
        # 1. Preview
        main(
            [
                "policy-preview",
                "--action-type",
                "move_to_recycle_bin",
                "--target-path",
                str(safe_file),
            ]
        )
        preview_data = json.loads(capsys.readouterr().out)
        token = preview_data["confirmation_token"]
        assert preview_data["requires_extra_confirmation"] is True

        # 2. Execute with confirm + token, but without extra-confirm on review_first
        code = main(
            [
                "policy-execute",
                "--action-type",
                "move_to_recycle_bin",
                "--target-path",
                str(safe_file),
                "--confirm",
                "--token",
                token,
            ]
        )
        assert code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["success"] is False
        assert "extra confirmation" in data["error"].lower()


def test_cli_policy_execute_confirmed(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    safe_file = tmp_path / "file.tmp"
    safe_file.write_text("data")

    # 1. Preview to obtain valid confirmation token
    main(
        [
            "policy-preview",
            "--action-type",
            "move_to_recycle_bin",
            "--target-path",
            str(safe_file),
        ]
    )
    preview_data = json.loads(capsys.readouterr().out)
    token = preview_data["confirmation_token"]

    with patch("send2trash.send2trash") as mock_trash:
        code = main(
            [
                "policy-execute",
                "--action-type",
                "move_to_recycle_bin",
                "--target-path",
                str(safe_file),
                "--confirm",
                "--token",
                token,
                "--extra-confirm",
            ]
        )
        assert code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["success"] is True
        mock_trash.assert_called_once()
