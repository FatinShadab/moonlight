"""Tests for the moonlight ui CLI command and module entrypoint."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from moonlight.cli import main


def test_cli_help_includes_ui(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify that moonlight --help lists the ui command."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "ui" in captured.out
    assert "launch desktop review interface" in captured.out


def test_cli_ui_help(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify that moonlight ui --help prints options and exits cleanly."""
    with pytest.raises(SystemExit) as exc_info:
        main(["ui", "--help"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "--mode" in captured.out


def test_cli_ui_execution() -> None:
    """Verify that moonlight ui dispatches to launch_ui with mode option."""
    with patch("moonlight.cli.launch_ui", return_value=0) as mock_launch:
        code = main(["ui", "--mode", "replay"])
        assert code == 0
        mock_launch.assert_called_once_with(
            argv=["ui", "--mode", "replay"], mode="replay"
        )
