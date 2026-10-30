"""Pytest configuration and headless Qt setup for CI and local test runs."""

from __future__ import annotations

import os
import sys

# Ensure PySide6/Qt initializes in headless offscreen mode across all test runs
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication


@pytest.fixture(scope="session")
def qapp() -> QApplication:
    """Session-scoped headless QApplication instance for UI tests."""
    app = QApplication.instance()
    if not isinstance(app, QApplication):
        app = QApplication(sys.argv)
    return app
