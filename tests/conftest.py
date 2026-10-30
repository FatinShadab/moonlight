"""Pytest configuration and headless Qt setup for CI and local test runs."""

from __future__ import annotations

import os
from collections.abc import Generator

# Ensure PySide6/Qt initializes in headless offscreen mode across all test runs
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import pytest
from PySide6.QtWidgets import QApplication

# Maintain a module-level reference to the single session QApplication so Python
# garbage collection does not tear down C++ Qt bindings out of order at exit.
_qapp_instance: QApplication | None = None


@pytest.fixture(scope="session")
def qapp() -> Generator[QApplication, None, None]:
    """Session-scoped headless QApplication instance for UI tests."""
    global _qapp_instance
    app = QApplication.instance()
    if not isinstance(app, QApplication):
        _qapp_instance = QApplication([])
        app = _qapp_instance
    else:
        _qapp_instance = app
    yield app
    app.closeAllWindows()
    app.processEvents()


@pytest.fixture(autouse=True)
def _cleanup_qt_widgets() -> Generator[None, None, None]:
    """Clean up open top-level Qt windows and drain event loop after each test."""
    yield
    app = QApplication.instance()
    if isinstance(app, QApplication):
        app.closeAllWindows()
        app.processEvents()


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Flush pending events and close all windows before Python interpreter shutdown."""
    app = QApplication.instance()
    if isinstance(app, QApplication):
        app.closeAllWindows()
        app.processEvents()
