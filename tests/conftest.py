"""Pytest configuration and headless Qt setup for CI and local test runs."""

from __future__ import annotations

import os

# Ensure PySide6/Qt initializes in headless offscreen mode across all test runs
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
