"""Entrypoint for python -m moonlight.ui."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from moonlight.ui.window import MoonlightMainWindow


def main() -> int:
    """Launch the Moonlight desktop review interface."""
    app = QApplication.instance()
    if not isinstance(app, QApplication):
        app = QApplication(sys.argv)
    win = MoonlightMainWindow()
    win.show()
    return int(app.exec())


if __name__ == "__main__":
    raise SystemExit(main())
