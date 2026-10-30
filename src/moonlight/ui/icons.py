"""Icon management and loader for Moonlight UI."""

from __future__ import annotations

from pathlib import Path
from typing import Final

from PySide6.QtGui import QIcon, QPixmap
from PySide6.QtWidgets import QApplication, QStyle

_ICONS_DIR: Final[Path] = Path(__file__).resolve().parent / "icons"
_CACHE: dict[str, QIcon] = {}


def get_icon(name: str) -> QIcon:
    """Retrieve an icon by name from icons/ or fallback to standard style icon."""
    if name in _CACHE:
        return _CACHE[name]

    svg_path = _ICONS_DIR / f"{name}.svg"
    if svg_path.exists():
        icon = QIcon(str(svg_path))
        if not icon.isNull():
            _CACHE[name] = icon
            return icon

    # Fallback to standard Qt application icons
    app = QApplication.instance()
    if app:
        style = QApplication.style()
        std_mapping = {
            "processes": QStyle.StandardPixmap.SP_FileDialogDetailedView,
            "storage": QStyle.StandardPixmap.SP_DriveHDIcon,
            "reports": QStyle.StandardPixmap.SP_FileIcon,
            "model": QStyle.StandardPixmap.SP_ComputerIcon,
            "shield": QStyle.StandardPixmap.SP_VistaShield,
            "activity": QStyle.StandardPixmap.SP_BrowserReload,
            "approval": QStyle.StandardPixmap.SP_DialogApplyButton,
            "check": QStyle.StandardPixmap.SP_DialogApplyButton,
            "warning": QStyle.StandardPixmap.SP_MessageBoxWarning,
            "refresh": QStyle.StandardPixmap.SP_BrowserReload,
            "chevron_right": QStyle.StandardPixmap.SP_ArrowRight,
            "world": QStyle.StandardPixmap.SP_DesktopIcon,
        }
        if name in std_mapping:
            pix = style.standardPixmap(std_mapping[name])
            icon = QIcon(pix)
            _CACHE[name] = icon
            return icon

    # Empty fallback
    fallback = QIcon()
    _CACHE[name] = fallback
    return fallback


def get_pixmap(name: str, width: int = 16, height: int = 16) -> QPixmap:
    """Retrieve a pixmap with specified dimensions."""
    icon = get_icon(name)
    return icon.pixmap(width, height)
