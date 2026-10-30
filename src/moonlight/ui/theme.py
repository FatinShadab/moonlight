"""Design system tokens and QSS stylesheet for Moonlight's review interface.

Provides:
- Moonlit dark theme tokens (deep blue-gray surfaces, soft cool accent).
- 8px grid spacing, radii, typography scale using Windows system font stack.
- Status chips with text label and color (never color alone).
- High DPI scaling configuration.
- Single unified QSS stylesheet.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class ThemeColors:
    """Color palette tokens for the moonlit dark theme."""

    # Background and surface layers
    bg_canvas: str = "#0b0f19"  # Deepest midnight blue-black canvas
    bg_surface: str = "#1e293b"  # Deep blue-gray card/container surface
    bg_surface_alt: str = "#111827"  # Raised panels (nav rail, side panel, top bar)
    bg_surface_hover: str = "#243452"  # Hover state on surfaces
    bg_surface_active: str = "#334155"  # Selected/pressed state

    # Borders and dividers
    border_subtle: str = "#1e293b"  # Subtle container boundary
    border_default: str = "#334155"  # Standard input/card border
    border_focus: str = "#38bdf8"  # High-contrast focus outline (soft sky blue)

    # Typography
    text_primary: str = "#f8fafc"  # Bright white for titles and primary labels
    text_secondary: str = "#cbd5e1"  # Soft slate for body and secondary text
    text_muted: str = "#64748b"  # Muted gray for captions, timestamps, hints
    text_inverse: str = "#0b0f19"  # Dark text on bright badge chips

    # Brand / Cool Accent
    accent_primary: str = "#38bdf8"  # Soft cool sky blue
    accent_hover: str = "#0ea5e9"  # Deeper sky hover
    accent_surface: str = "#082f49"  # Accent tint surface for active pills
    accent_border: str = "#0284c7"  # Accent border

    # Semantic Status - Risk Tiers (Text + Color paired)
    risk_low_text: str = "#34d399"  # Emerald green
    risk_low_bg: str = "#064e3b"  # Deep emerald
    risk_low_border: str = "#059669"

    risk_review_text: str = "#fbbf24"  # Amber
    risk_review_bg: str = "#78350f"  # Deep amber
    risk_review_border: str = "#d97706"

    risk_high_text: str = "#f87171"  # Rose red
    risk_high_bg: str = "#7f1d1d"  # Deep rose
    risk_high_border: str = "#dc2626"

    risk_inconclusive_text: str = "#c084fc"  # Purple
    risk_inconclusive_bg: str = "#4c1d95"  # Deep purple
    risk_inconclusive_border: str = "#9333ea"

    # Semantic Status - Actions & Warnings
    warning_text: str = "#fde047"
    warning_bg: str = "#713f12"
    warning_border: str = "#ca8a04"

    info_text: str = "#38bdf8"
    info_bg: str = "#082f49"
    info_border: str = "#0284c7"

    success_text: str = "#4ade80"
    success_bg: str = "#14532d"
    success_border: str = "#16a34a"


@dataclass(frozen=True)
class Spacing:
    """8-pixel grid spacing scale."""

    xxs: int = 2
    xs: int = 4
    sm: int = 8
    md: int = 16
    lg: int = 24
    xl: int = 32
    xxl: int = 40


@dataclass(frozen=True)
class Radii:
    """Corner radius tokens."""

    xs: int = 2
    sm: int = 4
    md: int = 6
    lg: int = 8
    xl: int = 12
    pill: int = 9999


@dataclass(frozen=True)
class Typography:
    """Font family and type scale tokens."""

    font_family: str = (
        "-apple-system, 'Segoe UI', system-ui, BlinkMacSystemFont, "
        "Roboto, 'Helvetica Neue', sans-serif"
    )
    caption_size: str = "11px"
    body_size: str = "13px"
    subtitle_size: str = "14px"
    title_size: str = "16px"
    header_size: str = "20px"
    display_size: str = "24px"


COLORS: Final[ThemeColors] = ThemeColors()
SPACING: Final[Spacing] = Spacing()
RADII: Final[Radii] = Radii()
TYPE: Final[Typography] = Typography()


def build_qss() -> str:
    """Generate the complete Moonlight dark theme QSS stylesheet."""
    c = COLORS
    r = RADII
    t = TYPE

    return f"""
/* =========================================================================
   Moonlight Review Interface - Unified Dark Theme
   ========================================================================= */

* {{
    font-family: {t.font_family};
    font-size: {t.body_size};
    color: {c.text_primary};
    outline: none;
}}

QPushButton, QToolButton, QListWidget, QTabBar::tab, QCheckBox, QComboBox,
QLineEdit, QTextEdit, QPlainTextEdit, QTableWidget, QTreeView {{
    outline: none;
}}

QMainWindow, QDialog {{
    background-color: {c.bg_canvas};
    color: {c.text_primary};
}}

QWidget {{
    background-color: transparent;
}}

/* Surface Card Containers */
QFrame#card, QFrame.card, QFrame#surface_card {{
    background-color: {c.bg_surface};
    border: 1px solid {c.border_default};
    border-radius: {r.lg}px;
    padding: {SPACING.md}px;
}}

QFrame#card_subtle, QFrame.card_subtle {{
    background-color: {c.bg_surface};
    border: 1px solid {c.border_default};
    border-radius: {r.md}px;
}}

/* Left Navigation Rail */
QFrame#nav_rail {{
    background-color: {c.bg_surface_alt};
    border-right: 1px solid {c.border_default};
    min-width: 200px;
    max-width: 220px;
}}

QPushButton#nav_button, QPushButton#btn_world_view {{
    background-color: transparent;
    color: {c.text_secondary};
    text-align: left;
    padding: 10px 16px;
    border: none;
    border-left: 3px solid transparent;
    border-radius: {r.xs}px;
    font-size: {t.body_size};
    font-weight: 500;
}}

QPushButton#nav_button:hover, QPushButton#btn_world_view:hover {{
    background-color: {c.bg_surface_hover};
    color: {c.text_primary};
}}

QPushButton#nav_button:checked, QPushButton#nav_button[active="true"],
QPushButton#btn_world_view:checked, QPushButton#btn_world_view[active="true"] {{
    background-color: {c.accent_surface};
    color: {c.accent_primary};
    border-left: 3px solid {c.accent_primary};
    font-weight: 600;
}}

QPushButton#nav_button:focus-visible, QPushButton#nav_button:focus,
QPushButton#btn_world_view:focus-visible, QPushButton#btn_world_view:focus {{
    border: 1px solid {c.border_focus};
    border-left: 3px solid {c.accent_primary};
}}

/* Top Control Bar */
QFrame#top_bar {{
    background-color: {c.bg_surface_alt};
    border-bottom: 1px solid {c.border_default};
    min-height: 48px;
    padding: 0px 16px;
}}

/* Right Side Panel Dock */
QFrame#side_panel, QTabWidget#side_panel {{
    background-color: {c.bg_surface_alt};
    border-left: 1px solid {c.border_default};
    min-width: 320px;
    max-width: 420px;
}}

QTabWidget#side_panel > QWidget {{
    background-color: {c.bg_surface_alt};
}}

/* Standard Buttons */
QPushButton {{
    background-color: {c.bg_surface_hover};
    color: {c.text_primary};
    border: 1px solid {c.border_default};
    border-radius: {r.md}px;
    padding: 6px 14px;
    font-weight: 500;
}}

QPushButton:hover {{
    background-color: {c.bg_surface_active};
    border-color: {c.accent_primary};
}}

QPushButton:pressed {{
    background-color: {c.accent_surface};
}}

QPushButton:disabled {{
    background-color: {c.bg_surface_alt};
    color: {c.text_muted};
    border-color: {c.border_subtle};
}}

QPushButton:focus-visible, QPushButton:focus {{
    border: 1px solid {c.border_focus};
    background-color: rgba(56, 189, 248, 0.12);
}}

/* Zoom & Compact Icon Buttons */
QPushButton#zoom_btn_1, QPushButton#zoom_btn_2, QPushButton#zoom_btn_3,
QPushButton[class="icon-btn"], QPushButton.icon-btn {{
    padding: 0px;
    min-width: 28px;
    max-width: 28px;
    min-height: 28px;
    max-height: 28px;
    font-size: 11px;
    font-weight: 700;
    text-align: center;
    border-radius: {r.sm}px;
    background-color: {c.bg_surface_hover};
    border: 1px solid {c.border_default};
}}

QPushButton#zoom_btn_1:hover,
QPushButton#zoom_btn_2:hover,
QPushButton#zoom_btn_3:hover,
QPushButton[class="icon-btn"]:hover {{
    background-color: {c.bg_surface_active};
    border-color: {c.accent_primary};
}}

/* Primary Accent Button */
QPushButton#primary_button,
QPushButton[primary="true"],
QPushButton#run_investigation_btn {{
    background-color: {c.accent_primary};
    color: {c.text_inverse};
    border: 1px solid {c.accent_border};
    font-weight: 700;
    letter-spacing: 0.3px;
}}

QPushButton#primary_button:hover,
QPushButton[primary="true"]:hover,
QPushButton#run_investigation_btn:hover {{
    background-color: {c.accent_hover};
    border-color: {c.accent_primary};
}}

QPushButton#primary_button:pressed,
QPushButton[primary="true"]:pressed,
QPushButton#run_investigation_btn:pressed {{
    background-color: {c.accent_surface};
    color: {c.accent_primary};
}}

QPushButton#primary_button:disabled,
QPushButton[primary="true"]:disabled,
QPushButton#run_investigation_btn:disabled {{
    background-color: {c.border_default};
    color: {c.text_muted};
    border-color: {c.border_subtle};
}}

/* Danger Button */
QPushButton#danger_button {{
    background-color: {c.risk_high_bg};
    color: {c.risk_high_text};
    border: 1px solid {c.risk_high_border};
    font-weight: 600;
}}

QPushButton#danger_button:hover {{
    background-color: {c.risk_high_border};
    color: #ffffff;
}}

/* Input Fields & Combos */
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox {{
    background-color: {c.bg_canvas};
    color: {c.text_primary};
    border: 1px solid {c.border_default};
    border-radius: {r.md}px;
    padding: 6px 10px;
    selection-background-color: {c.accent_surface};
    selection-color: {c.accent_primary};
}}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus {{
    border: 1px solid {c.border_focus};
}}

QComboBox::drop-down {{
    border: none;
    padding-right: 8px;
}}

QComboBox QAbstractItemView {{
    background-color: {c.bg_surface};
    border: 1px solid {c.border_default};
    selection-background-color: {c.accent_surface};
    selection-color: {c.accent_primary};
    padding: 4px;
}}

/* Checkboxes */
QCheckBox {{
    color: {c.text_primary};
    spacing: 8px;
}}

QCheckBox::indicator {{
    width: 18px;
    height: 18px;
    border: 1px solid {c.border_default};
    border-radius: {r.sm}px;
    background-color: {c.bg_canvas};
}}

QCheckBox::indicator:hover {{
    border-color: {c.accent_primary};
}}

QCheckBox::indicator:checked {{
    background-color: {c.accent_primary};
    border-color: {c.accent_border};
}}

QCheckBox:focus {{
    border: none;
}}

/* Tab Widget (Side Panel, Content) */
QTabWidget::pane {{
    border: none;
    background-color: transparent;
}}

QTabBar::tab {{
    background-color: transparent;
    color: {c.text_secondary};
    padding: 8px 16px;
    border-bottom: 2px solid transparent;
    font-weight: 500;
}}

QTabBar::tab:hover {{
    color: {c.text_primary};
    background-color: {c.bg_surface_hover};
}}

QTabBar::tab:selected {{
    color: {c.accent_primary};
    border-bottom: 2px solid {c.accent_primary};
    font-weight: 600;
}}

QTabBar::tab:focus {{
    border-bottom: 2px solid {c.accent_primary};
}}

/* Tables and Tree Views */
QTableWidget, QTableView, QTreeWidget, QTreeView {{
    background-color: {c.bg_surface};
    color: {c.text_primary};
    border: 1px solid {c.border_default};
    border-radius: {r.lg}px;
    gridline-color: {c.border_subtle};
    selection-background-color: {c.accent_surface};
    selection-color: {c.text_primary};
}}

QTableWidget::item:focus, QTableView::item:focus {{
    border: 1px solid {c.border_focus};
}}

QHeaderView::section {{
    background-color: {c.bg_surface_alt};
    color: {c.text_secondary};
    font-weight: 600;
    font-size: {t.caption_size};
    text-transform: uppercase;
    letter-spacing: 0.5px;
    padding: 8px;
    border: none;
    border-bottom: 1px solid {c.border_default};
    border-right: 1px solid {c.border_subtle};
}}

/* Scrollbars */
QScrollBar:vertical {{
    background-color: {c.bg_canvas};
    width: 10px;
    margin: 0px;
    border-radius: {r.sm}px;
}}

QScrollBar::handle:vertical {{
    background-color: {c.border_default};
    min-height: 24px;
    border-radius: {r.sm}px;
    margin: 2px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {c.accent_border};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QScrollBar:horizontal {{
    background-color: {c.bg_canvas};
    height: 10px;
    margin: 0px;
    border-radius: {r.sm}px;
}}

QScrollBar::handle:horizontal {{
    background-color: {c.border_default};
    min-width: 24px;
    border-radius: {r.sm}px;
    margin: 2px;
}}

QScrollBar::handle:horizontal:hover {{
    background-color: {c.accent_border};
}}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
}}

/* Labels and Badges */
QLabel#header_title {{
    font-size: {t.title_size};
    font-weight: 700;
    color: {c.text_primary};
}}

QLabel#section_title {{
    font-size: {t.subtitle_size};
    font-weight: 600;
    color: {c.text_secondary};
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}

QLabel#caption_label {{
    font-size: {t.caption_size};
    color: {c.text_muted};
}}

/* Empty and Loading States */
QFrame#empty_state {{
    background-color: #0b1120;
    border: 1px dashed {c.border_default};
    border-radius: {r.lg}px;
    padding: {SPACING.xl}px;
}}

QLabel#empty_state_title {{
    font-size: {t.title_size};
    font-weight: 600;
    color: {c.text_primary};
}}

QLabel#empty_state_text {{
    font-size: {t.body_size};
    color: {c.text_muted};
}}
"""


def get_risk_chip_style(tier: str) -> tuple[str, str]:
    """Return (label_text, qss_style) for a given risk tier.

    Ensures both text and color are carried (never color alone).
    """
    c = COLORS
    r = RADII
    clean = tier.strip().lower()

    base_style = (
        f"font-weight: 700; font-size: 11px; padding: 3px 10px; "
        f"border-radius: {r.pill}px; letter-spacing: 0.5px; "
    )

    if clean == "low":
        return (
            "LOW RISK",
            f"{base_style} background-color: {c.risk_low_bg}; "
            f"color: {c.risk_low_text}; border: 1px solid {c.risk_low_border};",
        )
    elif clean == "review":
        return (
            "REVIEW REQUIRED",
            f"{base_style} background-color: {c.risk_review_bg}; "
            f"color: {c.risk_review_text}; border: 1px solid {c.risk_review_border};",
        )
    elif clean == "high":
        return (
            "HIGH RISK",
            f"{base_style} background-color: {c.risk_high_bg}; "
            f"color: {c.risk_high_text}; border: 1px solid {c.risk_high_border};",
        )
    elif clean == "inconclusive":
        return (
            "INCONCLUSIVE",
            f"{base_style} background-color: {c.risk_inconclusive_bg}; "
            f"color: {c.risk_inconclusive_text}; "
            f"border: 1px solid {c.risk_inconclusive_border};",
        )
    else:
        return (
            clean.upper(),
            f"{base_style} background-color: {c.bg_surface_hover}; "
            f"color: {c.text_secondary}; border: 1px solid {c.border_default};",
        )


def get_confidence_chip_style(confidence: float) -> tuple[str, str]:
    """Return (label_text, qss_style) for a calibrated confidence score."""
    c = COLORS
    r = RADII
    pct = int(round(confidence * 100))
    text = f"CONFIDENCE: {pct}%"

    base_style = (
        f"font-weight: 600; font-size: 11px; padding: 3px 8px; "
        f"border-radius: {r.pill}px; "
    )

    if confidence >= 0.8:
        style = (
            f"{base_style} background-color: {c.accent_surface}; "
            f"color: {c.accent_primary}; border: 1px solid {c.accent_border};"
        )
    elif confidence >= 0.5:
        style = (
            f"{base_style} background-color: {c.bg_surface_hover}; "
            f"color: {c.text_secondary}; border: 1px solid {c.border_default};"
        )
    else:
        style = (
            f"{base_style} background-color: {c.warning_bg}; "
            f"color: {c.warning_text}; border: 1px solid {c.warning_border};"
        )

    return (text, style)


def get_fallback_badge_style(reason: str | None = None) -> tuple[str, str]:
    """Return (label_text, qss_style) for a rules-only fallback badge."""
    text = "rules-only fallback"
    style = (
        "background-color: rgba(245, 158, 11, 0.12); color: #fbbf24; "
        "font-weight: 600; font-size: 11px; padding: 3px 8px; "
        "border-radius: 6px; border: 1px solid rgba(245, 158, 11, 0.35);"
    )
    return (text, style)
