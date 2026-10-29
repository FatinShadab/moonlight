"""Provider badges and visual indicators for non-production model providers.

Whenever the model provider is not 'meta' (e.g. 'ollama-cloud' or 'mock'),
the UI displays a 'cloud placeholder model' badge to ensure complete transparency.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtWidgets import QLabel

CLOUD_PLACEHOLDER_BADGE_TEXT = "cloud placeholder model"


def get_provider_badge(provider: str | None) -> str | None:
    """Return badge text for non-meta providers, or None if meta."""
    if provider is None:
        return CLOUD_PLACEHOLDER_BADGE_TEXT
    clean = provider.strip().lower()
    if clean == "meta":
        return None
    return CLOUD_PLACEHOLDER_BADGE_TEXT


class ProviderBadgeWidget(QLabel):
    """Badge label showing 'cloud placeholder model' when provider is not meta."""

    def __init__(self, provider: str = "ollama-cloud", parent: Any = None) -> None:
        super().__init__(parent)
        self.setObjectName("provider_badge")
        self._provider = provider
        self.update_provider(provider)

    @property
    def provider(self) -> str:
        return self._provider

    def update_provider(self, provider: str | None) -> None:
        """Update badge text and visibility based on provider."""
        self._provider = provider or ""
        badge_text = get_provider_badge(provider)
        if badge_text:
            self.setText(badge_text)
            self.setVisible(True)
            self.setStyleSheet(
                "background-color: #fef3c7; color: #92400e; "
                "font-weight: 600; font-size: 11px; padding: 2px 8px; "
                "border-radius: 4px; border: 1px solid #f59e0b;"
            )
        else:
            self.setText("")
            self.setVisible(False)
