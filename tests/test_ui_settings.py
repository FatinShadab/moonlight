"""UI component tests for SettingsViewWidget."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QApplication, QLineEdit

from moonlight.core.config import AppSettings
from moonlight.ui.settings_view import SettingsViewWidget


def test_settings_view_widget_renders(qapp: QApplication) -> None:
    settings = AppSettings(
        provider="ollama-cloud",
        meta_api_key="meta-123",
        ollama_api_key="ollama-456",
        ollama_model="llama3.3:latest",
        timeout=40.0,
    )

    widget = SettingsViewWidget(settings=settings)
    widget.show()

    # Provider dropdown
    assert widget.combo_provider.currentText() == "ollama-cloud"

    # Password fields are initially masked
    assert widget.input_meta_key.echoMode() == QLineEdit.EchoMode.Password
    assert widget.input_ollama_key.echoMode() == QLineEdit.EchoMode.Password
    assert widget.input_meta_key.text() == "meta-123"
    assert widget.input_ollama_key.text() == "ollama-456"

    # Model and timeout
    assert widget.combo_ollama_model.currentText() == "llama3.3:latest"
    assert widget.spin_timeout.value() == 40.0

    # Toggle password visibility
    assert widget.btn_toggle_meta_key.text() == "Show"
    widget.btn_toggle_meta_key.click()
    assert widget.input_meta_key.echoMode() == QLineEdit.EchoMode.Normal
    assert widget.btn_toggle_meta_key.text() == "Hide"

    widget.btn_toggle_meta_key.click()
    assert widget.input_meta_key.echoMode() == QLineEdit.EchoMode.Password
    assert widget.btn_toggle_meta_key.text() == "Show"

    widget.close()
    widget.deleteLater()
    qapp.processEvents()


def test_settings_view_widget_save_emits_signal(
    qapp: QApplication, tmp_path: Path
) -> None:
    settings_file = tmp_path / "settings.json"
    widget = SettingsViewWidget(settings_path=settings_file)
    widget.show()

    emitted_settings: list[AppSettings] = []
    widget.settings_saved.connect(emitted_settings.append)

    # Modify some fields
    widget.combo_provider.setCurrentText("meta")
    widget.input_meta_key.setText("new-meta-secret")
    widget.spin_timeout.setValue(55.0)

    # Click Save Settings
    widget.btn_save.click()

    assert len(emitted_settings) == 1
    saved = emitted_settings[0]
    assert saved.provider == "meta"
    assert saved.meta_api_key == "new-meta-secret"
    assert saved.timeout == 55.0
    assert "saved successfully" in widget.lbl_feedback.text()
    assert settings_file.exists()

    widget.close()
    widget.deleteLater()
    qapp.processEvents()


def test_settings_view_widget_reset_to_defaults(
    qapp: QApplication, tmp_path: Path
) -> None:
    settings_file = tmp_path / "settings.json"
    custom = AppSettings(provider="meta", timeout=90.0, max_retries=4)
    widget = SettingsViewWidget(settings=custom, settings_path=settings_file)
    widget.show()

    assert widget.combo_provider.currentText() == "meta"
    assert widget.spin_timeout.value() == 90.0

    widget.btn_reset.click()

    assert widget.combo_provider.currentText() == "mock"
    assert widget.spin_timeout.value() == 30.0
    assert widget.spin_retries.value() == 2
    assert "reset to defaults" in widget.lbl_feedback.text()

    widget.close()
    widget.deleteLater()
    qapp.processEvents()


def test_settings_view_widget_fetch_callback(qapp: QApplication) -> None:
    widget = SettingsViewWidget()
    widget.show()

    # Simulate worker completion callback
    widget._on_models_fetched(True, "Loaded", ["model-alpha", "model-beta"])

    assert widget.combo_ollama_model.count() >= 2
    assert widget.combo_ollama_model.itemText(0) == "model-alpha"
    assert "Success" in widget.lbl_ollama_status.text()

    widget.close()
    widget.deleteLater()
    qapp.processEvents()
