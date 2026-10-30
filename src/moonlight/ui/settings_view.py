"""Settings and configuration view for Moonlight desktop application."""

from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from moonlight.core.config import (
    AppSettings,
    ProviderType,
    load_settings,
    save_settings,
    verify_ollama_connection,
)
from moonlight.reasoning.cache import ReasoningCache
from moonlight.ui.icons import get_icon
from moonlight.ui.theme import COLORS, RADII, SPACING

logger = logging.getLogger(__name__)


class OllamaConnectionWorker(QThread):
    """Background worker to query Ollama tags and models without UI freeze."""

    finished_result = Signal(bool, str, list)  # success, message, models

    def __init__(
        self,
        base_url: str,
        api_key: str,
        allow_custom_host: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.base_url = base_url
        self.api_key = api_key
        self.allow_custom_host = allow_custom_host

    def run(self) -> None:
        success, message, models = verify_ollama_connection(
            base_url=self.base_url,
            api_key=self.api_key,
            allow_custom_host=self.allow_custom_host,
        )
        self.finished_result.emit(success, message, models)


class SettingsViewWidget(QWidget):
    """Settings management view for providers, API keys, privacy, and heuristics."""

    settings_saved = Signal(object)  # AppSettings

    def __init__(
        self,
        settings: AppSettings | None = None,
        settings_path: Path | str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("settings_view_widget")
        self._settings_path = Path(settings_path) if settings_path else None
        self._settings = settings or load_settings(path=self._settings_path)
        self._worker: OllamaConnectionWorker | None = None

        self._init_layout()
        self.set_settings(self._settings)

    def _init_layout(self) -> None:
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(SPACING.md, SPACING.md, SPACING.md, SPACING.md)
        root_layout.setSpacing(SPACING.sm)

        # 1. Header Card
        header_card = QFrame()
        header_card.setObjectName("card")
        h_layout = QHBoxLayout(header_card)
        h_layout.setContentsMargins(SPACING.md, SPACING.sm, SPACING.md, SPACING.sm)

        title_box = QVBoxLayout()
        title_lbl = QLabel("Settings & Configuration")
        title_lbl.setObjectName("header_title")
        sub_lbl = QLabel(
            "Manage AI reasoning providers, API keys, model selections, "
            "privacy minimization, and local investigation heuristics."
        )
        sub_lbl.setStyleSheet(f"color: {COLORS.text_secondary}; font-size: 12px;")
        title_box.addWidget(title_lbl)
        title_box.addWidget(sub_lbl)
        h_layout.addLayout(title_box)
        h_layout.addStretch()

        root_layout.addWidget(header_card)

        # 2. Scrollable Body
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        scroll_area.setStyleSheet("background: transparent;")

        scroll_content = QWidget()
        scroll_content.setStyleSheet("background: transparent;")
        content_layout = QVBoxLayout(scroll_content)
        content_layout.setContentsMargins(0, SPACING.sm, 0, SPACING.sm)
        content_layout.setSpacing(SPACING.md)

        # Card 1: AI Provider & Reasoning
        content_layout.addWidget(self._create_ai_provider_card())

        # Card 2: Privacy Minimization
        content_layout.addWidget(self._create_privacy_card())

        # Card 3: Storage Attribution
        content_layout.addWidget(self._create_storage_card())

        # Card 4: Policy & Safeguards Transparency
        content_layout.addWidget(self._create_policy_card())

        content_layout.addStretch()
        scroll_area.setWidget(scroll_content)
        root_layout.addWidget(scroll_area, stretch=1)

        # 3. Footer Bar with Save / Reset actions
        root_layout.addWidget(self._create_footer_bar())

    def _create_ai_provider_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(SPACING.md, SPACING.md, SPACING.md, SPACING.md)
        layout.setSpacing(SPACING.md)

        header_lbl = QLabel("AI Reasoning & Model Providers")
        header_lbl.setStyleSheet(
            f"font-size: 14px; font-weight: 700; color: {COLORS.accent_primary};"
        )
        layout.addWidget(header_lbl)

        # Active Provider Selector
        prov_row = QHBoxLayout()
        prov_lbl = QLabel("Active Provider:")
        prov_lbl.setFixedWidth(130)
        prov_lbl.setStyleSheet(f"color: {COLORS.text_primary}; font-weight: 600;")
        prov_row.addWidget(prov_lbl)

        self.combo_provider = QComboBox()
        self.combo_provider.setObjectName("settings_provider_combo")
        self.combo_provider.addItems(["mock", "ollama-cloud", "meta"])
        self.combo_provider.currentTextChanged.connect(self._on_provider_changed)
        prov_row.addWidget(self.combo_provider)
        prov_row.addStretch()
        layout.addLayout(prov_row)

        # --- Meta Model API Section ---
        self.meta_frame = QFrame()
        self.meta_frame.setObjectName("sub_card")
        self.meta_frame.setStyleSheet(
            f"background-color: {COLORS.bg_surface_alt}; "
            f"border: 1px solid {COLORS.border_subtle}; "
            f"border-radius: {RADII.md}px; padding: {SPACING.sm}px;"
        )
        meta_layout = QVBoxLayout(self.meta_frame)
        meta_layout.setSpacing(SPACING.sm)

        meta_title = QLabel("Meta Model API Configuration")
        meta_title.setStyleSheet(f"font-weight: 700; color: {COLORS.text_primary};")
        meta_layout.addWidget(meta_title)

        # Meta API Key
        meta_key_row = QHBoxLayout()
        meta_key_lbl = QLabel("Meta API Key:")
        meta_key_lbl.setFixedWidth(120)
        meta_key_row.addWidget(meta_key_lbl)

        self.input_meta_key = QLineEdit()
        self.input_meta_key.setObjectName("input_meta_key")
        self.input_meta_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.input_meta_key.setPlaceholderText("Enter Meta Model API key...")
        meta_key_row.addWidget(self.input_meta_key, stretch=1)

        self.btn_toggle_meta_key = QPushButton("Show")
        self.btn_toggle_meta_key.setFixedWidth(60)
        self.btn_toggle_meta_key.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_toggle_meta_key.clicked.connect(
            lambda: self._toggle_password_visibility(
                self.input_meta_key, self.btn_toggle_meta_key
            )
        )
        meta_key_row.addWidget(self.btn_toggle_meta_key)
        meta_layout.addLayout(meta_key_row)

        # Meta Model
        meta_model_row = QHBoxLayout()
        meta_model_lbl = QLabel("Meta Model:")
        meta_model_lbl.setFixedWidth(120)
        meta_model_row.addWidget(meta_model_lbl)

        self.combo_meta_model = QComboBox()
        self.combo_meta_model.setObjectName("combo_meta_model")
        self.combo_meta_model.setEditable(True)
        self.combo_meta_model.addItems(
            [
                "llama-3.3-70b-instruct",
                "llama-3.1-70b-instruct",
                "llama-3.1-8b-instruct",
            ]
        )
        meta_model_row.addWidget(self.combo_meta_model, stretch=1)
        meta_layout.addLayout(meta_model_row)

        meta_info = QLabel(
            "Note: Meta Model API is used for schema-validated, "
            "grounded reasoning in production."
        )
        meta_info.setStyleSheet(f"color: {COLORS.text_muted}; font-size: 11px;")
        meta_layout.addWidget(meta_info)

        layout.addWidget(self.meta_frame)

        # --- Ollama Cloud Section ---
        self.ollama_frame = QFrame()
        self.ollama_frame.setObjectName("sub_card")
        self.ollama_frame.setStyleSheet(
            f"background-color: {COLORS.bg_surface_alt}; "
            f"border: 1px solid {COLORS.border_subtle}; "
            f"border-radius: {RADII.md}px; padding: {SPACING.sm}px;"
        )
        ollama_layout = QVBoxLayout(self.ollama_frame)
        ollama_layout.setSpacing(SPACING.sm)

        ollama_title = QLabel("Ollama Cloud (Placeholder / Stand-in Provider)")
        ollama_title.setStyleSheet(f"font-weight: 700; color: {COLORS.text_primary};")
        ollama_layout.addWidget(ollama_title)

        # Ollama API Key
        ollama_key_row = QHBoxLayout()
        ollama_key_lbl = QLabel("Ollama API Key:")
        ollama_key_lbl.setFixedWidth(120)
        ollama_key_row.addWidget(ollama_key_lbl)

        self.input_ollama_key = QLineEdit()
        self.input_ollama_key.setObjectName("input_ollama_key")
        self.input_ollama_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.input_ollama_key.setPlaceholderText("Enter Ollama Cloud API key...")
        ollama_key_row.addWidget(self.input_ollama_key, stretch=1)

        self.btn_toggle_ollama_key = QPushButton("Show")
        self.btn_toggle_ollama_key.setFixedWidth(60)
        self.btn_toggle_ollama_key.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_toggle_ollama_key.clicked.connect(
            lambda: self._toggle_password_visibility(
                self.input_ollama_key, self.btn_toggle_ollama_key
            )
        )
        ollama_key_row.addWidget(self.btn_toggle_ollama_key)
        ollama_layout.addLayout(ollama_key_row)

        # Base URL & Custom Host
        url_row = QHBoxLayout()
        url_lbl = QLabel("Base URL:")
        url_lbl.setFixedWidth(120)
        url_row.addWidget(url_lbl)

        self.input_ollama_url = QLineEdit("https://ollama.com")
        self.input_ollama_url.setObjectName("input_ollama_url")
        url_row.addWidget(self.input_ollama_url, stretch=1)

        self.check_custom_host = QCheckBox("Allow custom host")
        self.check_custom_host.setObjectName("check_custom_host")
        self.check_custom_host.setToolTip(
            "Allow private or local Ollama endpoints (e.g. localhost or internal)"
        )
        url_row.addWidget(self.check_custom_host)
        ollama_layout.addLayout(url_row)

        # Ollama Model & Fetch Button
        model_row = QHBoxLayout()
        model_lbl = QLabel("Ollama Model:")
        model_lbl.setFixedWidth(120)
        model_row.addWidget(model_lbl)

        self.combo_ollama_model = QComboBox()
        self.combo_ollama_model.setObjectName("combo_ollama_model")
        self.combo_ollama_model.setEditable(True)
        self.combo_ollama_model.addItems(
            [
                "gemma4:31b",
                "llama3.3:latest",
                "llama3.2:latest",
                "qwen2.5:latest",
                "mistral:latest",
            ]
        )
        model_row.addWidget(self.combo_ollama_model, stretch=1)

        self.btn_fetch_models = QPushButton("Fetch Models")
        self.btn_fetch_models.setObjectName("btn_fetch_models")
        self.btn_fetch_models.setIcon(get_icon("refresh"))
        self.btn_fetch_models.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_fetch_models.setToolTip(
            "Query /api/tags on the Ollama endpoint to list available models"
        )
        self.btn_fetch_models.clicked.connect(self._fetch_ollama_models_clicked)
        model_row.addWidget(self.btn_fetch_models)

        self.btn_test_ollama = QPushButton("Test Connection")
        self.btn_test_ollama.setObjectName("btn_test_ollama")
        self.btn_test_ollama.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_test_ollama.clicked.connect(self._test_ollama_clicked)
        model_row.addWidget(self.btn_test_ollama)

        ollama_layout.addLayout(model_row)

        # Ollama Status Feedback
        self.lbl_ollama_status = QLabel("")
        self.lbl_ollama_status.setObjectName("lbl_ollama_status")
        self.lbl_ollama_status.setStyleSheet(
            f"color: {COLORS.text_muted}; font-size: 11px;"
        )
        self.lbl_ollama_status.setWordWrap(True)
        ollama_layout.addWidget(self.lbl_ollama_status)

        layout.addWidget(self.ollama_frame)

        # --- Common Reasoning Parameters ---
        params_row = QHBoxLayout()

        timeout_lbl = QLabel("Timeout (s):")
        params_row.addWidget(timeout_lbl)
        self.spin_timeout = QDoubleSpinBox()
        self.spin_timeout.setObjectName("spin_timeout")
        self.spin_timeout.setRange(1.0, 300.0)
        self.spin_timeout.setValue(30.0)
        self.spin_timeout.setSingleStep(5.0)
        params_row.addWidget(self.spin_timeout)

        params_row.addSpacing(SPACING.md)

        retries_lbl = QLabel("Max Retries:")
        params_row.addWidget(retries_lbl)
        self.spin_retries = QSpinBox()
        self.spin_retries.setObjectName("spin_retries")
        self.spin_retries.setRange(0, 5)
        self.spin_retries.setValue(2)
        params_row.addWidget(self.spin_retries)

        params_row.addSpacing(SPACING.md)

        self.check_cache = QCheckBox("Enable Response Cache")
        self.check_cache.setObjectName("check_cache")
        self.check_cache.setChecked(True)
        params_row.addWidget(self.check_cache)

        self.btn_clear_cache = QPushButton("Clear Cache")
        self.btn_clear_cache.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_clear_cache.clicked.connect(self._clear_cache_clicked)
        params_row.addWidget(self.btn_clear_cache)

        params_row.addStretch()
        layout.addLayout(params_row)

        return card

    def _create_privacy_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(SPACING.md, SPACING.md, SPACING.md, SPACING.md)
        layout.setSpacing(SPACING.sm)

        header_lbl = QLabel("Privacy Minimization & Evidence Redaction")
        header_lbl.setStyleSheet(
            f"font-size: 14px; font-weight: 700; color: {COLORS.accent_primary};"
        )
        layout.addWidget(header_lbl)

        grid_layout = QHBoxLayout()

        cmd_lbl = QLabel("Max Command Length (chars):")
        grid_layout.addWidget(cmd_lbl)
        self.spin_max_cmd = QSpinBox()
        self.spin_max_cmd.setObjectName("spin_max_cmd")
        self.spin_max_cmd.setRange(32, 8192)
        self.spin_max_cmd.setValue(512)
        self.spin_max_cmd.setSingleStep(64)
        grid_layout.addWidget(self.spin_max_cmd)

        grid_layout.addSpacing(SPACING.md)

        items_lbl = QLabel("Max Evidence Items:")
        grid_layout.addWidget(items_lbl)
        self.spin_max_items = QSpinBox()
        self.spin_max_items.setObjectName("spin_max_items")
        self.spin_max_items.setRange(1, 4096)
        self.spin_max_items.setValue(256)
        self.spin_max_items.setSingleStep(32)
        grid_layout.addWidget(self.spin_max_items)

        grid_layout.addStretch()
        layout.addLayout(grid_layout)

        alias_row = QHBoxLayout()
        alias_lbl = QLabel("Custom Usernames to Redact:")
        alias_lbl.setFixedWidth(200)
        alias_row.addWidget(alias_lbl)

        self.input_custom_aliases = QLineEdit()
        self.input_custom_aliases.setObjectName("input_custom_aliases")
        self.input_custom_aliases.setPlaceholderText(
            "e.g. Alice, Bob, Administrator (comma-separated)"
        )
        alias_row.addWidget(self.input_custom_aliases, stretch=1)
        layout.addLayout(alias_row)

        desc_lbl = QLabel(
            "Privacy guarantee: All evidence sent to reasoning models is stripped of "
            "usernames, hostnames, and restricted to metadata only. File contents are "
            "NEVER read or transmitted."
        )
        desc_lbl.setStyleSheet(f"color: {COLORS.text_muted}; font-size: 11px;")
        layout.addWidget(desc_lbl)

        return card

    def _create_storage_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(SPACING.md, SPACING.md, SPACING.md, SPACING.md)
        layout.setSpacing(SPACING.sm)

        header_lbl = QLabel("Storage Investigator & Disk Attribution Heuristics")
        header_lbl.setStyleSheet(
            f"font-size: 14px; font-weight: 700; color: {COLORS.accent_primary};"
        )
        layout.addWidget(header_lbl)

        row = QHBoxLayout()
        growth_lbl = QLabel("Min Growth Rate Threshold (MB/s):")
        row.addWidget(growth_lbl)

        self.spin_min_growth = QDoubleSpinBox()
        self.spin_min_growth.setObjectName("spin_min_growth")
        self.spin_min_growth.setRange(0.0, 1000.0)
        self.spin_min_growth.setValue(1.0)
        self.spin_min_growth.setSingleStep(0.5)
        row.addWidget(self.spin_min_growth)

        row.addSpacing(SPACING.md)

        skew_lbl = QLabel("Max Endpoint Skew (s):")
        row.addWidget(skew_lbl)

        self.spin_max_skew = QDoubleSpinBox()
        self.spin_max_skew.setObjectName("spin_max_skew")
        self.spin_max_skew.setRange(0.0, 60.0)
        self.spin_max_skew.setValue(5.0)
        self.spin_max_skew.setSingleStep(1.0)
        row.addWidget(self.spin_max_skew)

        row.addStretch()
        layout.addLayout(row)

        note_lbl = QLabel(
            "Heuristic threshold: Used when correlating process disk write activity "
            "with folder growth snapshots."
        )
        note_lbl.setStyleSheet(f"color: {COLORS.text_muted}; font-size: 11px;")
        layout.addWidget(note_lbl)

        return card

    def _create_policy_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(SPACING.md, SPACING.md, SPACING.md, SPACING.md)
        layout.setSpacing(SPACING.xs)

        header_lbl = QLabel("Policy & Remediation Safeguards (Active Allowlist)")
        header_lbl.setStyleSheet(
            f"font-size: 14px; font-weight: 700; color: {COLORS.accent_primary};"
        )
        layout.addWidget(header_lbl)

        safeguards = [
            "• Action Allowlist: The ONLY permissible file action is "
            "move-to-Recycle-Bin.",
            "• Protected System Directories: C:\\Windows, C:\\Program Files, "
            "C:\\Program Files (x86) are strictly blocked.",
            "• Protected Personal Folders: User Desktop, Documents, Downloads, "
            "Pictures, Videos are strictly blocked.",
            "• Zero Direct Deletions: Moonlight never permanently deletes files, "
            "kills processes, or modifies registry.",
            "• Dry-Run & Confirmation: Every proposed action requires a previewed "
            "dry-run and explicit user confirmation.",
        ]
        for sg in safeguards:
            lbl = QLabel(sg)
            lbl.setStyleSheet(f"color: {COLORS.text_secondary}; font-size: 12px;")
            layout.addWidget(lbl)

        return card

    def _create_footer_bar(self) -> QFrame:
        bar = QFrame()
        bar.setObjectName("footer_bar")
        bar.setStyleSheet(
            f"border-top: 1px solid {COLORS.border_subtle}; "
            f"padding-top: {SPACING.sm}px;"
        )
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(SPACING.sm)

        self.lbl_feedback = QLabel("")
        self.lbl_feedback.setObjectName("lbl_feedback")
        self.lbl_feedback.setStyleSheet(
            f"color: {COLORS.success_text}; font-weight: 600;"
        )
        layout.addWidget(self.lbl_feedback)

        layout.addStretch()

        self.btn_reset = QPushButton("Reset to Defaults")
        self.btn_reset.setObjectName("btn_reset_settings")
        self.btn_reset.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_reset.clicked.connect(self._on_reset_clicked)
        layout.addWidget(self.btn_reset)

        self.btn_save = QPushButton("Save Settings")
        self.btn_save.setObjectName("btn_save_settings")
        self.btn_save.setProperty("primary", "true")
        self.btn_save.setIcon(get_icon("check"))
        self.btn_save.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_save.setMinimumWidth(130)
        self.btn_save.clicked.connect(self._on_save_clicked)
        layout.addWidget(self.btn_save)

        return bar

    def _toggle_password_visibility(
        self, line_edit: QLineEdit, button: QPushButton
    ) -> None:
        if line_edit.echoMode() == QLineEdit.EchoMode.Password:
            line_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            button.setText("Hide")
        else:
            line_edit.setEchoMode(QLineEdit.EchoMode.Password)
            button.setText("Show")

    def _on_provider_changed(self, provider: str) -> None:
        """Visual hint when provider selection changes."""
        self.lbl_feedback.setText("")

    def _clear_cache_clicked(self) -> None:
        cache = ReasoningCache()
        cache.clear()
        self.lbl_feedback.setText("Response cache cleared.")
        self.lbl_feedback.setStyleSheet(
            f"color: {COLORS.info_text}; font-weight: 600;"
        )

    def _fetch_ollama_models_clicked(self) -> None:
        url = self.input_ollama_url.text().strip()
        key = self.input_ollama_key.text().strip()
        allow_custom = self.check_custom_host.isChecked()

        if not key:
            self.lbl_ollama_status.setText(
                "Error: Ollama API key is required to fetch models."
            )
            self.lbl_ollama_status.setStyleSheet(
                f"color: {COLORS.risk_high_text};"
            )
            return

        self.btn_fetch_models.setEnabled(False)
        self.lbl_ollama_status.setText("Querying /api/tags for available models...")
        self.lbl_ollama_status.setStyleSheet(f"color: {COLORS.info_text};")

        self._worker = OllamaConnectionWorker(
            base_url=url,
            api_key=key,
            allow_custom_host=allow_custom,
            parent=self,
        )
        self._worker.finished_result.connect(self._on_models_fetched)
        self._worker.start()

    def _on_models_fetched(
        self, success: bool, message: str, models: list[str]
    ) -> None:
        self.btn_fetch_models.setEnabled(True)
        if success:
            current_model = self.combo_ollama_model.currentText()
            self.combo_ollama_model.clear()
            for m in models:
                self.combo_ollama_model.addItem(m)
            if current_model and current_model in models:
                self.combo_ollama_model.setCurrentText(current_model)
            elif models:
                self.combo_ollama_model.setCurrentIndex(0)

            self.lbl_ollama_status.setText(f"Success! Loaded {len(models)} model(s).")
            self.lbl_ollama_status.setStyleSheet(f"color: {COLORS.success_text};")
        else:
            self.lbl_ollama_status.setText(f"Fetch failed: {message}")
            self.lbl_ollama_status.setStyleSheet(f"color: {COLORS.risk_high_text};")

    def _test_ollama_clicked(self) -> None:
        url = self.input_ollama_url.text().strip()
        key = self.input_ollama_key.text().strip()
        allow_custom = self.check_custom_host.isChecked()

        self.btn_test_ollama.setEnabled(False)
        self.lbl_ollama_status.setText("Testing connection...")
        self.lbl_ollama_status.setStyleSheet(f"color: {COLORS.info_text};")

        self._worker = OllamaConnectionWorker(
            base_url=url,
            api_key=key,
            allow_custom_host=allow_custom,
            parent=self,
        )
        self._worker.finished_result.connect(self._on_connection_tested)
        self._worker.start()

    def _on_connection_tested(
        self, success: bool, message: str, models: list[str]
    ) -> None:
        self.btn_test_ollama.setEnabled(True)
        if success:
            self.lbl_ollama_status.setText(message)
            self.lbl_ollama_status.setStyleSheet(f"color: {COLORS.success_text};")
        else:
            self.lbl_ollama_status.setText(f"Connection error: {message}")
            self.lbl_ollama_status.setStyleSheet(f"color: {COLORS.risk_high_text};")

    def set_settings(self, settings: AppSettings) -> None:
        """Populate widget inputs from AppSettings."""
        self._settings = settings

        # Provider
        idx = self.combo_provider.findText(settings.provider)
        if idx >= 0:
            self.combo_provider.setCurrentIndex(idx)

        # Meta
        self.input_meta_key.setText(settings.meta_api_key)
        self.combo_meta_model.setEditText(settings.meta_model)

        # Ollama
        self.input_ollama_key.setText(settings.ollama_api_key)
        self.combo_ollama_model.setEditText(settings.ollama_model)
        self.input_ollama_url.setText(settings.ollama_base_url)
        self.check_custom_host.setChecked(settings.allow_custom_host)

        # Reasoning params
        self.spin_timeout.setValue(settings.timeout)
        self.spin_retries.setValue(settings.max_retries)
        self.check_cache.setChecked(settings.enable_cache)

        # Privacy
        self.spin_max_cmd.setValue(settings.max_command_chars)
        self.spin_max_items.setValue(settings.max_evidence_items)
        self.input_custom_aliases.setText(settings.custom_username_aliases)

        # Storage
        self.spin_min_growth.setValue(
            settings.min_growth_bytes_per_second / (1024.0 * 1024.0)
        )
        self.spin_max_skew.setValue(settings.max_endpoint_skew_seconds)

        self.lbl_feedback.setText("")

    def get_settings(self) -> AppSettings:
        """Extract and validate AppSettings from widget inputs."""
        prov_text = self.combo_provider.currentText().lower()
        provider: ProviderType = (
            prov_text
            if prov_text in ("mock", "ollama-cloud", "meta")
            else "mock"  # type: ignore[assignment]
        )

        min_growth = float(self.spin_min_growth.value()) * (1024.0 * 1024.0)

        meta_mod = (
            self.combo_meta_model.currentText().strip()
            or "llama-3.3-70b-instruct"
        )
        ollama_mod = (
            self.combo_ollama_model.currentText().strip() or "gemma4:31b"
        )
        ollama_url = (
            self.input_ollama_url.text().strip() or "https://ollama.com"
        )

        return AppSettings(
            provider=provider,
            meta_api_key=self.input_meta_key.text().strip(),
            meta_model=meta_mod,
            ollama_api_key=self.input_ollama_key.text().strip(),
            ollama_model=ollama_mod,
            ollama_base_url=ollama_url,
            allow_custom_host=self.check_custom_host.isChecked(),
            timeout=float(self.spin_timeout.value()),
            max_retries=int(self.spin_retries.value()),
            enable_cache=self.check_cache.isChecked(),
            max_command_chars=int(self.spin_max_cmd.value()),
            max_evidence_items=int(self.spin_max_items.value()),
            custom_username_aliases=self.input_custom_aliases.text().strip(),
            min_growth_bytes_per_second=min_growth,
            max_endpoint_skew_seconds=float(self.spin_max_skew.value()),
            default_mode=self._settings.default_mode,
        )

    def _on_save_clicked(self) -> None:
        try:
            new_settings = self.get_settings()
            save_settings(
                new_settings,
                path=self._settings_path,
                sync_env=(self._settings_path is None),
            )
            self._settings = new_settings
            self.settings_saved.emit(new_settings)
            self.lbl_feedback.setText("Settings saved successfully!")
            self.lbl_feedback.setStyleSheet(
                f"color: {COLORS.success_text}; font-weight: 600;"
            )
        except Exception as exc:
            logger.error("Failed to save settings: %s", exc)
            self.lbl_feedback.setText(f"Error saving settings: {exc}")
            self.lbl_feedback.setStyleSheet(
                f"color: {COLORS.risk_high_text}; font-weight: 600;"
            )

    def _on_reset_clicked(self) -> None:
        defaults = AppSettings()
        self.set_settings(defaults)
        self.lbl_feedback.setText(
            "Settings reset to defaults (click Save to persist)."
        )
        self.lbl_feedback.setStyleSheet(
            f"color: {COLORS.info_text}; font-weight: 600;"
        )
