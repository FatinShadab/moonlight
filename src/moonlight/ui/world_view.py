"""Main container widget for the Moonlight isometric device world view.

Features:
- Seamlessly integrates the isometric pixel-art renderer with investigation events.
- Real-time lit-node counter reflecting investigation progress.
- 'Reduce motion' user preference toggle disabling animated transitions.
- Interactive excerpt inspection card displaying grounded findings and citations.
- Subscribes to the Qt EventBus to reveal discovered processes and storage paths.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from moonlight.eval.scenarios import ProcessScenario, StorageScenario
from moonlight.ui.events import EventBus, InvestigationEvent, get_event_bus
from moonlight.ui.review import CitationButton
from moonlight.ui.theme import COLORS, RADII, SPACING
from moonlight.ui.world_model import (
    WorldModel,
    WorldTile,
    build_default_grid,
    build_from_bundles,
    build_from_scenario,
)
from moonlight.ui.world_renderer import IsometricWorldView, TileAtlas


class WorldViewWidget(QWidget):
    """Investigation World View visualizing endpoint state as an isometric map."""

    citation_clicked = Signal(str)
    tile_selected = Signal(object)  # WorldTile

    def __init__(
        self,
        event_bus: EventBus | None = None,
        atlas: TileAtlas | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("world_view_widget")
        self.bus = event_bus if event_bus is not None else get_event_bus()
        self.atlas = atlas if atlas is not None else TileAtlas()

        self.model: WorldModel = build_default_grid()
        self._reduce_motion: bool = False
        self.view: IsometricWorldView = IsometricWorldView(
            model=self.model, atlas=self.atlas, parent=self
        )

        self._active_selected_tile: WorldTile | None = None

        self._init_ui()
        self._bind_events()

    @property
    def reduce_motion(self) -> bool:
        """Whether motion reduction is enabled."""
        return self._reduce_motion

    @reduce_motion.setter
    def reduce_motion(self, enabled: bool) -> None:
        self._reduce_motion = enabled
        self.view.reduce_motion = enabled
        self.chk_reduce_motion.setChecked(enabled)

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(SPACING.sm)

        # 1. Top control toolbar
        toolbar = QFrame()
        toolbar.setObjectName("card")
        tb_layout = QHBoxLayout(toolbar)
        tb_layout.setContentsMargins(SPACING.md, SPACING.sm, SPACING.md, SPACING.sm)
        tb_layout.setSpacing(SPACING.md)

        title_lbl = QLabel("Device World Map (Isometric)")
        title_lbl.setStyleSheet(
            f"color: {COLORS.text_primary}; font-weight: 700; font-size: 14px;"
        )
        tb_layout.addWidget(title_lbl)

        # Lit nodes counter chip
        self.lit_chip = QLabel("Lit: 0 / 0 Nodes")
        self.lit_chip.setObjectName("lit_chip")
        self.lit_chip.setStyleSheet(
            f"background-color: {COLORS.accent_surface}; "
            f"color: {COLORS.accent_primary}; "
            f"border: 1px solid {COLORS.accent_border}; "
            f"border-radius: {RADII.pill}px; "
            f"font-weight: 700; font-size: 11px; padding: 2px 10px;"
        )
        tb_layout.addWidget(self.lit_chip)

        tb_layout.addStretch()

        # Reduce motion toggle
        self.chk_reduce_motion = QCheckBox("Reduce Motion")
        self.chk_reduce_motion.setObjectName("chk_reduce_motion")
        self.chk_reduce_motion.setToolTip(
            "Disable lantern travel animation and snap directly to active nodes"
        )
        self.chk_reduce_motion.toggled.connect(self._on_reduce_motion_toggled)
        tb_layout.addWidget(self.chk_reduce_motion)

        # Zoom buttons with dedicated class and fixed dimensions
        zoom_box = QHBoxLayout()
        zoom_box.setSpacing(SPACING.xs)
        z_lbl = QLabel("Zoom:")
        z_lbl.setStyleSheet(f"color: {COLORS.text_muted}; font-size: 11px;")
        zoom_box.addWidget(z_lbl)

        for z in (1, 2, 3):
            btn = QPushButton(f"{z}x")
            btn.setObjectName(f"zoom_btn_{z}")
            btn.setProperty("class", "icon-btn")
            btn.setFixedSize(28, 28)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setToolTip(f"Zoom {z * 100}% ({z}x)")
            btn.clicked.connect(
                lambda _checked=False, level=z: self.view.apply_zoom(level)
            )
            zoom_box.addWidget(btn)
        tb_layout.addLayout(zoom_box)

        # Center view button
        btn_center = QPushButton("Center Focus")
        btn_center.setObjectName("btn_center")
        btn_center.setToolTip("Center camera on current lantern position")
        btn_center.clicked.connect(self.view.center_on_lantern)
        tb_layout.addWidget(btn_center)

        layout.addWidget(toolbar)

        # 2. Isometric Graphics View
        self.view.tile_clicked.connect(self._on_tile_clicked)
        layout.addWidget(self.view, stretch=1)

        # 3. Bottom Inspection & Excerpt Card
        self.excerpt_card = QFrame()
        self.excerpt_card.setObjectName("card")
        card_layout = QVBoxLayout(self.excerpt_card)
        card_layout.setContentsMargins(SPACING.md, SPACING.sm, SPACING.md, SPACING.sm)
        card_layout.setSpacing(SPACING.xs)

        header_row = QHBoxLayout()
        header_row.setSpacing(SPACING.sm)

        self.node_title = QLabel("Select a node on the map to inspect evidence")
        self.node_title.setStyleSheet(
            f"color: {COLORS.text_primary}; font-weight: 700; font-size: 13px;"
        )
        header_row.addWidget(self.node_title)

        self.category_chip = QLabel("STANDBY")
        self.category_chip.setStyleSheet(
            f"background-color: {COLORS.bg_surface}; "
            f"color: {COLORS.text_muted}; "
            f"border: 1px solid {COLORS.border_subtle}; "
            f"border-radius: {RADII.pill}px; "
            f"font-weight: 700; font-size: 10px; padding: 1px 8px;"
        )
        header_row.addWidget(self.category_chip)
        header_row.addStretch()

        self.btn_jump = QPushButton("Jump to Evidence")
        self.btn_jump.setObjectName("btn_jump")
        self.btn_jump.setEnabled(False)
        self.btn_jump.clicked.connect(self._on_jump_clicked)
        header_row.addWidget(self.btn_jump)

        card_layout.addLayout(header_row)

        desc_init = (
            "The isometric world map visualizes endpoints as structured districts. "
            "Investigation events illuminate verified harmless components (dirt), "
            "review targets (grass), and critical system resources (stone)."
        )
        self.excerpt_text = QLabel(desc_init)
        self.excerpt_text.setWordWrap(True)
        self.excerpt_text.setStyleSheet(
            f"color: {COLORS.text_secondary}; font-size: 12px;"
        )
        card_layout.addWidget(self.excerpt_text)

        # Citations row
        self.citations_container = QWidget()
        self.citations_layout = QHBoxLayout(self.citations_container)
        self.citations_layout.setContentsMargins(0, 0, 0, 0)
        self.citations_layout.setSpacing(SPACING.xs)
        self.citations_label = QLabel("Citations:")
        self.citations_label.setStyleSheet(
            f"color: {COLORS.text_muted}; font-size: 11px;"
        )
        self.citations_layout.addWidget(self.citations_label)
        self.citations_layout.addStretch()
        self.citations_container.setVisible(False)
        card_layout.addWidget(self.citations_container)

        layout.addWidget(self.excerpt_card)

        self._update_lit_counter()

    def _bind_events(self) -> None:
        """Subscribe to EventBus to reveal nodes on incoming investigation events."""
        self.bus.event_emitted.connect(self._on_investigation_event)

    def _on_reduce_motion_toggled(self, checked: bool) -> None:
        self._reduce_motion = checked
        self.view.reduce_motion = checked

    def _on_investigation_event(self, event: InvestigationEvent) -> None:
        """Handle incoming telemetry events from the core pipeline."""
        revealed_ids = self.model.reveal_by_event(event)
        if revealed_ids:
            self.view.update_reveals(self.model, reduce_motion=self._reduce_motion)
            self._update_lit_counter()
            first_tile = self.model.get_tile(revealed_ids[0])
            if first_tile is not None:
                self._update_excerpt_card(first_tile)

    def _on_tile_clicked(self, tile: WorldTile) -> None:
        """Handle user clicking a tile in the isometric graphics view."""
        self._active_selected_tile = tile
        self.tile_selected.emit(tile)
        self._update_excerpt_card(tile)

        # Emit citation click if tile carries evidence
        if tile.evidence_ids:
            self.citation_clicked.emit(tile.evidence_ids[0])

    def _on_jump_clicked(self) -> None:
        """Handle explicit 'Jump to Evidence' button click."""
        if self._active_selected_tile and self._active_selected_tile.evidence_ids:
            self.citation_clicked.emit(self._active_selected_tile.evidence_ids[0])

    def _update_excerpt_card(self, tile: WorldTile) -> None:
        """Update inspection card with tile's classification and excerpt."""
        self._active_selected_tile = tile
        self.node_title.setText(f"{tile.label} ({tile.subject_type.upper()})")

        # Classification badge styling
        cat = tile.classification.upper().replace("_", " ")
        mat = tile.material.upper()
        if tile.material == "dirt":
            chip_style = (
                f"background-color: {COLORS.risk_low_bg}; "
                f"color: {COLORS.risk_low_text}; "
                f"border: 1px solid {COLORS.risk_low_border};"
            )
        elif tile.material == "grass":
            chip_style = (
                f"background-color: {COLORS.risk_review_bg}; "
                f"color: {COLORS.risk_review_text}; "
                f"border: 1px solid {COLORS.risk_review_border};"
            )
        elif tile.material == "stone":
            chip_style = (
                f"background-color: {COLORS.risk_high_bg}; "
                f"color: {COLORS.risk_high_text}; "
                f"border: 1px solid {COLORS.risk_high_border};"
            )
        else:
            chip_style = (
                f"background-color: {COLORS.accent_surface}; "
                f"color: {COLORS.accent_primary}; "
                f"border: 1px solid {COLORS.accent_border};"
            )

        self.category_chip.setText(f"{mat} • {cat}")
        self.category_chip.setStyleSheet(
            f"{chip_style} border-radius: {RADII.pill}px; "
            f"font-weight: 700; font-size: 10px; padding: 1px 8px;"
        )

        desc = tile.excerpt or (
            f"Node ID: {tile.tile_id} at grid ({tile.gx}, {tile.gy}). "
            f"Size: {tile.size_bytes:,} bytes."
        )
        self.excerpt_text.setText(desc)

        # Update citations
        while self.citations_layout.count() > 1:
            item = self.citations_layout.takeAt(1)
            if item is not None:
                w = item.widget()
                if w is not None:
                    w.deleteLater()

        if tile.evidence_ids:
            self.citations_container.setVisible(True)
            self.btn_jump.setEnabled(True)
            for eid in tile.evidence_ids:
                btn = CitationButton(eid)
                btn.clicked.connect(
                    lambda _checked=False, cid=eid: self.citation_clicked.emit(cid)
                )
                self.citations_layout.addWidget(btn)
            self.citations_layout.addStretch()
        else:
            self.citations_container.setVisible(False)
            self.btn_jump.setEnabled(False)

    def _update_lit_counter(self) -> None:
        """Update lit nodes count chip."""
        lit = self.model.revealed_count()
        tot = self.model.total_count()
        self.lit_chip.setText(f"Lit: {lit} / {tot} Nodes")

    def load_scenario(self, scenario: ProcessScenario | StorageScenario | Any) -> None:
        """Populate and display world model for a synthetic scenario."""
        if isinstance(scenario, ProcessScenario | StorageScenario):
            self.model = build_from_scenario(scenario)
            self.view.load_model(self.model)
            self._update_lit_counter()
            target = self.model.get_tile(f"target-{scenario.id}")
            if target is not None:
                self._update_excerpt_card(target)

    def load_investigation_result(self, result: Any) -> None:
        """Populate world model from investigation bundles and storage findings."""
        bundles = getattr(result, "bundles", ())
        storage_items = getattr(result, "storage_items", ())
        self.model = build_from_bundles(bundles, storage_items)
        self.view.load_model(self.model)
        self._update_lit_counter()
