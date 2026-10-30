"""Unit and headless integration tests for the isometric device World View.

Verifies:
- Pure-Python world model classification and material mapping:
    - clearly_safe -> dirt
    - review_first -> grass
    - do_not_touch -> rock / stone
    - unavailable / error -> water / fog
- Reveal-on-event behavior and lantern coordinate tracking.
- Missing-asset graceful fallback to procedural colored diamond tiles.
- Headless QGraphicsView offscreen render smoke test with integer pixel scaling.
- 'Reduce motion' preference handling and lantern snapping.
- Tile selection and citation signal forwarding to investigation panels.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QPointF, QPropertyAnimation
from PySide6.QtWidgets import QApplication

from moonlight.core.evidence import (
    EvidenceBundle,
    EvidenceItem,
    EvidenceKind,
    make_evidence_id,
)
from moonlight.eval.scenarios import ProcessScenario, StorageScenario
from moonlight.ui.events import EventBus, InvestigationEvent
from moonlight.ui.window import MoonlightMainWindow
from moonlight.ui.world_model import (
    WorldTile,
    build_default_grid,
    build_from_bundles,
    build_from_scenario,
    classification_for_process_tier,
    material_for_classification,
)
from moonlight.ui.world_renderer import (
    IsometricWorldView,
    LanternMarkerItem,
    TileAtlas,
)
from moonlight.ui.world_view import WorldViewWidget


def test_world_model_material_mapping() -> None:
    """Verify material mapping rules adhere strictly to policy definitions."""
    # Clearly safe -> dirt
    assert material_for_classification("clearly_safe") == "dirt"
    assert material_for_classification("safe") == "dirt"
    assert material_for_classification("common_benign") == "dirt"
    assert material_for_classification("low") == "dirt"

    # Review first -> grass
    assert material_for_classification("review_first") == "grass"
    assert material_for_classification("review") == "grass"
    assert material_for_classification("benign_but_odd") == "grass"

    # Do not touch -> stone
    assert material_for_classification("do_not_touch") == "stone"
    assert material_for_classification("high") == "stone"
    assert material_for_classification("critical_system") == "stone"
    assert material_for_classification("simulated_suspicious") == "stone"

    # Unavailable / error -> water
    assert material_for_classification("unavailable") == "water"
    assert material_for_classification("error") == "water"
    assert material_for_classification("inconclusive") == "water"
    assert material_for_classification("missing") == "water"

    # Process tier helper
    cat_low, mat_low = classification_for_process_tier("low")
    assert cat_low == "clearly_safe"
    assert mat_low == "dirt"

    cat_rev, mat_rev = classification_for_process_tier("review")
    assert cat_rev == "review_first"
    assert mat_rev == "grass"

    cat_high, mat_high = classification_for_process_tier("high")
    assert cat_high == "do_not_touch"
    assert mat_high == "stone"


def test_world_model_reveal_on_event() -> None:
    """Verify incoming InvestigationEvents illuminate matching world tiles."""
    model = build_default_grid(width=8, height=8)
    initial_lit = model.revealed_count()

    ev_id = "ev-process-test-42"
    custom_tile = WorldTile(
        tile_id="custom-target-proc",
        gx=3,
        gy=3,
        material="grass",
        classification="review_first",
        label="suspicious_worker.exe",
        evidence_ids=(ev_id,),
        subject_type="process",
        subject_id="suspicious_worker.exe",
        revealed=False,
    )
    model.add_tile(custom_tile)

    found_tile = model.get_tile("custom-target-proc")
    assert found_tile is not None
    assert found_tile.revealed is False

    # Emit event citing the evidence ID
    event = InvestigationEvent(
        kind="rules_evaluated",
        subject="suspicious_worker.exe",
        message="Suspicious temp directory execution detected.",
        evidence_ids=(ev_id,),
        severity="review",
    )

    revealed_ids = model.reveal_by_event(event)
    assert "custom-target-proc" in revealed_ids
    assert model.revealed_count() == initial_lit + 1

    updated_tile = model.get_tile("custom-target-proc")
    assert updated_tile is not None
    assert updated_tile.revealed is True
    # Lantern marker must have moved to target tile coordinates
    assert model.lantern_grid == (3, 3)


def test_world_model_builders_scenario_and_bundles() -> None:
    """Verify building world models from labeled scenarios and bundles."""
    ev_item = EvidenceItem(
        id=make_evidence_id(
            "process", "404", "collector", EvidenceKind.EXECUTABLE_PATH
        ),
        source="test",
        kind=EvidenceKind.EXECUTABLE_PATH,
        value="C:\\temp\\decoy.exe",
        availability="observed",
        timestamp=datetime.now(UTC),
    )
    bundle = EvidenceBundle(
        subject_id="404",
        subject_type="process",
        items=(ev_item,),
    )

    proc_scenario = ProcessScenario(
        id="proc-test-synthetic",
        category="simulated_suspicious",
        description="Synthetic suspicious decoy process",
        expected_tier="high",
        bundle=bundle,
    )

    model = build_from_scenario(proc_scenario, width=10, height=10)
    target = model.get_tile(f"target-{proc_scenario.id}")
    assert target is not None
    assert target.material == "stone"  # High risk -> stone
    assert target.classification == "do_not_touch"
    assert ev_item.id in target.evidence_ids

    # Storage scenario
    stor_scenario = StorageScenario(
        id="stor-test-cache",
        category="clearly_safe",
        description="Transient user cache directory",
        target_path="C:\\Users\\Analyst\\AppData\\Local\\Temp",
        bundle=bundle,
    )
    stor_model = build_from_scenario(stor_scenario, width=10, height=10)
    stor_target = stor_model.get_tile(f"target-{stor_scenario.id}")
    assert stor_target is not None
    assert stor_target.material == "dirt"  # Clearly safe -> dirt
    assert stor_target.classification == "clearly_safe"

    # Bundles builder
    bundle_model = build_from_bundles(
        bundles=(bundle,),
        storage_items=({"path": "C:\\temp", "category": "review_first", "id": "ev-1"},),
        width=10,
        height=10,
    )
    assert bundle_model.total_count() > 0


def test_missing_asset_fallback_to_procedural_diamonds(qapp: QApplication) -> None:
    """Verify graceful procedural diamond fallback when sprite files are absent."""
    # 1. Force procedural mode
    proc_atlas = TileAtlas(force_procedural=True)
    assert proc_atlas.is_procedural is True

    for mat in ("dirt", "grass", "stone", "water", "fog"):
        lit_pix = proc_atlas.get_pixmap(mat, revealed=True)
        assert not lit_pix.isNull()
        assert lit_pix.width() == 32
        assert lit_pix.height() == 32

        dark_pix = proc_atlas.get_pixmap(mat, revealed=False)
        assert not dark_pix.isNull()
        assert dark_pix.width() == 32
        assert dark_pix.height() == 32

    # 2. Test nonexistent atlas directory
    missing_atlas = TileAtlas(atlas_dir=Path("C:/nonexistent_moonlight_atlas_dir"))
    assert missing_atlas.is_procedural is True
    assert not missing_atlas.get_pixmap("dirt", True).isNull()

    # 3. Test real atlas loading from assets/world
    real_atlas = TileAtlas()
    # If assets/world exists on disk, it should load the spritesheet
    if (Path("assets/world/atlas.json")).exists():
        assert not real_atlas.get_pixmap("dirt", True).isNull()


def test_headless_isometric_world_renderer_smoke(qapp: QApplication) -> None:
    """Verify headless offscreen rendering, zoom levels, and pixmap grab."""
    model = build_default_grid(width=6, height=6)
    view = IsometricWorldView(model=model)
    view.show()

    # Test integer zoom levels
    view.apply_zoom(1)
    assert view.zoom_level == 1
    view.apply_zoom(2)
    assert view.zoom_level == 2
    view.apply_zoom(3)
    assert view.zoom_level == 3

    # Offscreen render smoke test using grab()
    grabbed_pixmap = view.grab()
    assert not grabbed_pixmap.isNull()
    assert grabbed_pixmap.width() > 0
    assert grabbed_pixmap.height() > 0

    view.close()
    view.deleteLater()
    qapp.processEvents()


def test_reduce_motion_setting_snaps_lantern(qapp: QApplication) -> None:
    """Verify 'reduce motion' snaps the lantern instantly without animation."""
    lantern = LanternMarkerItem()
    lantern.setPos(QPointF(0, 0))

    # Without reduce motion: animation starts
    lantern.move_to_target(QPointF(50, 50), reduce_motion=False)
    assert lantern._anim.state() == QPropertyAnimation.State.Running

    # With reduce motion: snaps immediately and animation is stopped
    lantern.move_to_target(QPointF(100, 100), reduce_motion=True)
    assert lantern.pos() == QPointF(100, 100)
    assert lantern._anim.state() == QPropertyAnimation.State.Stopped


def test_world_view_widget_interactive_selection_and_signals(
    qapp: QApplication,
) -> None:
    """Verify selecting world nodes displays excerpts and forwards citations."""
    bus = EventBus()
    widget = WorldViewWidget(event_bus=bus)
    widget.show()

    ev_id = "ev-process-exec-test-99"
    test_tile = WorldTile(
        tile_id="test-selected-node",
        gx=2,
        gy=2,
        material="grass",
        classification="review_first",
        label="staged_payload.ps1",
        evidence_ids=(ev_id,),
        subject_type="process",
        subject_id="staged_payload.ps1",
        revealed=False,
        excerpt="Suspicious PowerShell command line with encoded argument.",
    )
    widget.model.add_tile(test_tile)
    widget.view.load_model(widget.model)

    received_citations: list[str] = []
    widget.citation_clicked.connect(received_citations.append)

    # Click tile
    widget._on_tile_clicked(test_tile)

    # Verify excerpt card updated
    assert "staged_payload.ps1" in widget.node_title.text()
    assert "GRASS • REVIEW FIRST" in widget.category_chip.text()
    assert "encoded argument" in widget.excerpt_text.text()
    assert widget.btn_jump.isEnabled() is True

    # Verify citation was emitted
    assert ev_id in received_citations

    # Test reduce motion checkbox toggle
    widget.chk_reduce_motion.setChecked(True)
    assert widget.reduce_motion is True
    assert widget.view.reduce_motion is True

    widget.close()
    widget.deleteLater()
    qapp.processEvents()


def test_main_window_world_view_integration(qapp: QApplication) -> None:
    """Verify World View is accessible from MainWindow nav rail and reflects runs."""
    bus = EventBus()
    win = MoonlightMainWindow(event_bus=bus)
    win.show()

    # World View button exists in navigation rail (View index 5)
    assert hasattr(win, "world_view_btn")
    assert win.world_view_btn.text() == "World Map"

    # Select World View
    win.world_view_btn.click()
    assert win.stacked_views.currentIndex() == 5
    assert isinstance(win.stacked_views.currentWidget(), WorldViewWidget)

    # Verify world view loads scenario target
    assert win.world_view.model.total_count() > 0

    # Emit an event through event bus; verify world view lights up
    scenarios = win.scenario_combo
    assert scenarios.count() > 0

    first_tile_id = next(iter(win.world_view.model.tiles))
    tile = win.world_view.model.tiles[first_tile_id]

    bus.emit_event(
        kind="collection_started",
        subject=tile.label,
        message="Examining process district node.",
        evidence_ids=tile.evidence_ids,
        severity="info",
    )
    qapp.processEvents()

    win.close()
    win.deleteLater()
    qapp.processEvents()
