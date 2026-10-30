"""Isometric QGraphicsView renderer for the Moonlight device world view.

Features:
- Integer pixel scaling with smoothing disabled (sharp pixel art aesthetics).
- Sprite atlas loader with automatic procedural colored diamond fallback.
- Unrevealed tiles render darkened; evidence events light and reveal them.
- Lantern marker tracking active investigation focus with reduce-motion support.
- Interactive tile selection displaying report excerpts and evidence citations.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from PySide6.QtCore import (
    QEasingCurve,
    QPointF,
    QPropertyAnimation,
    QRectF,
    Qt,
    Signal,
)
from PySide6.QtGui import (
    QColor,
    QImage,
    QPainter,
    QPen,
    QPixmap,
    QPolygonF,
)
from PySide6.QtWidgets import (
    QGraphicsItem,
    QGraphicsObject,
    QGraphicsPixmapItem,
    QGraphicsScene,
    QGraphicsView,
    QWidget,
)

from moonlight.ui.world_model import TileMaterial, WorldModel, WorldTile

_DEFAULT_ATLAS_DIR = Path(__file__).resolve().parents[3] / "assets" / "world"


class TileAtlas:
    """Manages loaded sprite sheets or generates procedural diamond fallbacks."""

    def __init__(
        self,
        atlas_dir: Path | str | None = None,
        force_procedural: bool = False,
    ) -> None:
        self.atlas_dir = Path(atlas_dir) if atlas_dir else _DEFAULT_ATLAS_DIR
        self.force_procedural = force_procedural
        self._spritesheet: QImage | None = None
        self._atlas_data: dict[str, Any] = {}
        self._lit_cache: dict[TileMaterial, QPixmap] = {}
        self._dark_cache: dict[TileMaterial, QPixmap] = {}
        self._is_procedural: bool = False

        self._initialize()

    @property
    def is_procedural(self) -> bool:
        """Whether the atlas is using procedural fallback diamond rendering."""
        return self._is_procedural

    def _initialize(self) -> None:
        atlas_file = self.atlas_dir / "atlas.json"
        sheet_file = self.atlas_dir / "spritesheet.png"

        if not self.force_procedural and atlas_file.exists() and sheet_file.exists():
            try:
                data = json.loads(atlas_file.read_text(encoding="utf-8"))
                img = QImage(str(sheet_file))
                if not img.isNull() and "materials" in data:
                    self._atlas_data = data
                    self._spritesheet = img
                    self._is_procedural = False
                    self._precache_materials()
                    return
            except Exception:
                pass  # Fallback to procedural

        self._is_procedural = True
        self._precache_procedural()

    def _precache_materials(self) -> None:
        """Slice material tiles from spritesheet into lit and dark variants."""
        if not self._spritesheet:
            self._precache_procedural()
            return

        materials_meta = self._atlas_data.get("materials", {})
        for mat in ("dirt", "grass", "stone", "water", "fog"):
            m_key = mat
            if m_key in materials_meta:
                meta = materials_meta[m_key]
                x = int(meta.get("x", 0))
                y = int(meta.get("y", 0))
                w = int(meta.get("width", 32))
                h = int(meta.get("height", 32))
                sub_img = self._spritesheet.copy(x, y, w, h)
                lit_pix = QPixmap.fromImage(sub_img)
            else:
                lit_pix = self._generate_procedural_diamond(mat)

            self._lit_cache[mat] = lit_pix
            self._dark_cache[mat] = self._make_darkened_pixmap(lit_pix)

    def _precache_procedural(self) -> None:
        """Pre-generate procedural diamond tiles for all supported materials."""
        for mat in ("dirt", "grass", "stone", "water", "fog"):
            lit_pix = self._generate_procedural_diamond(mat)
            self._lit_cache[mat] = lit_pix
            self._dark_cache[mat] = self._make_darkened_pixmap(lit_pix)

    def _generate_procedural_diamond(self, material: TileMaterial) -> QPixmap:
        """Generate a 32x32 isometric diamond block procedurally."""
        pix = QPixmap(32, 32)
        pix.fill(QColor(0, 0, 0, 0))

        color_map: dict[TileMaterial, tuple[str, str, str]] = {
            "dirt": ("#ad7757", "#8f5d40", "#73462d"),
            "grass": ("#75a743", "#5b8a30", "#456e22"),
            "stone": ("#819796", "#627574", "#4b5a59"),
            "water": ("#73bed3", "#549db1", "#3b7e90"),
            "fog": ("#1e293b", "#172033", "#0f172a"),
        }
        top_c, left_c, right_c = color_map.get(
            material, ("#1e293b", "#172033", "#0f172a")
        )

        painter = QPainter(pix)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        painter.setPen(Qt.PenStyle.NoPen)

        # 1. Left front side
        left_poly = QPolygonF(
            [
                QPointF(1, 11),
                QPointF(16, 18),
                QPointF(16, 27),
                QPointF(1, 20),
            ]
        )
        painter.setBrush(QColor(left_c))
        painter.drawPolygon(left_poly)

        # 2. Right front side
        right_poly = QPolygonF(
            [
                QPointF(16, 18),
                QPointF(31, 11),
                QPointF(31, 20),
                QPointF(16, 27),
            ]
        )
        painter.setBrush(QColor(right_c))
        painter.drawPolygon(right_poly)

        # 3. Top surface diamond
        top_poly = QPolygonF(
            [
                QPointF(16, 4),
                QPointF(31, 11),
                QPointF(16, 18),
                QPointF(1, 11),
            ]
        )
        painter.setBrush(QColor(top_c))
        painter.drawPolygon(top_poly)

        painter.end()
        return pix

    def _make_darkened_pixmap(self, pixmap: QPixmap) -> QPixmap:
        """Create an unrevealed darkened/fogged variant of a tile pixmap."""
        dark = QPixmap(pixmap.size())
        dark.fill(QColor(0, 0, 0, 0))

        painter = QPainter(dark)
        painter.drawPixmap(0, 0, pixmap)
        painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceAtop)
        # Deep midnight blue-gray fog tint
        painter.fillRect(dark.rect(), QColor(11, 15, 25, 180))
        painter.end()
        return dark

    def get_pixmap(self, material: TileMaterial, revealed: bool) -> QPixmap:
        """Retrieve the appropriate pixmap for material and reveal status."""
        cache = self._lit_cache if revealed else self._dark_cache
        if material in cache:
            return cache[material]
        return cache.get("fog", self._generate_procedural_diamond("fog"))


class IsometricTileGraphicsItem(QGraphicsPixmapItem):
    """Interactive visual representation of a single world tile."""

    def __init__(
        self,
        tile: WorldTile,
        atlas: TileAtlas,
        parent: QGraphicsItem | None = None,
    ) -> None:
        super().__init__(parent)
        self.tile = tile
        self.atlas = atlas
        self.is_hovered: bool = False
        self.is_selected: bool = False

        self.setAcceptHoverEvents(True)
        self.setTransformationMode(Qt.TransformationMode.FastTransformation)
        self.update_appearance()

    def update_tile(self, tile: WorldTile) -> None:
        """Update data and refresh appearance."""
        self.tile = tile
        self.update_appearance()

    def update_appearance(self) -> None:
        """Refresh pixmap based on material, revealed state, and selection."""
        base_pix = self.atlas.get_pixmap(self.tile.material, self.tile.revealed)

        if self.is_selected or self.is_hovered:
            pix = QPixmap(base_pix)
            painter = QPainter(pix)
            pen_color = QColor("#38bdf8") if self.is_selected else QColor("#94a3b8")
            painter.setPen(QPen(pen_color, 1))
            painter.drawPolygon(
                QPolygonF(
                    [
                        QPointF(16, 4),
                        QPointF(31, 11),
                        QPointF(16, 18),
                        QPointF(1, 11),
                    ]
                )
            )
            painter.end()
            self.setPixmap(pix)
        else:
            self.setPixmap(base_pix)

    def hoverEnterEvent(self, event: Any) -> None:
        self.is_hovered = True
        self.update_appearance()
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event: Any) -> None:
        self.is_hovered = False
        self.update_appearance()
        super().hoverLeaveEvent(event)


class LanternMarkerItem(QGraphicsObject):
    """Floating glowing lantern marker positioned over the active investigation tile."""

    def __init__(self, parent: QGraphicsItem | None = None) -> None:
        super().__init__(parent)
        self.setZValue(10000)  # Always render above all isometric tiles
        self._anim = QPropertyAnimation(self, b"pos")
        self._anim.setDuration(220)
        self._anim.setEasingCurve(QEasingCurve.Type.InOutQuad)

    def boundingRect(self) -> QRectF:
        return QRectF(-16, -24, 32, 32)

    def paint(
        self,
        painter: QPainter,
        option: Any,
        widget: QWidget | None = None,
    ) -> None:
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)

        # Amber outer glow
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(245, 158, 11, 70))
        painter.drawEllipse(QPointF(0, -6), 14, 14)

        # Lantern frame
        painter.setBrush(QColor(120, 53, 15))
        painter.drawRect(QRectF(-5, -14, 10, 16))

        # Bright warm glass and flame
        painter.setBrush(QColor(254, 240, 138))
        painter.drawRect(QRectF(-3, -11, 6, 10))

        # Core flame spark
        painter.setBrush(QColor(255, 255, 255))
        painter.drawRect(QRectF(-1, -8, 2, 4))

        # Top cap and loop
        painter.setBrush(QColor(180, 83, 9))
        painter.drawRect(QRectF(-3, -16, 6, 2))
        painter.drawRect(QRectF(-1, -19, 2, 3))

    def move_to_target(
        self,
        target_pos: QPointF,
        reduce_motion: bool = False,
    ) -> None:
        """Position or animate lantern to target coordinates."""
        if reduce_motion:
            self._anim.stop()
            self.setPos(target_pos)
        else:
            self._anim.stop()
            self._anim.setStartValue(self.pos())
            self._anim.setEndValue(target_pos)
            self._anim.start()


class IsometricWorldView(QGraphicsView):
    """QGraphicsView displaying the 2:1 isometric world with pixel-perfect scaling."""

    tile_clicked = Signal(object)  # WorldTile

    def __init__(
        self,
        model: WorldModel | None = None,
        atlas: TileAtlas | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("world_graphics_view")
        self.atlas = atlas if atlas is not None else TileAtlas()
        self.scene_obj = QGraphicsScene(self)
        self.setScene(self.scene_obj)

        self._model: WorldModel = model if model is not None else WorldModel()
        self._tile_items: dict[str, IsometricTileGraphicsItem] = {}
        self._lantern_item = LanternMarkerItem()
        self.scene_obj.addItem(self._lantern_item)

        self._zoom_level: int = 2
        self._reduce_motion: bool = False

        self._configure_view()
        if model is not None:
            self.load_model(model)

    @property
    def zoom_level(self) -> int:
        return self._zoom_level

    @property
    def reduce_motion(self) -> bool:
        return self._reduce_motion

    @reduce_motion.setter
    def reduce_motion(self, enabled: bool) -> None:
        self._reduce_motion = enabled

    def _configure_view(self) -> None:
        # Enforce pixel art rendering: disable antialiasing and smoothing
        self.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        self.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, False)
        self.setStyleSheet("background-color: #0b0f19; border: none;")
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)
        self.apply_zoom(self._zoom_level)

    def apply_zoom(self, zoom: int) -> None:
        """Apply integer pixel scale factor without smoothing."""
        self._zoom_level = max(1, min(zoom, 4))
        self.resetTransform()
        self.scale(float(self._zoom_level), float(self._zoom_level))

    @staticmethod
    def grid_to_screen(gx: int, gy: int) -> tuple[float, float]:
        """Convert grid (gx, gy) to 2:1 isometric screen coordinates."""
        sx = (gx - gy) * 16.0
        sy = (gx + gy) * 8.0
        return sx, sy

    def load_model(self, model: WorldModel) -> None:
        """Rebuild scene items from a WorldModel."""
        self._model = model

        # Clear existing tile items
        for item in self._tile_items.values():
            self.scene_obj.removeItem(item)
        self._tile_items.clear()

        # Add all world tiles
        for tile in model.tiles.values():
            item = IsometricTileGraphicsItem(tile=tile, atlas=self.atlas)
            sx, sy = self.grid_to_screen(tile.gx, tile.gy)
            item.setPos(sx, sy)
            # Depth sort: tiles in front (greater gx+gy) overlap tiles behind
            item.setZValue(tile.gx + tile.gy)
            self.scene_obj.addItem(item)
            self._tile_items[tile.tile_id] = item

        # Reposition lantern marker
        self._update_lantern_position(reduce_motion=True)
        self.center_on_lantern()

    def update_reveals(
        self,
        model: WorldModel,
        reduce_motion: bool | None = None,
    ) -> None:
        """Synchronize revealed states and lantern position from WorldModel."""
        self._model = model
        use_reduce_motion = (
            self._reduce_motion if reduce_motion is None else reduce_motion
        )

        for tid, tile in model.tiles.items():
            if tid in self._tile_items:
                item = self._tile_items[tid]
                item.is_selected = tid == model.selected_tile_id
                item.update_tile(tile)

        self._update_lantern_position(reduce_motion=use_reduce_motion)

    def _update_lantern_position(self, reduce_motion: bool = False) -> None:
        gx, gy = self._model.lantern_grid
        sx, sy = self.grid_to_screen(gx, gy)
        target = QPointF(sx + 16.0, sy + 6.0)
        self._lantern_item.move_to_target(target, reduce_motion=reduce_motion)

    def center_on_lantern(self) -> None:
        """Center the viewport on the lantern marker."""
        gx, gy = self._model.lantern_grid
        sx, sy = self.grid_to_screen(gx, gy)
        self.centerOn(sx + 16.0, sy + 16.0)

    def mousePressEvent(self, event: Any) -> None:
        item = self.itemAt(event.position().toPoint())
        if isinstance(item, IsometricTileGraphicsItem):
            # Update selection
            for other in self._tile_items.values():
                other.is_selected = False
                other.update_appearance()
            item.is_selected = True
            item.update_appearance()

            self._model.select_tile(item.tile.tile_id)
            self.tile_clicked.emit(item.tile)
            self._update_lantern_position(reduce_motion=self._reduce_motion)

        super().mousePressEvent(event)
