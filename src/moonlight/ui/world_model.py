"""Pure-Python data model for the Moonlight isometric device world view.

Features:
- Decoupled, pure-Python representation suitable for headless testing.
- Maps folders and processes to tiles with material, classification, and label.
- Material mapping rules:
    - clearly_safe -> dirt
    - review_first -> grass
    - do_not_touch -> rock / stone
    - unavailable / error -> water / fog
- Event-driven tile revealing and lantern position tracking.
- Scenario and evidence bundle builders for replay and live investigations.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from moonlight.core.evidence import EvidenceBundle
from moonlight.eval.scenarios import ProcessScenario, StorageScenario
from moonlight.ui.events import InvestigationEvent

TileMaterial = Literal["dirt", "grass", "stone", "water", "fog"]
TileClassification = Literal[
    "clearly_safe", "review_first", "do_not_touch", "unavailable"
]
TileSubject = Literal["process", "storage", "system"]


def material_for_classification(
    classification: str | TileClassification,
) -> TileMaterial:
    """Map a storage or process safety classification to its isometric material."""
    cleaned = str(classification).lower().strip()
    if cleaned in ("clearly_safe", "safe", "common_benign", "low"):
        return "dirt"
    if cleaned in ("review_first", "review", "benign_but_odd", "benign_odd"):
        return "grass"
    if cleaned in (
        "do_not_touch",
        "high",
        "simulated_suspicious",
        "suspicious_simulated",
        "critical_system",
    ):
        return "stone"
    if cleaned in ("unavailable", "error", "inconclusive", "missing"):
        return "water"
    return "fog"


def classification_for_process_tier(
    tier: str,
) -> tuple[TileClassification, TileMaterial]:
    """Map a process risk tier to classification and material."""
    t = tier.lower().strip()
    if t == "low":
        return "clearly_safe", "dirt"
    if t == "review":
        return "review_first", "grass"
    if t == "high":
        return "do_not_touch", "stone"
    return "unavailable", "water"


class WorldTile(BaseModel):
    """An isometric grid tile representing a process, folder, or endpoint node."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tile_id: str = Field(
        min_length=1, description="Unique identifier for this world tile."
    )
    gx: int = Field(ge=0, description="Isometric grid column X coordinate.")
    gy: int = Field(ge=0, description="Isometric grid row Y coordinate.")
    material: TileMaterial = Field(
        description="Assigned material: dirt, grass, stone, water, or fog."
    )
    classification: TileClassification = Field(
        description="Policy category: safe, review, do_not_touch, or unavailable."
    )
    label: str = Field(min_length=1, description="Human-readable title or node name.")
    size_bytes: int = Field(
        default=0, ge=0, description="Estimated byte size of file, folder, or memory."
    )
    evidence_ids: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Evidence item citations associated with this node.",
    )
    subject_type: TileSubject = Field(
        default="process", description="Domain subject type (process, storage, system)."
    )
    subject_id: str = Field(
        default="", description="Unique identifier of subject (e.g. PID or path ID)."
    )
    revealed: bool = Field(
        default=False,
        description="Whether this tile has been lit by an investigation event.",
    )
    excerpt: str = Field(
        default="",
        description="Brief summary or report finding associated with this tile.",
    )

    def with_revealed(self, revealed: bool = True) -> WorldTile:
        """Return a copy of this tile with updated revealed status."""
        return self.model_copy(update={"revealed": revealed})


class WorldModel:
    """Coordinate system and state manager for the isometric investigation world."""

    def __init__(self, width: int = 10, height: int = 10) -> None:
        self.width = max(1, width)
        self.height = max(1, height)
        self._tiles: dict[str, WorldTile] = {}
        self._grid: dict[tuple[int, int], str] = {}
        self._lantern_grid: tuple[int, int] = (0, 0)
        self._selected_tile_id: str | None = None

    @property
    def tiles(self) -> dict[str, WorldTile]:
        """Return map of tile_id to WorldTile."""
        return dict(self._tiles)

    @property
    def lantern_grid(self) -> tuple[int, int]:
        """Current grid coordinates (gx, gy) where the lantern marker rests."""
        return self._lantern_grid

    @lantern_grid.setter
    def lantern_grid(self, coords: tuple[int, int]) -> None:
        self._lantern_grid = coords

    @property
    def selected_tile_id(self) -> str | None:
        """Currently selected tile ID, if any."""
        return self._selected_tile_id

    def add_tile(self, tile: WorldTile) -> None:
        """Add or update a tile in the world model."""
        self._tiles[tile.tile_id] = tile
        self._grid[(tile.gx, tile.gy)] = tile.tile_id

    def get_tile(self, tile_id: str) -> WorldTile | None:
        """Fetch tile by unique ID."""
        return self._tiles.get(tile_id)

    def get_tile_at(self, gx: int, gy: int) -> WorldTile | None:
        """Fetch tile at grid coordinates."""
        tid = self._grid.get((gx, gy))
        if tid is None:
            return None
        return self._tiles.get(tid)

    def reveal_tile(self, tile_id: str) -> bool:
        """Reveal a single tile by ID. Returns True if tile was found and revealed."""
        tile = self._tiles.get(tile_id)
        if tile is None:
            return False
        if not tile.revealed:
            self._tiles[tile_id] = tile.with_revealed(True)
            self._lantern_grid = (tile.gx, tile.gy)
            return True
        return False

    def reveal_by_evidence_id(self, evidence_id: str) -> list[str]:
        """Reveal all tiles citing a given evidence ID. Returns revealed tile IDs."""
        revealed_ids: list[str] = []
        for tid, tile in self._tiles.items():
            if evidence_id in tile.evidence_ids:
                if not tile.revealed:
                    self._tiles[tid] = tile.with_revealed(True)
                    revealed_ids.append(tid)
                self._lantern_grid = (tile.gx, tile.gy)
        return revealed_ids

    def reveal_by_event(self, event: InvestigationEvent) -> list[str]:
        """Reveal tiles associated with an incoming InvestigationEvent.

        Matches either through cited evidence IDs, subject string, or kind.
        """
        revealed_ids: list[str] = []

        # 1. Direct evidence ID match
        for ev_id in event.evidence_ids:
            rev = self.reveal_by_evidence_id(ev_id)
            revealed_ids.extend(rev)

        # 2. Subject name / path match if no evidence IDs matched
        if not revealed_ids and event.subject:
            subj_lower = event.subject.lower()
            for tid, tile in self._tiles.items():
                if (
                    tile.subject_id.lower() == subj_lower
                    or tile.label.lower() in subj_lower
                    or subj_lower in tile.label.lower()
                ):
                    if not tile.revealed:
                        self._tiles[tid] = tile.with_revealed(True)
                        revealed_ids.append(tid)
                    self._lantern_grid = (tile.gx, tile.gy)

        return revealed_ids

    def select_tile(self, tile_id: str | None) -> WorldTile | None:
        """Select a tile by ID and move lantern to it."""
        self._selected_tile_id = tile_id
        if tile_id is not None and tile_id in self._tiles:
            tile = self._tiles[tile_id]
            self._lantern_grid = (tile.gx, tile.gy)
            return tile
        return None

    def revealed_count(self) -> int:
        """Return total number of currently revealed tiles."""
        return sum(1 for t in self._tiles.values() if t.revealed)

    def total_count(self) -> int:
        """Return total number of registered tiles."""
        return len(self._tiles)


def build_default_grid(width: int = 10, height: int = 10) -> WorldModel:
    """Generate a structured default device grid (Process and Storage districts)."""
    model = WorldModel(width=width, height=height)

    # Process District: Rows 0 to 4
    process_templates = [
        ("proc-sys", 1, 1, "stone", "do_not_touch", "System (PID 4)", 0, "process"),
        ("proc-csrss", 2, 1, "stone", "do_not_touch", "csrss.exe", 0, "process"),
        ("proc-svchost", 1, 2, "dirt", "clearly_safe", "svchost.exe", 0, "process"),
        ("proc-explorer", 2, 2, "dirt", "clearly_safe", "explorer.exe", 0, "process"),
        ("proc-dwm", 3, 2, "dirt", "clearly_safe", "dwm.exe", 0, "process"),
        ("proc-target", 2, 3, "grass", "review_first", "Active Process", 0, "process"),
    ]

    for tid, gx, gy, mat, cat, lbl, sz, subj in process_templates:
        if gx < width and gy < height:
            model.add_tile(
                WorldTile(
                    tile_id=tid,
                    gx=gx,
                    gy=gy,
                    material=mat,  # type: ignore[arg-type]
                    classification=cat,  # type: ignore[arg-type]
                    label=lbl,
                    size_bytes=sz,
                    subject_type=subj,  # type: ignore[arg-type]
                    subject_id=lbl,
                    revealed=False,
                )
            )

    # Storage District: Rows 5 to 9
    storage_templates = [
        (
            "stor-sys32",
            6,
            6,
            "stone",
            "do_not_touch",
            "C:\\Windows\\System32",
            1024 * 1024 * 500,
            "storage",
        ),
        (
            "stor-prog",
            7,
            6,
            "stone",
            "do_not_touch",
            "C:\\Program Files",
            1024 * 1024 * 1200,
            "storage",
        ),
        (
            "stor-temp",
            6,
            7,
            "dirt",
            "clearly_safe",
            "AppData\\Local\\Temp",
            1024 * 1024 * 45,
            "storage",
        ),
        (
            "stor-wintemp",
            7,
            7,
            "dirt",
            "clearly_safe",
            "C:\\Windows\\Temp",
            1024 * 1024 * 12,
            "storage",
        ),
        (
            "stor-downloads",
            6,
            8,
            "grass",
            "review_first",
            "Downloads",
            1024 * 1024 * 850,
            "storage",
        ),
        (
            "stor-staged",
            7,
            8,
            "grass",
            "review_first",
            "Staged Updates",
            1024 * 1024 * 220,
            "storage",
        ),
    ]

    for tid, gx, gy, mat, cat, lbl, sz, subj in storage_templates:
        if gx < width and gy < height:
            model.add_tile(
                WorldTile(
                    tile_id=tid,
                    gx=gx,
                    gy=gy,
                    material=mat,  # type: ignore[arg-type]
                    classification=cat,  # type: ignore[arg-type]
                    label=lbl,
                    size_bytes=sz,
                    subject_type=subj,  # type: ignore[arg-type]
                    subject_id=lbl,
                    revealed=False,
                )
            )

    # Fill remaining grid slots with neutral background fog or water perimeter
    for y in range(height):
        for x in range(width):
            if model.get_tile_at(x, y) is None:
                # Water on outer border, fog inside
                is_border = x == 0 or y == 0 or x == width - 1 or y == height - 1
                border_mat: TileMaterial = "water" if is_border else "fog"
                model.add_tile(
                    WorldTile(
                        tile_id=f"tile-grid-{x}-{y}",
                        gx=x,
                        gy=y,
                        material=border_mat,
                        classification="unavailable",
                        label=f"Perimeter ({x},{y})" if is_border else f"Fog ({x},{y})",
                        revealed=False,
                    )
                )

    return model


def build_from_scenario(
    scenario: ProcessScenario | StorageScenario,
    width: int = 10,
    height: int = 10,
) -> WorldModel:
    """Build a world model populated with evidence and nodes from a test scenario."""
    model = build_default_grid(width=width, height=height)

    # Extract evidence IDs from bundle
    ev_ids = tuple(item.id for item in scenario.bundle.items)

    if isinstance(scenario, ProcessScenario):
        cat, mat = classification_for_process_tier(scenario.expected_tier)
        target_tile = WorldTile(
            tile_id=f"target-{scenario.id}",
            gx=4,
            gy=4,
            material=mat,
            classification=cat,
            label=f"Investigated Process: {scenario.id}",
            evidence_ids=ev_ids,
            subject_type="process",
            subject_id=scenario.bundle.subject_id,
            revealed=False,
            excerpt=(
                f"Verdict: {scenario.expected_tier.upper()}. {scenario.description}"
            ),
        )
        model.add_tile(target_tile)
        model.lantern_grid = (4, 4)

    elif isinstance(scenario, StorageScenario):
        mat = material_for_classification(scenario.category)
        target_tile = WorldTile(
            tile_id=f"target-{scenario.id}",
            gx=5,
            gy=5,
            material=mat,
            classification=scenario.category,
            label=f"Investigated Path: {scenario.target_path}",
            evidence_ids=ev_ids,
            subject_type="storage",
            subject_id=scenario.target_path,
            revealed=False,
            excerpt=f"Category: {scenario.category.upper()}. {scenario.description}",
        )
        model.add_tile(target_tile)
        model.lantern_grid = (5, 5)

    return model


def build_from_bundles(
    bundles: Sequence[EvidenceBundle],
    storage_items: Sequence[dict[str, Any]] = (),
    width: int = 10,
    height: int = 10,
) -> WorldModel:
    """Construct an active world model from live investigation bundles."""
    model = build_default_grid(width=width, height=height)

    gx_proc, gy_proc = 1, 3
    gx_stor, gy_stor = 5, 7

    for b in bundles:
        ev_ids = tuple(it.id for it in b.items)
        if b.subject_type == "process":
            tid = f"live-proc-{b.subject_id}"
            lbl = f"Process {b.subject_id}"
            model.add_tile(
                WorldTile(
                    tile_id=tid,
                    gx=gx_proc % width,
                    gy=gy_proc % (height // 2),
                    material="grass",
                    classification="review_first",
                    label=lbl,
                    evidence_ids=ev_ids,
                    subject_type="process",
                    subject_id=b.subject_id,
                    revealed=False,
                )
            )
            gx_proc += 1
            if gx_proc >= width - 1:
                gx_proc = 1
                gy_proc += 1

    for s in storage_items:
        p_str = s.get("path", "")
        cat_str = s.get("category", "clearly_safe")
        mat = material_for_classification(cat_str)
        cid = s.get("id", f"stor-{gx_stor}-{gy_stor}")
        sz = s.get("size", 0)
        tid = f"live-stor-{cid}"
        model.add_tile(
            WorldTile(
                tile_id=tid,
                gx=gx_stor % width,
                gy=(height // 2) + (gy_stor % (height // 2)),
                material=mat,
                classification=cat_str
                if cat_str
                in ("clearly_safe", "review_first", "do_not_touch", "unavailable")
                else "clearly_safe",
                label=p_str or f"Storage {cid}",
                size_bytes=int(sz) if isinstance(sz, int | float) else 0,
                evidence_ids=(cid,) if cid else (),
                subject_type="storage",
                subject_id=p_str,
                revealed=False,
            )
        )
        gx_stor += 1
        if gx_stor >= width - 1:
            gx_stor = 5
            gy_stor += 1

    return model
