# Moonlight Assets & Attribution

This document records the provenance, origin, and licensing of all visual assets and icons in the Moonlight repository.

---

## 1. UI Vector Icons (`src/moonlight/ui/icons/`)

All icons used by the Moonlight desktop review interface are custom hand-crafted SVG vector graphics created specifically for this project. They carry zero external third-party dependencies or icon-pack licensing requirements.

| File | Description | Origin | License |
| --- | --- | --- | --- |
| `processes.svg` | CPU processor chip icon for process inventory navigation | Hand-drawn SVG for Moonlight | MIT License |
| `storage.svg` | Hard drive disk cylinder icon for storage view navigation | Hand-drawn SVG for Moonlight | MIT License |
| `reports.svg` | Investigation report document icon for report review navigation | Hand-drawn SVG for Moonlight | MIT License |
| `world.svg` | Layered isometric cubes icon for world view navigation | Hand-drawn SVG for Moonlight | MIT License |
| `model.svg` | Neural / sparkle model icon for 'Sent to the model' navigation | Hand-drawn SVG for Moonlight | MIT License |
| `shield.svg` | Security guardrail shield icon for policy log navigation | Hand-drawn SVG for Moonlight | MIT License |
| `activity.svg` | Timeline pulse / activity monitor icon for investigation telemetry | Hand-drawn SVG for Moonlight | MIT License |
| `approval.svg` | Star approval badge icon for consent queue tab | Hand-drawn SVG for Moonlight | MIT License |
| `check.svg` | Status checkmark icon for verified/allowed items | Hand-drawn SVG for Moonlight | MIT License |
| `warning.svg` | Warning triangle icon for review alerts and provider warnings | Hand-drawn SVG for Moonlight | MIT License |
| `refresh.svg` | Circular reload arrows icon for re-running investigations | Hand-drawn SVG for Moonlight | MIT License |
| `chevron_right.svg` | Right navigation arrow icon for tables and breadcrumbs | Hand-drawn SVG for Moonlight | MIT License |

---

## 2. Documentation Images (`docs/images/`)

Screenshots illustrating the Moonlight review interface, consent dialogs, and telemetry.

| File | Description | Origin | License |
| --- | --- | --- | --- |
| `ui_overview.png` | Overview of the primary review window, navigation rail, and activity timeline | Generated via `scripts/generate_ui_screenshots.py` using PySide6 offscreen `widget.grab()` | MIT License |
| `ui_consent_dialog.png` | Dry-run preview consent dialog displaying target path, size, and in-memory confirmation token | Generated via `scripts/generate_ui_screenshots.py` using PySide6 offscreen `widget.grab()` | MIT License |
| `ui_sent_to_model.png` | Verifiable model wire payload and local redaction log preview | Generated via `scripts/generate_ui_screenshots.py` using PySide6 offscreen `widget.grab()` | MIT License |
| `ui_world_view.png` | Isometric device map visualizing process and storage districts with illuminated nodes and floating lantern focus | Generated via `scripts/generate_ui_screenshots.py` using PySide6 offscreen `widget.grab()` | MIT License |

---

## 3. Isometric World View Assets (`assets/world/`)

Spritesheet and tile rect atlas powering the optional isometric device map renderer.

| Directory / File | Description | Origin | License |
| --- | --- | --- | --- |
| `assets/world/spritesheet.png` | 352x352 32-pixel isometric prototype tile sheet (dirt, grass, stone, water, fog) | Kenney Game Assets (Isometric Prototype) | CC0 1.0 Universal (Public Domain) |
| `assets/world/atlas.json` | JSON atlas defining tile coordinates and material mappings for isometric rendering | Hand-crafted atlas for Moonlight | MIT License |
| `assets/isometric tileset/` | Raw isometric prototype tileset and separated images | Kenney Game Assets (Isometric Prototype) | CC0 1.0 Universal (Public Domain) |
