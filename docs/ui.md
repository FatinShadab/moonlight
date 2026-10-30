# Moonlight Review Interface & UI Architecture

Moonlight features a modern, accessible desktop review interface built with **PySide6 (Qt for Python)**. Designed specifically for security analysts and camera-ready demos, it emphasizes visual clarity, immutable auditability, and safety guardrails.

---

## Architecture Overview

```mermaid
flowchart TD
    subgraph UI ["Desktop Review Interface (PySide6)"]
        TopBar["Top Control Bar (Replay / Live Mode, Badges)"]
        NavRail["Left Navigation Rail"]
        CentralStack["Central Views (Processes, Storage, Reports, Wire Payload, Policy Log, World)"]
        RightPanel["Right Side Panel (Activity Timeline & Approvals)"]
        ConsentDialog["ActionPreviewDialog (In-Memory Token, Consent)"]
    end

    subgraph WorldView ["Isometric Device World View"]
        WorldModel["WorldModel (Pure-Python Coordinates)"]
        Renderer["IsometricWorldView (QGraphicsView 2:1)"]
        Atlas["TileAtlas (Spritesheet / Procedural Fallback)"]
        Lantern["LanternMarkerItem (Focus Tracking)"]
    end

    subgraph Telemetry ["Event Bus (moonlight.ui.events)"]
        EventBus["Qt-Signal EventBus"]
        Events["InvestigationEvents (Chronological Stream)"]
    end

    subgraph Engine ["Core Safety & Reasoning Engine"]
        Collectors["Read-Only Collectors"]
        Rules["Deterministic Rules"]
        Minimizer["Privacy Minimizer"]
        Orchestrator["Reasoning Orchestrator (Mock / Cloud / Meta)"]
        Policy["Policy Layer (Gated Execution & Audit Log)"]
    end

    TopBar --> NavRail
    NavRail --> CentralStack
    CentralStack <--> RightPanel
    CentralStack --> ConsentDialog
    ConsentDialog --> Policy
    Engine --> EventBus
    EventBus --> Events
    Events --> RightPanel
    Events --> WorldView
    WorldView --> CentralStack
```

---

## Visual Design System & Theme

Moonlight's visual presentation is driven by a bespoke design token system in [`moonlight.ui.theme`](../src/moonlight/ui/theme.py), producing a unified Qt Style Sheet (QSS):

1. **Moonlit Dark Palette**: Deep midnight blue-black canvas (`#0b0f19`), layered card surfaces (`#131c2e`, `#182338`), subtle structural dividers (`#1e293b`), and a cool sky accent (`#38bdf8`).
2. **8px Spacing Grid**: Rigorous geometric scaling (`xs: 4px`, `sm: 8px`, `md: 16px`, `lg: 24px`, `xl: 32px`).
3. **Windows System Font Stack**: Native type rendering with fallback support (`Segoe UI`, `-apple-system`, `system-ui`, `sans-serif`).
4. **Status Chips with Text + Color**: Risk tiers and confidence scores always present explicit textual labels alongside their semantic color badge (e.g. `[LOW RISK]`, `[REVIEW REQUIRED]`, `[HIGH RISK]`, `[INCONCLUSIVE]`, `[CONFIDENCE: 92%]`), never relying on color alone.
5. **High-Contrast Focus Outlines**: Full keyboard accessibility with visible `:focus` states throughout all buttons, tables, text areas, and navigation pills.
6. **Hand-Drawn Vector Icons**: All icons are custom, clean SVGs authored in [`src/moonlight/ui/icons/`](../src/moonlight/ui/icons/) under the project's MIT License (see [`ASSETS.md`](../ASSETS.md)).

---

## Screen Gallery

### 1. Investigation Review & Activity Timeline
![Investigation Overview](images/ui_overview.png)
*Figure 1: Full desktop review window displaying the Executive Summary, grounded observed facts with clickable citations, investigative hypotheses with likelihood ratings, top bar mode controls, and the real-time activity timeline.*

### 2. Action Consent & Dry-Run Preview Dialog
![Consent Dialog](images/ui_consent_dialog.png)
*Figure 2: Dry-run preview consent dialog displaying target path, size, modified time, destination, and the in-memory confirmation token required for policy execution.*

### 3. Sent to the Model Wire Inspection
![Sent to the Model](images/ui_sent_to_model.png)
*Figure 3: Privacy inspection tab displaying the exact serialized wire payload JSON alongside the local redaction audit log.*

### 4. Isometric Device World View
![Isometric World View](images/ui_world_view.png)
*Figure 4: Isometric world map visualizing endpoint process and storage districts, illuminated discovered nodes, and a floating lantern marker tracking investigation focus.*

---

## Layout and Panels

The interface is structured into four primary layout regions:

### 1. Left Navigation Rail
Provides one-click switching between investigation views:
- **Processes**: Complete inventory of observed processes, digital signatures, hashes, command lines, and rule findings.
- **Storage**: Evaluated storage paths, size totals, and policy safety categories (`clearly_safe`, `review_first`, `do_not_touch`).
- **Reports**: Executive summary, risk tier, confidence, separated facts vs hypotheses, benign explanations, missing evidence, uncertainty notes, and recommended actions.
- **Sent to the model**: The exact minimized payload JSON eligible for model use and the local redaction log.
- **Policy log**: Append-only local audit log recording every policy verification, preview, and execution decision.
- **World Map**: Visual isometric device world map reflecting endpoint components and investigation progression.

### 2. Top Control Bar
- **Replay / Live Mode Toggle**: Replay mode (default) evaluates reproducible labeled scenarios; Live mode runs read-only local machine collection.
- **Scenario Selector**: Dropdown to inspect any of the 103 synthetic scenarios from `fixtures/scenarios/`.
- **Provider Selector**: Selects between `mock`, `ollama-cloud`, and `meta`.
- **Provider Transparency Badge**: Automatically renders the `'cloud placeholder model'` badge whenever the provider is not `'meta'`.
- **Investigate Button**: Launches background worker thread.

### 3. Central Content Area
A high-performance `QStackedWidget` hosting the active investigation panel, with automatic view transitions when citations are clicked.

### 4. Right Side Panel
- **Activity Tab**: Real-time chronological timeline rendering `InvestigationEvent` telemetry emitted across the pipeline.
- **Approvals Tab**: Interactive queue of pending action recommendations with policy status chips and dry-run preview triggers.

---

## Isometric World View Visualization

The optional **Isometric World View** (`src/moonlight/ui/world_view.py`) visualizes investigations as a lit-up device map. It strictly **reflects** real events and data, never adds powers, and leaves policy gating unchanged:

1. **2:1 Isometric Projection**:
   - Screen coordinates: `sx = (gx - gy) * 16`, `sy = (gx + gy) * 8`.
   - Depth sorting: `zValue = gx + gy` ensures front tiles naturally overlap rear tiles.
   - Integer pixel scaling (1x, 2x, 3x) with smoothing disabled (`Antialiasing=False`, `SmoothPixmapTransform=False`) preserves crisp retro pixel art.
2. **Material Semantic Mapping**:
   - `clearly_safe` -> **Dirt** (`#ad7757`): Verified harmless processes and safe user cache directories.
   - `review_first` -> **Grass** (`#75a743`): Ambiguous items, download directories, or processes requiring analyst confirmation.
   - `do_not_touch` -> **Stone / Rock** (`#819796`): Protected system roots (`System32`, `Program Files`) and critical Windows system processes.
   - `unavailable / error` -> **Water / Fog** (`#73bed3` / `#1e293b`): Missing evidence, unreachable endpoints, or unexplored peripheral boundaries.
3. **Event-Driven Illumination**:
   - Unrevealed tiles start in deep blue-gray darkness (`#0b0f19` tint).
   - As `InvestigationEvent`s arrive across the EventBus, matching nodes are illuminated and lit up.
   - A floating **lantern marker** moves between tiles to track the investigator's active telemetry focus.
4. **Reduce Motion Setting**:
   - An accessible checkbox toggle allows users to disable animation.
   - When enabled, the lantern snaps immediately to target coordinates with zero travel duration.
5. **Asset Graceful Degradation**:
   - Uses `assets/world/spritesheet.png` and `atlas.json` (CC0 public domain Kenney tiles).
   - If sprite assets are absent or in headless CI clones, it automatically falls back to procedural shaded diamond blocks.
6. **Interactive Selection & Excerpt Card**:
   - Clicking any isometric tile selects it, reveals grounded details (size, category, domain), and displays its report excerpt.
   - Clicking the excerpt's citation button automatically jumps to the matching row in the Processes or Storage tables.

---

## Safety Guarantees & Consent Flow

In strict compliance with `AGENTS.md` rules:

1. **Read-Only Collectors**: Collectors never terminate processes, delete files, or modify the system registry.
2. **In-Memory Confirmation Tokens**: The cryptographic `confirmation_token` generated by `preview_action` is stored strictly in dialog memory. It is never included in prompt templates, never transmitted to external APIs, and never parsed from model output.
3. **No Direct OS Invocations**: UI code never calls `os.system`, `subprocess`, or file deletion primitives. `open_file_location` strictly invokes the policy layer's argument-safe launcher (`launch_file_location`), and `move_to_recycle_bin` strictly routes through `send2trash` via `execute_action`.
4. **Extra Confirmation for Review-First Paths**: Items classified as `review_first` require explicitly checking a secondary acknowledgment checkbox before the `Confirm & Execute` button is enabled.
5. **Air-Gapped Default in Live Mode**: Live mode defaults to the offline mock provider so zero endpoint data leaves the workstation. Switching to an external provider requires explicit confirmation via `LiveProviderWarningDialog`.
6. **Thread Safety**: All long-running operations execute inside background `QThread` workers, ensuring the UI remains responsive and free from lockups.

---

## Headless Testing and Offscreen Verification

All UI components, dialogs, and the isometric renderer are verified via automated headless pytest suites using Qt's `offscreen` platform plugin (`os.environ["QT_QPA_PLATFORM"] = "offscreen"`):

```powershell
# Run all UI component, dialog, and isometric world view tests:
.venv\Scripts\pytest.exe tests/test_ui_world.py tests/test_ui_window.py tests/test_ui_dialogs.py tests/test_ui_badge.py

# Regenerate offscreen screenshots:
.venv\Scripts\python.exe scripts/generate_ui_screenshots.py
```
