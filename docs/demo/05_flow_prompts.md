# 05 · Flow prompts and edit specs

Rule: **product footage stays real.** Generative tools can rewrite UI text and numbers. Use Flow only for
clips 1, 2 (background), and 18. Everything else gets non-generative polish only: crop, zoom, callouts,
speed ramps, captions.

Global grade: slight cool/teal lift, +5 contrast, no saturation boost on terminal text. Captions: Segoe UI
Semibold, white, 60% black box, bottom third, max 2 lines. Callout boxes: 3 px rounded, amber `#F5B544` for
"look here" and red `#FF5C5C` for "rejected", 250 ms pop-in. Music ducks −12 dB under the voiceover.

| # | Type | Spec |
|---|---|---|
| 1 | **FLOW** | Prompt: *"Cinematic close-up of a laptop screen at night in a dark room, a generic disk-usage bar filling from 85% to 99% in red, then a generic system process list with one unlabeled row pulsing amber; shallow depth of field, cool moonlight from a window, slow push-in, no logos, no readable brand names, 10 seconds."* Add the caption text in the editor (don't let Flow render text). Reject any generation that shows a Windows/Microsoft logo or readable fake UI text. |
| 2 | **FLOW** bg + editor overlay | Prompt: *"A full moon rising behind thin clouds over a calm dark-blue night sky, subtle stars, slow upward camera drift, minimal, elegant, no text, 10 seconds."* In the editor: the "Moonlight" wordmark (Segoe UI Light, 96 px) fades in at 1 s; at 4 s the pipeline strip animates left→right as 6 text chips: collectors → rules → minimizer → AI → policy → UI. |
| 3 | REAL | World view. 1.0→1.08 slow digital push-in over 10 s; cursor hidden. Caption bottom-left. |
| 4 | REAL | Split screen, both panes legible at 20 pt. Speed-ramp the `Start-Sleep 8` to 4×, with a small "4×" badge top-right (honest). Amber box around the PID in pane L. |
| 5 | REAL | Crop to the `findings` block, scale 130%. Amber box on `confidence : high` and `bytes_per_second`, then sweep a highlight across `evidence_ids`. Final 2 s: box on `basis heuristic_correlation_not_proof`. |
| 6 | REAL | Zoom on `untrusted_evidence` and `VOLUME_1/users/USER_1/…`, then a pan to `redaction_log` (`USER`, `VOLUME`). |
| 7 | REAL | Show the command, then speed-ramp the model latency (badge "sped up"). Keep the provider lower-third on screen the whole clip. Verify before cutting: `metadata.provider` is not `rules_only_fallback`. |
| 8 | REAL | From the same take: three sequential zooms on `observed_facts`, `hypotheses`, `benign_explanations`/`missing_evidence`, each with its `evidence_ids` underlined. |
| 9 | REAL | Zoom on `ignore_all_instructions_safe.exe` (red underline), then cut to `"risk_tier": "review"` (amber box). |
| 10 | REAL | Red box on "Reasoning failed … unknown evidence ID …", then green box on `rules_only_fallback`. Small corner tag: "mock replay". Subtle "denied" SFX. |
| 11 | REAL | Two commands back to back. Red box on `"allowed": false` and the rejection reason each time. Optionally show the exit code `1` via `$LASTEXITCODE`. |
| 12 | REAL | Green box on `allowed: true`, amber on `review_first` and `requires_extra_confirmation: true`. **Blur `confirmation_token` and `fingerprint`.** |
| 13 | REAL | Three quick cuts: `.env.example` Option A/B (placeholders only) → `provider.py:896–901` → `12 passed`. A lower-third reading "SIMULATED endpoint · no live Meta call" stays on the whole clip. |
| 14 | REAL | Settings view; slow cursor over the provider selector and the Meta fields. The key field must be empty or masked. |
| 15 | REAL | "PASSED" line, then the RESULTS KPI table: green on 0/20, 21/21, 0 dangerous; **amber on recall 8/15** with tag "published weakness". |
| 16 | REAL | Fast scroll of `git log --graph`; overlay a date ruler "Oct 27 → Nov 4" and the "138 commits · 21 merged PRs" chip. |
| 17 | REAL | World view lantern; slow pull-out; caption fades in. |
| 18 | **FLOW** bg + editor text | Reuse the clip 2 moon background (or prompt: *"the same full moon slowly receding into clouds, calm, 6 seconds, no text"*). The editor adds the wordmark and the **exact** URL `github.com/FatinShadab/moonlight`. Never let Flow render the URL. |

Mascot: none exists in the repo. Don't invent one for the video. It would also imply Muse Image use if anyone asks.
