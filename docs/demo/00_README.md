# Moonlight demo-video production package

Everything here is grounded in `main` @ `2556a4d` plus checks run on the maintainer's machine on 2026-11-05
(01:00–01:15 Asia/Dhaka). Unverified items are marked ⚠️ UNVERIFIED wherever they appear.

## Files, in order of use

| File | Use it for |
|---|---|
| `08_timeline_to_deadline.md` | **Start here**: hour-by-hour plan to 07:30 Dhaka |
| `01_repo_analysis.md` | What exists, claim→evidence table, risks, the "wow" moment |
| `02_strategy.md` | Track, rubric map, Stage 1 risk, option ranking, bonus odds |
| `03_script.md` | The 18-beat, 2:56 script + **swap-in plan** (clips 7 and 13) |
| `04_recording_runbook.md` | Exact commands per clip, capture settings, ffmpeg, fallbacks, dry-run checklist |
| `05_flow_prompts.md` | Flow prompts (clips 1, 2, 18 only) and edit specs for the real clips |
| `06_voiceover_captions.md` | VO lines, `.srt` captions, TTS, music/SFX |
| `07_submission_pack.md` | Paste-ready submission text, Meta-usage statement, checklists, X + Discord posts |
| `fixtures/*.bundle.json` | Demo inputs: the `bundle` field extracted verbatim from `fixtures/scenarios/process/proc_svchost_in_user_temp.json` and `fixtures/scenarios/injection/inject_process_name_safe_override.json` (synthetic; the folder name keeps them on the CLI's fixture path) |

## The next ~6.5 hours on one page

**Deadline: 9:00 PM EST Wed Nov 4 = 08:00 Dhaka Thu Nov 5. Submit by 07:30.**

1. **01:15–01:45: unblock.** Merge the UI launcher branch (`moonlight ui` is not on `main` yet). Run `pytest -q`. Check the Ollama key with `moonlight provider-check --provider ollama-cloud`. Start a Baseten sign-up in parallel.
2. **01:45–02:15: dry run** every command in `04_recording_runbook.md` §2. Fill `HACKATHON.md`'s "maintainer to fill" cells.
3. **02:15–03:15: record** masters A–E. **03:00 decision:** if a Muse Spark Open (Baseten) or Meta key works, re-record clips 7 and 13 per the swap-in plan. Otherwise drop it.
4. **03:15–05:15: edit**: cut, 3 Flow clips, VO, captions.
5. **05:15–06:15: export, QC muted, upload** as Unlisted, check in incognito.
6. **06:15–07:30: submit** (`07_submission_pack.md`). Then X post + Discord.

**Honesty guardrails:** the AI provider on screen is the Ollama Cloud placeholder (or a labeled fallback). The Meta
provider is "implemented + contract-tested (simulated)". Recall 8/15 is shown, not hidden.

**Verified during prep:** offline eval PASSED (numbers match `results/RESULTS.md`), 12/12 simulated Meta tests,
disk-growth attribution end to end with the harmless decoy, policy refusals (PID 4 kill, System32),
Recycle-Bin preview, minimizer redaction, ungrounded-report → rules-only fallback.
**Not verified:** Ollama Cloud report (no key in this shell), `moonlight ui` on `main` (not merged), any live Meta call (never run).
