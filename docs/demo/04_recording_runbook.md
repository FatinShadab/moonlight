# 04 · Recording runbook

Everything marked ✅ was run on this machine during prep (2026-11-05, Asia/Dhaka) and the output shape is real.
⚠️ UNVERIFIED steps need your key, or the merged UI, before you rely on them.

## 0. Preconditions (do these first, about 20 min)

1. **Merge the UI launcher.** Commit the work on `feat/ui-runner-and-judge-docs` (`src/moonlight/cli.py` `ui` subcommand, `src/moonlight/ui/__main__.py`, `src/moonlight/ui/main.py`, `tests/test_ui_cli.py`), open a PR, run CI and merge. Then `git switch main && git pull`. If you can't merge in time, **cut clips 3, 14 and 17's UI shots** and use the terminal-only fallbacks below.
2. Activate the env and re-check:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   pip install -e .            # only if `moonlight --help` fails
   pytest -q                   # say "600+ tests" in captions only if this passes
   ```
3. Ollama Cloud key (placeholder provider), set off-camera in a window you never record:
   ```powershell
   $env:OLLAMA_API_KEY = '<paste>'
   moonlight provider-check --provider ollama-cloud
   ```
   Expect `Provider : ollama-cloud`, `Status : OK…`, `Model : gemma4:31b`. ⚠️ UNVERIFIED (no key here; without one it prints `Status : FAILED - Ollama API key is required…` ✅).
   **If you have no key:** the clip 7/8 take will show `Reasoning failed … OLLAMA_API_KEY … returning rules-only report` ✅. That is honest, but it isn't an AI report. In that case re-caption clip 7 as "No key → automatic rules-only fallback (by design)", drop clip 8's facts-vs-hypotheses VO, and say "fallback report".
4. Demo working folder (keeps your username out of every path):
   ```powershell
   New-Item -ItemType Directory -Force D:\mldemo | Out-Null
   ```
   It needs ≥ 1 GiB free on D: for the decoy.

## 1. Capture settings

- OBS Studio: 1920×1080 canvas and output, **60 fps** (the final export is 30 fps; 60 gives smooth speed-ramps). Recording format MKV (remux to MP4 after), encoder NVENC/x264 CQP/CRF **18**. Record **one master take per section** (A–E below), not per clip.
- Windows: display scaling 100% or 125%. Turn on Focus Assist / Do Not Disturb, hide desktop icons, auto-hide the taskbar.
- Terminal: Windows Terminal, **Cascadia Mono 20 pt**, a dark scheme (Campbell or One Half Dark), window about 110×30, padding 16. Use a short prompt:
  ```powershell
  function prompt { "moonlight> " }
  Clear-Host
  ```
- UI: `moonlight ui` maximised at 1920×1080 (the app's dark moonlit theme is the default).
- Cursor: turn on cursor highlight (PowerToys Mouse Highlighter, or the OBS cursor plugin).
- **Never on screen:** `$env:*_KEY` lines, `.env` contents, `C:\Users\<you>` paths, the `user` field of raw bundles, `confirmation_token` values (blur them), browser tabs or bookmarks, email.
- Pre-type long commands in a scratch file and paste them. Typing on camera is slow, and you will speed-ramp anyway.

## 2. Per-section commands (copy-paste)

### Section A: UI world view (clip 3, plus later clips 14 and 17)
```powershell
moonlight ui --mode replay
```
- Clip 3: World view nav item → wait for the lantern to settle → 8 s slow mouse drift. ⚠️ UNVERIFIED on main until merged. Reference render: `docs/images/ui_world_view.png`.
- Clip 14: Settings → "AI Reasoning & Model Providers" → Meta configuration (leave the key field empty or masked) → Reports view. **Do not type a key on camera.**
- Clip 17: World view again, lantern on a flagged node → Reports view.
- Fallback if the UI won't launch: a slow Ken-Burns pan over `docs/images/ui_world_view.png` and `docs/images/ui_settings.png`, captioned "UI screenshot (offscreen render from scripts/generate_ui_screenshots.py)". Never pass a screenshot off as live use.

### Section B: Disk growth caught live (clips 4–5) ✅ verified end to end
Use two terminal panes side by side (Windows Terminal: Alt+Shift+D).

Pane L:
```powershell
python fixtures/disk_link_decoy.py --parent D:\mldemo --mode hold --seconds 40
```
It prints the temp folder and the decoy **PID** (2nd line). It writes ~1 MiB every 0.4 s, removes itself on exit, and has no network access or persistence.

Pane R (replace 12345 with the printed PID):
```powershell
$P = 12345
# PowerShell 5.1 '>' writes UTF-16; use Out-File utf8 (the CLI reads utf-8-sig)
moonlight disk-snapshot --root D:\mldemo --pid $P | Out-File -Encoding utf8 D:\before.json
Start-Sleep 8
moonlight disk-snapshot --root D:\mldemo --pid $P | Out-File -Encoding utf8 D:\after.json
$L = moonlight disk-link --before D:\before.json --after D:\after.json | Out-String | ConvertFrom-Json
$L.findings | Select-Object confidence, reason, growth_bytes, bytes_per_second, evidence_ids | Format-List
$L | Select-Object mode, scope, basis | Format-List
```
(In the prep run, Git Bash redirection was used. The PowerShell `Out-File` variant is ⚠️ UNVERIFIED, so dry-run it once.)
Expected on screen (real values from the prep run): `confidence : high`, `reason : path_and_write_correlation`, `growth_bytes : 25165824`, `bytes_per_second : ~2672630`, 7 `ev-…` IDs; then `mode rules_only`, `scope selected_processes_only`, `basis heuristic_correlation_not_proof`.
Snapshots go to `D:\` (outside the scan root). Delete `D:\before.json` and `D:\after.json` afterwards. Don't show the raw full JSON: the process bundle contains your `user` and venv path.
Time: about 25 s of real time → speed-ramp the `Start-Sleep 8` to 4×.

### Section C: Process, privacy, AI report, injection (clips 6–9)
```powershell
moonlight minimize --input docs/demo/fixtures/proc_svchost_in_user_temp.bundle.json
```
✅ Shows `payload_json` with `untrusted_evidence`, `VOLUME_1/users/USER_1/appdata/local/temp/svchost.exe`, `HASH_1`, and a `redaction_log` (USER, VOLUME replacements). Zoom on those.

```powershell
moonlight investigate --provider ollama-cloud --input docs/demo/fixtures/proc_svchost_in_user_temp.bundle.json
```
⚠️ UNVERIFIED (needs your key). Expected shape: a JSON report with `summary`, `risk_tier`, `confidence`, `observed_facts[{text, evidence_ids}]`, `hypotheses[{text, evidence_ids, likelihood}]`, `benign_explanations`, `missing_evidence`, `recommended_actions[{action_id, …}]`, `uncertainty_notes`, `metadata{provider, model, …}`.
**Check before using the take:** `metadata.provider` must be the Ollama provider (not `rules_only_fallback`), and there must be no "Reasoning failed" line. If it falls back, retake once; if it falls back again, use the fallback caption from §0.3.
The evidence is a synthetic fixture, so no `--allow-real-evidence` is needed (the path contains `fixtures`).

```powershell
moonlight investigate --provider ollama-cloud --input docs/demo/fixtures/inject_process_name_safe_override.bundle.json
```
Rules path ✅: `risk_tier: review` with "Unsigned user-location executable". The model path is ⚠️ UNVERIFIED. If the model says anything other than review, **do not use the take** and use the mock/rules version (`--provider mock`, which yields `review` ✅ via rules fallback); caption it "rules tier".

### Section D: Peak (clips 10–12) ✅ all verified
```powershell
moonlight investigate --provider mock --input docs/demo/fixtures/proc_svchost_in_user_temp.bundle.json 2>&1 | Select-Object -First 3
```
✅ Line 1: `Reasoning failed after repair (Repair retry failed grounding: Observed fact cites unknown evidence ID 'ev-process-executable_path-fcee12d7' not in bundle.); returning rules-only report`. The report then says `"provider": "rules_only_fallback"`.
Truthful caption: "Replayed (mock) AI report cites evidence not in this bundle → rejected → rules-only". This is the mock provider, so say so.

```powershell
moonlight policy-validate --action-type terminate_process --target-pid 4 --audit-log D:\audit.jsonl
moonlight policy-validate --action-type move_to_recycle_bin --target-path C:/Windows/System32 --audit-log D:\audit.jsonl
```
✅ `"allowed": false` with "Action 'terminate_process' is strictly prohibited…" and "…inside protected directory 'C:\Windows'". Exit code 1.

```powershell
[IO.File]::WriteAllBytes('D:\mldemo\old-build-cache.bin', (New-Object byte[] 5242880))
moonlight policy-preview --action-type move_to_recycle_bin --target-path D:/mldemo/old-build-cache.bin --audit-log D:\audit.jsonl
```
✅ `allowed: true`, `5,242,880 bytes`, `storage_category: review_first` (unrecognized_location), `requires_confirmation: true`, `requires_extra_confirmation: true`, `confirmation_token: cfm_…` ← **blur it**. **Do not run `policy-execute`.** Afterwards: `Remove-Item D:\mldemo\old-build-cache.bin, D:\audit.jsonl`.

Optional bonus shot for clip 10: `moonlight eval --output-dir D:\mleval 2>&1 | Select-String "not permitted by policy allowlist"` ✅ shows "Recommended action 'terminate_process' is not permitted by policy allowlist".

### Section E: Meta tooling, eval, history (clips 13, 15, 16)
```powershell
code .env.example      # or: Get-Content .env.example | Select-Object -First 32
```
Show Option A (Meta Model API) and Option B (Baseten Muse Spark Open). The file contains no secrets, only empty placeholders.
```powershell
code -g src/moonlight/reasoning/provider.py:896   # response_format → json_schema → Report.model_json_schema()
pytest tests/test_meta_simulated_endpoint.py -q
```
✅ `12 passed` (about 17 s, speed-ramp). Caption: SIMULATED endpoint.
```powershell
moonlight eval --output-dir D:\mleval
```
✅ It ends with `Offline evaluation complete: PASSED`. stderr shows the 5 fallback reasons (good B-roll). Then open `D:\mleval\RESULTS.md` (rendered in a VS Code preview) and highlight the KPI table: recall 8/15 in amber.
Use `--output-dir` so the tracked `results/` isn't modified on camera.
```powershell
git log --oneline --graph --date=short --format="%h %ad %s" main | Select-Object -First 40
```
Alternative: the GitHub "Pull requests → Closed" page for FatinShadab/moonlight (logged-out/incognito view, so no avatar menu).

## 3. Real vs Flow

| Clip | Source |
|---|---|
| 1 | FLOW (stylised hook, no real brand UI) |
| 2 | FLOW title + REAL pipeline overlay made in the editor (text boxes) |
| 3–17 | **REAL screen recordings only** |
| 18 | FLOW outro card (static text added in the editor so the URL is exact) |

## 4. ffmpeg

Assume the masters are `A.mp4` … `E.mp4`. Mark the in-points while reviewing; the example cut points below assume you've noted them.

(a) Cut 10 s clips with exact cut points (re-encode for frame accuracy):
```bash
# clip_04 from master B starting at 00:00:03.200
ffmpeg -ss 00:00:03.200 -i B.mp4 -t 10 -c:v libx264 -crf 18 -preset medium -r 30 -c:a aac -b:a 160k clip_04.mp4
# Batch: cuts.txt lines like "B.mp4 00:00:03.200 04"
while read src t n; do ffmpeg -y -ss "$t" -i "$src" -t 10 -c:v libx264 -crf 18 -r 30 -an "clip_$n.mp4"; done < cuts.txt
# Even 10 s segmentation of one master (rough split):
ffmpeg -i C.mp4 -c:v libx264 -crf 18 -r 30 -an -f segment -segment_time 10 -force_key_frames "expr:gte(t,n_forced*10)" -reset_timestamps 1 C_%02d.mp4
# Speed-ramp a wait (4x) inside a clip:
ffmpeg -i raw.mp4 -filter:v "setpts=0.25*PTS" -an fast.mp4
```
(b) Concatenate the final clips (all must share codec, resolution and fps):
```bash
printf "file 'clip_%02d.mp4'\n" $(seq 1 18) > list.txt
ffmpeg -f concat -safe 0 -i list.txt -c copy video_noaudio.mp4
ffmpeg -i video_noaudio.mp4 -i voiceover_mix.wav -c:v copy -c:a aac -b:a 192k -shortest moonlight_av.mp4
```
(c) Captions: burn in (best for X and for judges watching muted), or attach as a soft track:
```bash
ffmpeg -i moonlight_av.mp4 -vf "subtitles=captions.srt:force_style='FontName=Segoe UI,FontSize=22,PrimaryColour=&H00FFFFFF,OutlineColour=&H80000000,BorderStyle=3,Outline=1,Shadow=0,MarginV=40'" -c:a copy moonlight_burned.mp4
ffmpeg -i moonlight_av.mp4 -i captions.srt -c copy -c:s mov_text -metadata:s:s:0 language=eng moonlight_softsubs.mp4
```
(d) Final export, ≤ 3:00, 1080p, about 60–120 MB:
```bash
ffmpeg -i moonlight_burned.mp4 -t 179.5 -c:v libx264 -preset slow -crf 20 -maxrate 6M -bufsize 12M -pix_fmt yuv420p -r 30 -c:a aac -b:a 160k -movflags +faststart moonlight_final_1080p.mp4
ffprobe -v error -show_entries format=duration,size -of default=nw=1 moonlight_final_1080p.mp4   # duration must be < 180
```
X's 30–60 s cut: `ffmpeg -ss 90 -i moonlight_final_1080p.mp4 -t 45 -c:v libx264 -crf 21 -c:a aac moonlight_x_45s.mp4` (peak + policy + eval).

## 5. Fallbacks during recording

| Failure | Do this |
|---|---|
| Ollama key missing or 5xx | Use the fallback take and caption it as fallback (honest). Don't fake a report. |
| Decoy refuses (< 1 GiB free) | Use `--parent` on another drive with space, e.g. `E:\mldemo`, and the same root in the snapshots |
| `disk-link` shows no finding | Re-run with the snapshots further apart (`Start-Sleep 12`) while the decoy is still writing (it runs 40 s) |
| UI won't start | Screenshot fallback (§2A), labeled as a screenshot |
| eval FAILS | Show the committed `results/RESULTS.md` (generated 2026-11-03) and caption it "committed results, 2026-11-03" |

## 6. Dry-run checklist (do it once, end to end, before the real takes)

- [ ] On `main`, UI launcher merged, `moonlight --help` lists `ui`
- [ ] `pytest -q` green (note the count)
- [ ] `provider-check --provider ollama-cloud` OK (or fallback captions chosen)
- [ ] D:\mldemo exists, ≥ 1 GiB free; no leftover `before/after.json`
- [ ] Prompt is `moonlight> `; no key lines or usernames in scrollback (`Clear-Host`)
- [ ] Notifications off, taskbar hidden, cursor highlight on
- [ ] Sections A–E recorded; each in-point noted in `cuts.txt`
- [ ] Every token, key and username blurred; watch the final export muted to check the captions
- [ ] Final duration < 3:00
