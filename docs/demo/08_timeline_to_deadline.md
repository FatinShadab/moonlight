# 08 · Timeline to deadline

## Deadline conversion (verified)

- US daylight saving time 2026 ends **Sunday Nov 1, 2026**, so Wed Nov 4 is **EST = UTC−5**.
- 9:00 PM EST Nov 4 = **02:00 UTC Thu Nov 5** = **08:00 Asia/Dhaka (UTC+6) Thu Nov 5**.
- This package was finished at about 01:15 Dhaka, leaving **≈ 6 h 45 m**. **Submit by 07:30 Dhaka** (30-minute buffer). Hard stop at 08:00.
- Rule: **no new features.** Only merging the already-written UI launcher and filling in docs.

## Work-back schedule (Asia/Dhaka)

| Dhaka | ET (Nov 4) | Block | Output | Owner notes |
|---|---|---|---|---|
| 01:15–01:45 | 14:15–14:45 | **Fix blockers** | UI launcher PR merged; `pytest -q` green; Ollama key checked (`provider-check`) | In parallel: start the Baseten (or Fireworks/Modal) sign-up and credit request |
| 01:45–02:15 | 14:45–15:15 | **Seed + dry run** | `D:\mldemo` ready; every command in `04_recording_runbook.md` §2 run once, off-camera | Fill `HACKATHON.md` "maintainer to fill" cells now (5 min) |
| 02:15–03:15 | 15:15–16:15 | **Record** | Masters A–E (UI, disk, process/AI, peak, Meta/eval/history) | Note in-points in `cuts.txt` while recording |
| **03:00** | 16:00 | **Swap-in decision** | If a Baseten/Meta key works: run `provider-check --provider meta` and the clip 7 command; re-record clips 7 and 13 (15 min) | If not working by 03:15, **drop it** for good |
| 03:15–04:00 | 16:15–17:00 | **Split / edit** | 17 real clips cut to 10 s (ffmpeg §4a), speed ramps, callouts, blurs | |
| 03:15–03:45 | (parallel) | **Flow clips** | Clips 1, 2-bg, 18-bg (`05_flow_prompts.md`); at most 2 generations each | If Flow stalls, use a plain dark title card |
| 04:00–04:45 | 17:00–17:45 | **Voiceover + assemble** | VO recorded or TTS (`06_voiceover_captions.md`), music ducked, 18 clips concatenated (§4b) | |
| 04:45–05:15 | 17:45–18:15 | **Captions** | `captions.srt` timed; burned in (§4c) | |
| 05:15–05:45 | 18:15–18:45 | **Export + QC** | `moonlight_final_1080p.mp4` < 3:00 (§4d); watch once with sound, once muted | Scrub at 0.5× for keys, tokens, usernames |
| 05:45–06:15 | 18:45–19:15 | **Upload** | YouTube Unlisted; incognito playback check; link added to the README; repo public, CI green | |
| 06:15–07:15 | 19:15–20:15 | **Submit** | Cerebral Valley form: title, descriptions, Meta section, repo, video, all team members (`07_submission_pack.md`) | Use the swap block only if the live call really happened |
| **07:30** | **20:30** | **SUBMITTED** | Confirmation screenshot | Buffer: 30 min |
| 07:30–08:00 | 20:30–21:00 | **X post + Discord** | 45 s cut posted; link pasted into the platform's viral field; Discord post | Posting can continue after the deadline; engagement counts to Nov 8 EOD |

## Minimum viable video (if at 04:30 Dhaka you are not assembled)

1. Drop all Flow clips. Use a plain dark title card with "Moonlight" and the 1-line hook for clips 1, 2 and 18.
2. Drop clips 3, 14 and 17 if the UI was a problem; extend clips 5, 11 and 15 instead.
3. Use the built-in Windows TTS (`06_voiceover_captions.md`), one WAV per clip.
4. Burn captions straight from `captions.srt`; no manual callouts except the red/green boxes on clips 10–12.
5. A 2:00–2:30 video is fine. A complete, honest, working demo beats a polished partial one.
6. Non-negotiable even in MVV: clip 5 (disk answer), 10–12 (peak), 13 (Meta status, labeled), 15 (eval incl. 8/15), 16 (built-during-hackathon proof).

## Rules for tonight

- Submit with a 30-minute buffer: by 07:30 Dhaka / 20:30 ET.
- Do not start new features or "quick fixes" to product code after 02:15.
- Never claim a live Meta call that you didn't make and capture on video.
