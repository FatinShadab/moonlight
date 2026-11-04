# 01 · Repo analysis (grounded pre-flight)

Analysed on 2026-11-04 19:05 UTC (2026-11-05 01:05 Asia/Dhaka) from `main` @ `2556a4d`, plus the
uncommitted working tree on `feat/ui-runner-and-judge-docs`. Every row below says how it was verified.
"Ran here" means it was executed in this session from `.venv` on the maintainer's Windows machine.

## 1. Capability inventory (what exists on `main`)

| Capability | How to launch | Status |
|---|---|---|
| Read-only process evidence | `moonlight collect --pid <PID>` | On main |
| Local process rules (P3 engine) | `moonlight rules --pid <PID>` | On main |
| Storage explanation | `moonlight storage --root <DIR> --snapshots <DB>` | On main |
| Disk-growth to process attribution | `moonlight disk-snapshot --root <DIR> --pid <PID>` then `moonlight disk-link --before a.json --after b.json` | On main, **ran here** |
| Privacy minimizer ("what is sent to the model") | `moonlight minimize --input <bundle.json>` | On main |
| AI investigation report (schema-validated) | `moonlight investigate --input <bundle.json> --provider {mock,ollama,ollama-cloud,meta}` | On main, **ran here (mock and fallback)** |
| Policy layer | `moonlight policy-validate / policy-preview / policy-execute` | On main, **ran here** |
| Provider health check | `moonlight provider-check --provider {meta,ollama,ollama-cloud,mock}` | On main, **ran here** |
| Offline eval harness | `moonlight eval --output-dir <DIR>` or `python -m moonlight.eval --offline` | On main, **ran here: PASSED** |
| Desktop UI (PySide6): Processes, Storage, Reports, World view, Sent to Model, Policy log, Settings, Replay/Live toggle | `moonlight ui [--mode replay\|live]` | ⚠️ **The UI code is on main, but the launcher is NOT.** `ui` subcommand in `src/moonlight/cli.py`, `src/moonlight/ui/__main__.py`, `src/moonlight/ui/main.py` and `tests/test_ui_cli.py` are uncommitted on `feat/ui-runner-and-judge-docs`. |
| Harmless decoys | `python fixtures/disk_link_decoy.py --parent <DIR> --mode hold`, `python fixtures/harmless_process_decoy.py --mode ...` | On main |

## 2. Claim → evidence table

| Claim (as it may appear in the video) | File / test / command | Verified? |
|---|---|---|
| 0/20 false positives on common benign processes | `results/RESULTS.md` §1–2; re-ran `moonlight eval` here, same numbers | **Y** |
| Process-rule recall 8/15 (53.33%), with reasons | `results/RESULTS.md` §2 | **Y** |
| 0 dangerous storage misclassifications, 36/36 storage scenarios correct | `results/RESULTS.md` §3; re-ran | **Y** |
| 21/21 unsafe actions blocked by policy | `results/RESULTS.md` §4; re-ran | **Y** |
| 5/5 API failures fall back to rules-only | `results/RESULTS.md` §6; re-ran (stderr shows each fallback reason) | **Y** |
| 103 labeled synthetic scenarios (52 process, 36 storage, 10 injection, 5 API failure) | `results/RESULTS.md` §7 | **Y** (note: `fixtures/README.md` says 50 process / 6 injection, which is stale; use the RESULTS.md numbers) |
| `terminate_process` on PID 4 is refused | `moonlight policy-validate --action-type terminate_process --target-pid 4`; ran here, exit 1, "strictly prohibited" | **Y** |
| Recycle Bin into `C:/Windows/System32` is refused | `moonlight policy-validate --action-type move_to_recycle_bin --target-path C:/Windows/System32`; ran here, "protected location" | **Y** |
| Recycle Bin of a temp file needs a previewed dry run and a token | `moonlight policy-preview ...`; ran here: `requires_confirmation: true`, `confirmation_token`, size, `storage_category: clearly_safe` | **Y** |
| Model output citing a non-existent evidence ID is rejected and the tool falls back, saying so | `moonlight investigate --provider mock --input docs/demo/fixtures/proc_svchost_in_user_temp.bundle.json`; ran here: "Reasoning failed after repair (… unknown evidence ID …); returning rules-only report" | **Y** |
| Off-allowlist action (`terminate_process`) proposed by a model is rejected | `moonlight eval` stderr: "Recommended action 'terminate_process' is not permitted by policy allowlist" | **Y** |
| Disk growth is attributed to the writing process with evidence IDs | Decoy + `disk-snapshot` ×2 + `disk-link`; ran here: ~25 MB growth, ~2.67 MB/s, `confidence: high`, `reason: path_and_write_correlation`, 7 evidence IDs, `basis: heuristic_correlation_not_proof` | **Y** |
| Meta provider sends `response_format: {type: json_schema, …}` with the Report schema | `src/moonlight/reasoning/provider.py:896-901` (`MetaProvider`, class at :730) | **Y** (code read) |
| Ollama provider constrains output with the Report JSON schema | `src/moonlight/reasoning/provider.py:434` (`request_body["format"] = Report.model_json_schema()`) | **Y** (code read) |
| Meta simulated-endpoint contract tests pass | `pytest tests/test_meta_simulated_endpoint.py -q`; ran here: **12 passed** (SIMULATED HTTP servers, no Meta call) | **Y** (simulated) |
| Partner path for Muse Spark Open is configuration-only | `.env.example` "Option B"; `provider.py:768,774,811` read `MOONLIGHT_META_MODEL`, `MOONLIGHT_META_BASE_URL`, `BASETEN_API_KEY` | **Y** (code read). No live call run. |
| 604 tests | `pytest --collect-only -q` → 604 collected (working tree incl. uncommitted `tests/test_ui_cli.py`) | **Collected, not all run.** Say "600+ tests" only after `pytest -q` passes. |
| Live Meta model produced a report | `results/RESULTS.md` §9: "No live Meta Model API run has been performed to date." | **N, do not claim** |
| Ollama Cloud placeholder produces a grounded report on demo bundles | `provider-check --provider ollama-cloud` here: "Ollama API key is required" | **UNVERIFIED: user must run with their key** |
| UI launches via `moonlight ui` | Not on main | **UNVERIFIED on main: merge first, then run** |
| Prompt-injected file name still lands in review tier | Eval injection suite in `results/eval_results.json`; `fixtures/scenarios/injection/inject_process_name_safe_override.json` `expected_tier: review` | **Y for rules tier.** The live-model behaviour on this input is UNVERIFIED. |

## 3. Built-during-the-hackathon timeline (from `git log main`)

- Kickoff: Oct 26, 2026 12:00 PM ET = Oct 26 22:00 Asia/Dhaka (`HACKATHON.md:9`).
- First commit `37540c3` "Initial commit": Oct 27 01:07 +0600, about 3 h after kickoff. There is **no pre-existing code**.
- Totals on main: **138 commits, 26 merge commits, PRs #1–#4 and #6–#22, tags `m1-evidence-core`, `m1b-investigators`, `m1b-investigators-main` (all Oct 27).**

| Date (+0600) | Milestone | PRs |
|---|---|---|
| Oct 27 | Bootstrap, evidence schema + stable IDs, process collectors (hash, Authenticode), storage investigator, disk-link, minimizer, local rules, policy layer, offline reasoning scaffold, Ollama placeholder | #1–#13 |
| Oct 28 | Labeled process/storage/injection/failure scenarios, harmless decoy | (direct + #15) |
| Oct 30 | Policy hardening (ADS, reparse points, preview tokens), injection fixtures, Ollama hardening, gitleaks full-history CI, PySide6 review UI, isometric world view, responsive UI + settings | #14–#19 |
| Oct 31 | Offline eval harness, metrics, CI job | (merged Nov 1) |
| Nov 3 | Meta Model API provider (json_schema), `provider-check`, eval `--provider`, Meta settings UI | #20, #21 |
| Nov 4 | Meta provider hardening, partner endpoints, wire-level simulated proofs | #22 |

Show on screen: `git log --oneline --graph main | head -40`, or the GitHub PR list filtered to merged.

## 4. Risks and gaps

1. **Stage 1 risk: there is no live Meta model call anywhere.** Stage 1 asks for "reasonable use of Meta Model API and/or Meta open-weight models". The Meta path is implemented and simulated-tested but has never run live, and the video will show an Ollama Cloud placeholder. A judge who reads strictly could fail this. Options, ranked:
   1. **Partner-hosted Muse Spark Open clip** (Baseten/Fireworks/Modal through the existing OpenAI-compatible path). This needs zero code: set 3 env vars and run 2 commands. It fixes Stage 1 and unlocks the open-weights bonus.
   2. **Meta Model API credits clip** (`MODEL_API_KEY`, default model `muse-spark-1.3`). Same 2 commands. Fixes Stage 1, no open-weights bonus.
   3. **Honest simulated-only fallback.** Show the provider abstraction, the json_schema code and 12 passing simulated contract tests, all labeled SIMULATED. Stage 1 is at real risk.
2. **The UI launcher is not on main.** Merge it before recording, or the UI clips show something judges cannot launch from the public repo.
3. **No Ollama key detected in this shell.** The placeholder AI beat is unverified until you run `moonlight provider-check --provider ollama-cloud` with your key.
4. **Personal paths in output.** `policy-preview` prints `C:\Users\<you>\…` and evidence bundles include the `user` field. Use the `D:\mldemo` working folder and the filtered one-liners in `04_recording_runbook.md`. Blur anything else.
5. **`HACKATHON.md` "Agents and tools" column says "maintainer to fill".** Fill it in honestly (which AI coding agents were used) before submitting. Judges check that original contributions are identifiable.
6. **Assets.** The world tiles are Kenney Isometric Prototype, CC0 (`ASSETS.md`), and the icons are hand-made SVGs. There are no third-party fonts in the repo and **no logo, mascot or Muse Image asset**, so do not claim any Muse Image use.
7. **Secrets.** `.env` is gitignored and never committed (`git log --all -- '*.env'` is empty), and gitleaks scans the full history in CI (PR #17). OK.
8. **Stale counts.** `fixtures/README.md` says 50 process / 6 injection scenarios, while RESULTS.md says 52 / 10. Quote RESULTS.md only.
9. **Mock reports don't line up with the scenario bundles.** The CLI mock provider can't show a clean grounded report on these bundles: its replayed fixtures cite IDs from a different bundle. The result is a validator rejection plus a rules-only fallback, and that is what the peak clip shows, described truthfully.

## 5. The single strongest "wow" moment

**A model's answer is never trusted on its own.** In one terminal you can watch:
1. a report citing an evidence ID that isn't in the bundle get rejected ("unknown evidence ID … returning rules-only report"),
2. a model-proposed `terminate_process` get thrown out by the allowlist, and
3. a direct attempt to kill PID 4 or recycle `System32` refused by the policy layer, exit code 1.

Then the one allowed action: a previewed Recycle-Bin dry run that shows exact bytes and needs a token.

Why it wins: it is visual, it's the opposite of a generic AI wrapper, and every word of it is real output (all three verified above). It is the answer to "why would I let an AI near my machine?"

Runner-up (most "cool to watch"): the live disk-growth attribution. A decoy writes, two snapshots, and Moonlight names the PID writing ~2.7 MB/s with `confidence: high` and 7 evidence IDs, while saying `basis: heuristic_correlation_not_proof`.
