# Hackathon build log

Moonlight is being built for the Meta Global AI Developer Hackathon, Build for Your World track. This log distinguishes implemented behavior from planned work.

## Timezone and hackathon schedule

- **Project commit timezone offset**: `+06:00` (UTC+6, Bangladesh Standard Time, observed from `git log --date=iso`).
- **Eastern Time equivalent**: `UTC-4` (EDT, 10 hours behind project local time) through November 1, 2026, transitioning to `UTC-5` (EST, 11 hours behind) upon DST change.
- **Kickoff**: October 26, 2026 at 12:00 PM ET (October 26, 2026 at 10:00 PM UTC+6).
- **Building period**: October 27 – November 4, 2026.

## Agents and tools

| Phase | Description / Scope | Agent or tool |
| --- | --- | --- |
| P0 | Repository bootstrap and foundation (PR #1) | maintainer to fill |
| P1 | Evidence schema and stable IDs (PR #2) | maintainer to fill |
| P2 | Process collectors (PR #3) | maintainer to fill |
| P3 | Storage investigator (PR #4) | maintainer to fill |
| P4 | Process-to-disk link (PR #5) | maintainer to fill |
| P5 | Privacy minimizer (PR #6) | maintainer to fill |
| P6 | Rule engine and immutable evidence (PRs #7, #8) | maintainer to fill |
| P7a | Process-to-disk rule findings & live decoy check (PRs #9, #10) | maintainer to fill |
| P7b | Policy layer and consent flow (PR #12) | maintainer to fill |
| P9 | Offline reasoning scaffold & mock provider (PR #13) | maintainer to fill |

## History notes

- **P5 commits**: The P5 commits (`47ee92d` through `544e225`) landed directly on `main` under different hashes than PR #5 lists.
- **Tags and lineage**: The old tag `m1b-investigators` points to `ad8e7b5`, which is not on `main`. The new tag `m1b-investigators-main` marks the PR #9 merge commit `0af40a6`. Existing history was not rewritten.
- **Model provider**: The Ollama cloud model, when used, is a temporary development placeholder; the submitted system uses the Meta Model API.

## 2026-10-27 — Repository bootstrap

- Added the installable Python 3.11+ package skeleton and pinned runtime/development dependencies.
- Added Windows CI for installation, Ruff, mypy, and pytest, plus local Ruff and Gitleaks commit hooks.
- Added contribution templates, a sample environment file, documentation and results placeholders, and a package import smoke test.
- No collection, AI reasoning, policy execution, file action, or UI behavior is implemented yet.

## Evidence schema

- Added validated process and storage evidence bundles with deterministic citation IDs, duplicate rejection, timezone-aware timestamps, and explicit unavailable/error reasons.
- Exported the JSON Schema and documented the contract in `docs/evidence.md`.
- Collectors, rules, AI calls, policy behavior, and UI remain unimplemented.

## 2026-10-27 — Process metadata collector

- Added read-only psutil collection for executable path, ancestor names/paths, command line, start time, user, connections, and I/O counters.
- Added PID-plus-creation-time identities and guards against PID reuse.
- Added mocked success, denied, exited, timeout, and OS-error coverage with independent unavailable/error evidence for each field.
- If creation time cannot be established, return a structured collection error.
- Rules, AI calls, policy execution, and UI remain unimplemented.

## 2026-10-27 — Executable hash collector

- Added streamed SHA-256 with configurable size/chunk limits and a bounded read-only helper.
- Added unavailable evidence for oversized, changed, missing, denied and timed-out files.
- Added mocked OS boundary tests and an inert-byte helper integration check.

## 2026-10-27 — Authenticode collector

- Added bounded, shell-free Windows Authenticode queries with four explicit signature states.
- Added a bounded cache keyed by SHA-256, modified time and path, plus file-change guards.
- Added mocked valid, invalid, unsigned, unavailable, denied, missing, malformed and timeout coverage.

## 2026-10-27 — Collection CLI

- Added `moonlight collect --pid N` and `python -m moonlight collect --pid N`.
- The JSON bundle contains all nine observations, preserving individual failures; missing process identity returns a structured error and status 1.
- Added assembly/CLI tests and a Windows CI smoke check against the runner's own PowerShell process.
- Collection remains read-only and has no rule evaluation or AI calls.

## 2026-10-27 — Selected-root storage scanner

- Added read-only folder sizes, modification age, extension-based type and size-first duplicate candidates using the P1 evidence schema.
- Added structured root/relative path references, no-follow Windows guards, explicit unavailable evidence and bounded duplicate hashing.
- Added temporary-tree tests for size totals, duplicates, hard links, reparse points, permissions, limits and evidence identity.

## 2026-10-27 — Storage size snapshots

- Added transactional local SQLite snapshots outside selected roots, with path-free size history and average growth between comparable scans.
- Added unavailable growth for first/incomplete scans, changed root scope, invalid time intervals and database failures.
- Added SQLite persistence, rollback, shrinkage and destination-containment tests, including a hard-linked destination that cannot modify a scanned file.

## 2026-10-27 — Storage classification

- Added location-based clearly_safe, review_first and do_not_touch labels with evidence references; no action paths are implemented.
- Added redirected known-folder discovery and conservative protection for documents, media, system paths and their containing folders.
- Added override-prevention tests: do_not_touch takes priority even when the same path is allowlisted as a cache.

## 2026-10-27 — Storage CLI and benchmark

- Added `moonlight storage --root PATH --snapshots FILE`, with explicit non-overlapping roots, JSON evidence/classifications and no cleanup actions.
- Added end-to-end temporary-tree/SQLite CLI tests and a reproducible benchmark script.
- Local Ruff, mypy and all 177 tests pass. A Windows 11 / Python 3.12.14 sample tree of 1,008 files and 41 directories took 9.619, 9.627 and 10.087 seconds (median 9.627); eight files were hashed after size grouping.
- Timings include helper startup, scanning, SQLite and classification, exclude tree generation/JSON, and do not clear the filesystem cache. Raw timing and reproduction are documented in results and storage docs.

## 2026-10-27 — Process-to-disk attribution

- Added opt-in, identity-guarded open-file path collection and JSON snapshots of explicit storage roots/PIDs.
- Added deterministic comparison of folder growth, process write-byte deltas and path links with high/medium/low/unattributed confidence and versioned endpoint evidence citations.
- Ambiguous writers, missing baselines, PID reuse, reset counters, incomplete folder totals and stale samples abstain; weak coverage reduces confidence.
- Added the approved P3 findings adapter: exact process identity and validated AFTER citations permit a combined storage/security report. P3 rules themselves are not implemented here.
- Added synthetic confidence/boundary, uncertainty, citation, collector and CLI coverage. Documented capture commands, heuristic thresholds and limitations in `docs/process-disk-link.md` and `docs/limitations.md`.
- This feature is local and rules-only, with no AI dependency or action implementation. Confidence is correlation among sampled processes, not a calibrated probability or proof of a writer.
- Validation: Ruff lint/format checks, strict mypy and all 254 tests pass; confidence scenarios use synthetic snapshots.

## 2026-10-27 — Privacy minimizer

- Added allowlisted, local evidence projection with stable per-payload placeholders for usernames, hosts, private path segments, subjects, roots, addresses, hashes and free-text command arguments.
- Added bounded command previews with explicit truncation markers and exact JSON/UTF-8 payload bytes separate from the local redaction log. No originals or reversible mappings are logged.
- Unknown fields and embedded contents, raw timestamps, source/error strings and nonessential identifiers are withheld. Explicit evidence selection and item budgets limit payload scope.
- Added a final normalized identity leak guard that withholds the entire payload on residual names or unavoidable schema/citation collisions; local rules results remain independent.
- Added Hypothesis-generated identifier/content privacy invariants, per-kind and CLI tests, and documented the preview contract and limits in `docs/privacy.md`.
- No model request format, API call, transmission, action or UI implementation was added.
- Validation: Ruff lint/format checks, strict mypy and all 301 tests pass, including 650 generated privacy cases.

## 2026-10-27 — Windows collection CI timeout regression

- Diagnosed the previous main-branch failure: Authenticode correctly returned unavailable signature evidence after its five-second timeout, but CI incorrectly required an observed signature.
- Replaced the inline assertion with a tested smoke validator that accepts explicit documented signature unavailability while requiring the complete kind set, requested process, observed executable/hash and consistent signature state; unexpected errors still fail.
- Removed raw live evidence from CI output and added regression coverage for timeout and malformed/error results. Production collector limits and fallback behavior are unchanged.
- Validation: Ruff lint/format, strict mypy and all 319 tests pass; the live PowerShell collection smoke pipeline also passes outside sandbox process-query restrictions.

## 2026-10-27 — Bounded immutable evidence

- Deep-froze nested evidence dictionaries and lists after validation while retaining JSON serialization and stable value-independent citation IDs.
- Limited observed values to 65,536 compact UTF-8 JSON bytes. Oversized collector observations become unavailable evidence with the fixed `value_too_large` reason.
- Added mutation, serialized-size boundary, nested JSON, collector fallback and round-trip tests; documented the limit in `docs/evidence.md`.
- Full-suite Hypothesis cases exposed delimiter-only and JSON-escape aliases that were omitted from the existing minimizer leak guard; registered raw aliases, scanned serialized envelopes, and added fail-closed regression tests.

## 2026-10-27 — Local process rules

- Added nine deterministic process rules, including one negative-weight mitigation, with documented rationale and benign alternatives. The rules read immutable evidence only and produce stable citations plus findings compatible with the existing P3 adapter.
- Added configurable YAML 1.2 weights and thresholds, four-tier derivation, explicit missing-evidence reporting, and `moonlight rules --pid N` JSON output. Missing hash, path, signature, parent or command evidence caps high at review; two missing key kinds yield inconclusive.
- Added synthetic positive/negative cases, tier and missing-evidence boundaries, immutable-value and determinism checks, and a generated rule catalog freshness check. No AI or action path is involved.

## 2026-10-27 — Live Windows disk-link decoys

- Added a harmless 60-second fixture with held-open and close-between-writes modes and ran each on Windows using two UTF-8 PowerShell disk snapshots of its temporary folder and exact writer PID.
- Held-open writes yielded `high` correlation; close-between-writes yielded `unattributed` because `open_files` missed the short-lived handle, despite matching write-byte and folder-growth deltas. An initial launcher-PID selection also abstained as expected.
- Recorded evidence IDs, timings, counter limits, and an unimplemented low-capped path-hint option in `docs/limitations.md`. No raw local snapshots were committed.
- Validation: 346 tests, Ruff lint/format, strict mypy, and a separate strict mypy check of the decoy fixture passed.

## 2026-10-27 — Disk-link decoy safety bounds

- Capped the fixture at 128 MiB and 60 seconds by default, with command-line limits for small controlled runs.
- Added a 1 GiB free-space start guard and guaranteed temporary-folder cleanup on normal exit, exceptions, and Ctrl+C.
- Added in-process tests using tiny caps; no default-cap decoy run occurs in pytest or CI.

## 2026-10-27 — P3 findings in disk links

- Process-to-disk comparisons now run local P3 rules on AFTER process evidence, remap citations to versioned AFTER IDs, and join findings to process comparisons and selected writers by exact PID plus creation time.
- The optional supplied-findings adapter remains available. Standard disk snapshots omit hash and signature observations, so only rules supported by their observed evidence can match.
- Added synthetic matching, no-match, PID-reuse, and unrelated-process coverage. No AI call or action path was added.


## 2026-10-27 — Policy layer and consent flow

- Added the deterministic policy layer (`moonlight.policy`) gating all proposed remediation actions with a strict allowlist: `open_file_location`, `copy_hash_to_clipboard`, `move_to_recycle_bin` (dry-run preview and explicit confirmation required), and `mark_reviewed`. Process termination and permanent deletion are strictly prohibited and structurally rejected.
- Protected Windows directories, Program Files, user personal document folders (Documents, Desktop, Pictures, Music, Videos, OneDrive), system volume folders, and critical Windows system processes (`System`, `lsass.exe`, `csrss.exe`, `services.exe`, `smss.exe`, `explorer.exe`, etc.) and system PIDs (0, 4) from being targeted.
- Added strict path safety normalization: rejects path traversal (`..`), UNC / network paths, Windows DOS device paths/names (`\\.\`, `\\?\`, `CON`, `NUL`, `AUX`), and symlink escapes.
- Added mandatory dry-run previews detailing item counts, sizes, and destinations; requires explicit user confirmation before executing `move_to_recycle_bin` via `send2trash` only.
- Added execution re-validation and TOCTOU guards detecting modified files, swapped symlinks, or changed targets between preview and execution.
- Added local append-only JSON lines audit logging (`policy_audit.jsonl`) for every attempted action.
- Exported `ALLOWED_ACTION_IDS` and `ALLOWED_ACTION_TYPES` for report and schema validators.
- Added CLI subcommands: `moonlight policy-validate`, `moonlight policy-preview`, and `moonlight policy-execute`.
- Validation: 454 tests pass across the suite, Ruff lint and format clean, strict mypy passes with 0 errors across 63 files.

## 2026-10-27 — Offline reasoning scaffold & mock provider

- Added the schema-validated AI investigation report model (`moonlight.reasoning.models.Report`) with risk tier derivation, calibrated confidence, observed facts citing evidence, hypotheses with likelihood, benign explanations, missing evidence, allowlisted recommended actions, uncertainty notes, provenance metadata, and visible fallback indicator. Exported the JSON Schema to `docs/report-schema.json`.
- Implemented the `ReportProvider` protocol, `MockProvider` replaying handwritten/cached reports from `fixtures/reports/`, and offline placeholders for `OllamaCloudProvider` and `MetaProvider` raising clear `NotImplementedError` (zero external network API calls).
- Added provider selection by configuration and `PROVIDER` environment variable (`mock | ollama-cloud | meta`).
- Added strict grounding validator (`moonlight.reasoning.grounding`): enforces that every cited ID exists in the evidence bundle, every observed fact cites at least one evidence ID, and every proposed action is on the policy allowlist (`ALLOWED_ACTION_IDS`).
- Added investigation reasoning orchestrator (`moonlight.reasoning.orchestrator`): runs grounding validation, attempts exactly one repair retry through the provider upon validation or provider failure, and falls back to a deterministic rules-only report (`build_rules_fallback_report`) with a visible `is_fallback=True` flag and explanation.
- Added prompt templates (`src/moonlight/reasoning/prompts/`) with untrusted evidence datamarking, explicit directives forbidding the model from executing directives within evidence, and short aliases (`E1`, `E2`) automatically mapped back to stable evidence IDs.
- Added `moonlight investigate` CLI command with mock and offline provider support.
- Validation: 474 tests pass across the suite, Ruff lint and format clean, strict mypy passes with 0 errors across 70 files.


- 2026-10-28: Bound policy execution to preview confirmation tokens, gated recycling via storage classifier, hardened path alias resolution, and unblocked mark_reviewed for process names.

## Planned evaluation

The [PRD](Moonlight%20Product%20Requirements%20Document.md) defines process and storage rule metrics, citation coverage, schema validity, ablations, and robustness scenarios. Results will include the labeled-set size and reproduction method when measurements exist. No performance or safety metric is claimed yet.
