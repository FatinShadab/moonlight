# Hackathon build log

Moonlight is being built for the Meta Global AI Developer Hackathon, Build for Your World track. This log distinguishes implemented behavior from planned work.

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

## Planned evaluation

The [PRD](Moonlight%20Product%20Requirements%20Document.md) defines process and storage rule metrics, citation coverage, schema validity, ablations, and robustness scenarios. Results will include the labeled-set size and reproduction method when measurements exist. No performance or safety metric is claimed yet.
