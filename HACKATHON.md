# Hackathon build log

Moonlight is being built for the Meta Global AI Developer Hackathon, Build for Your World track. This log distinguishes implemented behavior from planned work.

## 2026-10-27 — Repository bootstrap

- Added the installable Python 3.11+ package skeleton and pinned runtime/development dependencies.
- Added Windows CI for installation, Ruff, mypy, and pytest, plus local Ruff and Gitleaks commit hooks.
- Added contribution templates, a sample environment file, documentation and results placeholders, and a package import smoke test.
- No collection, AI reasoning, policy execution, file action, or UI behavior is implemented yet.

## Planned evaluation

The [PRD](Moonlight%20Product%20Requirements%20Document.md) defines process and storage rule metrics, citation coverage, schema validity, ablations, and robustness scenarios. Results will include the labeled-set size and reproduction method when measurements exist. No performance or safety metric is claimed yet.
