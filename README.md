# Moonlight: evidence-first PC investigator

Moonlight is a planned local-first Windows desktop app for investigating unfamiliar processes and disk usage. It combines read-only collection, deterministic rules, minimized evidence sent to Meta's Model API, local policy checks, and a review UI. It is an investigator and explainer, not an antivirus product.

## Status

This repository is being built during the Meta Global AI Developer Hackathon, Build for Your World track. The package currently contains the project skeleton and tooling; the investigator and UI are not implemented yet. See the [product requirements](Moonlight%20Product%20Requirements%20Document.md) and [hackathon log](HACKATHON.md).

## Development on Windows

Use Python 3.11 or newer:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\ruff check .
.\.venv\Scripts\ruff format --check .
.\.venv\Scripts\mypy
.\.venv\Scripts\pytest -q
```

Copy `.env.example` to `.env` when the model integration is implemented, then set `META_API_KEY` locally. Never commit `.env` or a real key. The local rules pipeline is intended to remain usable when the API is unavailable.

To enable commit hooks after installing the development dependencies, run `.\.venv\Scripts\pre-commit install`.

## Safety baseline

Collectors will be read-only. Any future file action must pass local policy, show a dry-run preview, and require explicit confirmation before moving an eligible file to the Recycle Bin. System and personal-document folders are blocked. See [AGENTS.md](AGENTS.md) for the full rules.
