# Moonlight: evidence-first PC investigator

Moonlight is a planned local-first Windows desktop app for investigating unfamiliar processes and disk usage. It combines read-only collection, deterministic rules, minimized evidence sent to Meta's Model API, local policy checks, and a review UI. It is an investigator and explainer, not an antivirus product.

## Status

This repository is being built during the Meta Global AI Developer Hackathon, Build for Your World track. The package contains tooling, the [shared evidence model](docs/evidence.md), [read-only process collection](docs/collectors.md), and a [storage investigator](docs/storage.md) with local size history and conservative classification rules. AI calls, action policy execution and the UI are not implemented yet. See the [product requirements](Moonlight%20Product%20Requirements%20Document.md) and [hackathon log](HACKATHON.md).

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

## Collect a Windows process

```powershell
moonlight collect --pid 4242
# Or: .\.venv\Scripts\python -m moonlight collect --pid 4242
```

The command prints a validated EvidenceBundle as JSON, including explicit reasons
for unavailable fields. If the PID's creation time cannot be read, it prints a
structured collection error and exits with status 1. A bundle with unavailable
items still exits with status 0. No administrator elevation, rules or AI calls
are performed. See [collector behavior and limits](docs/collectors.md).

## Investigate selected storage roots

```powershell
moonlight storage --root "D:\Downloads" --root "D:\Projects" --snapshots "C:\MoonlightData\sizes.sqlite3"
```

The snapshot file's parent directory must already exist and be outside the
selected roots. Scanned files are never modified; the explicit SQLite database
stores local folder-size history. JSON output contains P1 evidence bundles,
growth observations and `clearly_safe`, `review_first`, `do_not_touch` labels.
Protection always overrides cache labels. No cleanup action is implemented.
See [storage behavior, limits and benchmark](docs/storage.md).

## Link fast growth to a process

`moonlight disk-snapshot --root PATH --pid N` captures selected folder sizes,
process write counters and available open-file paths as JSON. Compare two saved
captures with `moonlight disk-link --before before.json --after after.json`.
Results include high/medium/low/unattributed confidence, evidence citations and
optional supplied P3 security findings joined by PID plus creation time. This
is a rules-only correlation, limited to selected processes; uncertain matches
remain unattributed. See the [capture workflow and P3 contract](docs/process-disk-link.md)
and [limitations](docs/limitations.md).

## Preview minimized model evidence

`moonlight minimize --input evidence.json` accepts a bundle, an array of bundles,
or a report containing bundles. It prints the exact eligible `payload_json` and
a separate local redaction log. Usernames, hosts, private path segments, IPs and
free-text arguments become coherent placeholders; long commands are marked as
truncated. Unknown fields and file contents are withheld. This command performs
no transmission. See [privacy, selection and failure behavior](docs/privacy.md).

## Safety baseline

Collectors are read-only. Any future file action must pass local policy, show a dry-run preview, and require explicit confirmation before moving an eligible file to the Recycle Bin. System and personal-document folders are blocked. See [AGENTS.md](AGENTS.md) for the full rules.
