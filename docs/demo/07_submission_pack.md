# 07 · Submission pack (ready to paste)

Fill in the `[ ]` items before pasting. Every number here traces to `results/RESULTS.md`, `git log main`, or a command in
`01_repo_analysis.md`.

## Title and tagline

**Moonlight**: *What is eating my disk, and what is this process? Evidence-grounded answers from an AI that is never trusted to act alone.*

## 150-word description

Moonlight is a local-first Windows investigator for the two questions every PC user eventually asks: what is eating my disk, and what is this process? Read-only collectors gather process, file and disk-growth evidence, and every item gets a stable evidence ID. A deterministic rules engine scores it, and a privacy minimizer redacts usernames, volumes and hashes. Only then does a language model write a schema-validated report that separates observed facts from hypotheses, with every claim citing evidence IDs. Uncited or off-allowlist output is rejected, and Moonlight falls back to local rules and says why. A policy layer the model cannot bypass refuses process kills and system paths. The only action it allows is a previewed, consented move to the Recycle Bin. We measured it on 103 labeled synthetic scenarios: 0/20 false positives, 21/21 unsafe actions blocked, and a published recall of 8/15.

## 400-word description

Every Windows user has seen it: the disk is suddenly full, or Task Manager lists a process with a familiar name in an unfamiliar place. Existing tools give you a name and a number, not an explanation. Asking a chatbot means pasting private data into a box and trusting whatever comes back, including advice to kill or delete things.

Moonlight answers those questions locally, with evidence. The pipeline is: collectors → rule engine → minimizer → model reasoning → policy layer → desktop UI.

- **Collectors are read-only.** They take process metadata, hashes, Authenticode status, storage scans, and before/after disk snapshots that attribute folder growth to the process writing it. Each item gets a stable evidence ID.
- **A deterministic rule engine** scores processes and classifies storage as clearly-safe, review-first or do-not-touch. System and personal folders can never be "safe".
- **A privacy minimizer** replaces usernames, volumes and hashes with placeholders and sends evidence only inside an `untrusted_evidence` block, so a file named "ignore all instructions" stays data.
- **The model** must return a JSON-schema-constrained report: observed facts, hypotheses, benign explanations, missing evidence and recommended actions, each citing evidence IDs. A grounding validator rejects unknown IDs and off-allowlist actions. After one repair attempt it falls back to rules-only and states the reason.
- **The policy layer** sits outside the model. It refuses terminate-process, registry edits, permanent delete, protected and system paths, traversal and UNC tricks. The single allowed file action is Move to Recycle Bin, after a dry-run preview showing exact bytes, plus a confirmation token, plus extra confirmation for unknown locations.
- **A PySide6 desktop UI** shows processes, storage, reports, exactly what was sent to the model, a policy log, and an isometric "world view" of the machine.

We measure rather than claim. The offline eval covers 103 labeled synthetic scenarios: 0/20 false positives on common benign software, 0 dangerous storage misclassifications, 21/21 unsafe actions blocked, and 5/5 API failures falling back gracefully. Process-rule recall is 8/15 (53%). We publish that, with the reasons, because a triage tool that hides its blind spots is worse than one that shows them.

Moonlight is not antivirus and makes no detection guarantees. It is an explainer that keeps the human in charge.

## What I built during the hackathon

All code in the repository was written during the hackathon. The first commit (`37540c3`) is dated Oct 27, 2026 01:07 +0600, about 3 hours after the Oct 26 12:00 PM ET kickoff. The last feature merge is PR #22 (Nov 5 00:40 +0600 / Nov 4 ET). `main` has 138 commits and 21 merged PRs (#1–#22; #5's commits landed directly), with a dated build log in `HACKATHON.md`:
- Oct 27: evidence schema and IDs, process/storage collectors, disk-growth attribution, minimizer, rules, policy layer, reasoning scaffold
- Oct 28–30: 103 labeled scenarios incl. prompt injection, policy hardening, gitleaks, desktop UI, isometric world view
- Oct 31: eval harness
- Nov 3–4: Meta provider, provider-check, Settings UI, partner endpoints, simulated contract tests

The world-view tiles are Kenney's CC0 Isometric Prototype set (`ASSETS.md`). Everything else is original. AI coding agents used: [fill in honestly, matching HACKATHON.md].

## How Meta's models are used (exact status)

**Implemented**
- `MetaProvider` (`src/moonlight/reasoning/provider.py:730`) targets the Meta Model API (`https://api.meta.ai/v1`, default model `muse-spark-1.3`, configurable via `MOONLIGHT_META_MODEL`).
- Structured output via `response_format: {"type": "json_schema", "json_schema": {… "schema": Report.model_json_schema()}}` (`provider.py:896–901`). The model must return Moonlight's investigation-report schema, which the grounding validator and policy allowlist then check.
- An OpenAI-compatible **partner-endpoint mode** for the open-weight **Muse Spark Open** (`MOONLIGHT_META_BASE_URL=https://inference.baseten.co/v1`, `MOONLIGHT_META_MODEL=meta-models/muse-spark-open-1026`, `BASETEN_API_KEY`), configuration only.
- Provider abstraction: `investigate --provider {mock, ollama, ollama-cloud, meta}`, a UI Settings page for Meta configuration, a `moonlight provider-check` health command, and `python -m moonlight.eval --provider meta` for opt-in live evaluation.

**Tested**
- `tests/test_meta_simulated_endpoint.py`: 12 tests pass against **simulated** local HTTP servers covering request shape, json_schema output, error mapping (401/403/404/429/500/timeouts) and partner endpoints.
- Orchestrator fallback is tested for timeouts, malformed JSON, schema mismatch, hallucinated citations and off-allowlist actions (5/5).

**Not run live**
- As of submission, **no live call to the Meta Model API or to a partner-hosted Muse Spark Open has been made** (`results/RESULTS.md` §9). AI output in the demo comes from an Ollama Cloud development placeholder and is labeled as such on screen.

> **SWAP BLOCK: replace "Not run live" if you complete the swap-in:**
> "Live: the demo's investigation report (0:00–0:00) was produced by Muse Spark Open (`meta-models/muse-spark-open-1026`) served by Baseten, through the same schema, validator and policy layer. Run on [date/time ET]." Also add the live row to `results/RESULTS.md` §9 only if you actually ran `python -m moonlight.eval --provider meta`.

## Tech stack

Python ≥ 3.11 (developed on 3.12), Pydantic 2 (evidence and report schemas), psutil (read-only process data), httpx (providers), send2trash (Recycle Bin only), PySide6 (desktop UI), SQLite (storage snapshots), pytest + hypothesis, ruff, mypy, pre-commit, GitHub Actions on Windows, gitleaks.

## Challenges

- Attributing disk growth to a process without admin drivers: correlating before/after folder sizes with process I/O counters and open handles, and labelling it "correlation, not proof".
- Treating file names and command lines as hostile input (prompt injection) end to end.
- Making the policy layer robust to path tricks: aliases, `..` traversal, UNC, alternate data streams, reparse points.
- Keeping the product fully useful without the AI, with explicit fallbacks.
- Honest evaluation: publishing 53% recall instead of tuning the labels.

## What's next

A live Muse Spark Open evaluation on the 52 process scenarios; improving recall (lookalike distance-2, combined weak signals) without raising false positives; signed installer; per-folder trend charts in the world view.

## Public-repo checklist

- [ ] UI launcher branch merged; `main` is the default branch
- [ ] Repo visibility: Public (Settings → General → Danger zone)
- [ ] README top: one-line pitch, the video link, quickstart (`pip install -e .`, `moonlight ui`, `moonlight eval`)
- [ ] LICENSE (MIT) present ✅; `ASSETS.md` lists Kenney CC0 ✅
- [ ] `.env` not tracked ✅; no keys in history (gitleaks CI ✅); `.env.example` has empty placeholders only ✅
- [ ] `HACKATHON.md` "maintainer to fill" cells completed
- [ ] `docs/demo/` committed only if you want it public (your choice)
- [ ] CI green on main

## Video-link checklist

- [ ] Uploaded to YouTube as **Unlisted** (or Public), not Private; or Loom/Drive with "anyone with the link"
- [ ] Opened in an incognito window while logged out: plays, 1080p available, captions visible
- [ ] Duration < 3:00 (`ffprobe` check)
- [ ] No keys, tokens or usernames visible (scrub through at 0.5×)
- [ ] Link pasted into the README and the submission form; all team members listed on the form

## X post (Most Viral)

Attach `moonlight_x_45s.mp4` (the 1:30–2:15 peak), with captions burned in.

**Post:**
> Your disk is full. A process called svchost is running from your Temp folder.
>
> I built Moonlight in 9 days: a local Windows investigator where the AI must cite evidence for every claim, and a policy layer refuses anything dangerous.
>
> Watch it reject its own model ↓ #MetaHackathon

**Thread:**
1. How it works: read-only collectors → rules → privacy minimizer → schema-validated AI report → policy layer the model can't bypass.
2. The AI can't kill a process, touch System32, or delete anything. The only action: Move to Recycle Bin after a dry-run preview and your confirmation.
3. Measured on 103 labeled scenarios: 0/20 false positives, 21/21 unsafe actions blocked. Recall 8/15, published on purpose.
4. Open source (MIT): github.com/FatinShadab/moonlight · full 3-min demo: [video link]

Tag the official hackathon/Meta developer accounts **only after checking their exact handles** on the hackathon page. Use the hashtag the organisers specify (`#MetaHackathon` above is a placeholder: [confirm]).
Best time: right after submitting (≈ 07:30–08:00 Dhaka = 20:30–21:00 ET Nov 4, US evening). Repost or quote at about 12:00 ET Nov 5. Engagement counts until Nov 8 EOD.
Submit the post URL in the Cerebral Valley platform's Most Viral field: [confirm where the form puts it].

## Discord post (Community Vote)

> 🌙 **Moonlight**: what's eating your disk, and what is this process?
> A local-first Windows investigator: read-only evidence → schema-validated AI report (every claim cites evidence) → a policy layer the AI can't bypass. Only allowed action: Recycle Bin, after a dry run and your OK.
> 0/20 false positives · 21/21 unsafe actions blocked · recall 8/15 (published).
> 3-min demo: [video] · Repo: github.com/FatinShadab/moonlight
> If it's useful to you, a community vote means a lot 🙏
