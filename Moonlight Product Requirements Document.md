# Moonlight: Product Requirements Document

*A local-first Windows investigator for processes and disk space. Meta Global AI Developer Hackathon, Build for Your World track. Version 1.0*

## 1. Overview

Moonlight is a local-first Windows desktop app that helps non-expert users understand what their computer is doing. It answers two everyday questions with evidence and explainable AI: **"Is this process safe?"** and **"What is eating my disk?"** Like moonlight, it shows things clearly without glare: it reports what is known, what is only suspected, and what is still in the dark.

Moonlight is **not** an antivirus engine. It is an investigator and explainer. It never takes destructive action on its own, and the user stays in control of every change.

## 2. Problem

- Task Manager and Windows Storage settings show *what exists*, not *whether it matters*.
- An unfamiliar process may be harmless or suspicious; a folder that suddenly grows by tens of gigabytes may be a game update or a runaway process.
- Non-experts either ignore these signals or panic. Existing tools either dump raw data or give black-box verdicts with no explanation.

## 3. Target Users

| User | Need |
| --- | --- |
| Everyday Windows users and families | Plain-language answers about unfamiliar processes and full disks |
| Small-business owners | Quick, careful triage without a security team |
| New IT helpers | A guided, evidence-based way to investigate |

## 4. Goals and Non-Goals

**Goals**

1. A working, end-to-end Windows prototype: collect evidence, reason with Meta's model, review, act with consent.
2. Transparent, testable local rules that produce structured evidence.
3. Grounded AI reports: every claim traceable to evidence.
4. Measured results, not claims: published false-positive and false-negative rates and AI-grounding metrics.
5. Minimal data sharing and full user control.

**Non-goals (for the hackathon)**

- Replacing antivirus or EDR, real-time blocking, or malware detection claims.
- Autonomous remediation, permanent file deletion, or registry/system changes.
- Semantic file organization and knowledge graphs (roadmap only).

## 5. Core Features (MVP)

**F1. Process Investigator** On-demand investigation of a selected process: executable path, parent chain, command line, network activity, SHA-256 hash, and digital-signature status. Transparent heuristics (for example, unsigned binary running from a temp folder) produce evidence items. No single indicator is treated as proof.

**F2. Storage Investigator (read-only)** Folder sizes, growth rate, file age and type, and duplicate hashes, grouped into categories: temp files, caches, old installers, large forgotten downloads, duplicates, and "do not touch."

**F3. Process-to-Disk Link** When a folder grows quickly, Moonlight attributes the growth to a likely responsible process. A process writing gigabytes into a temp folder is reasoned about as both a storage and a security question.

**F4. AI Investigation Report** A schema-validated report from Meta's Model API with: observed facts, hypotheses, uncertainty, missing evidence, legitimate alternative explanations, a risk tier with confidence, and constrained recommended next steps. Every factual claim cites evidence IDs.

**F5. Policy Layer and Consent Flow** Every proposed action is validated locally before it is shown. Space-freeing actions are previewed (dry run), limited to the Recycle Bin, and blocked for system and personal-document folders. Nothing runs without explicit user confirmation.

**F6. Review Interface** A desktop UI showing the evidence list, the AI report with citations, exactly what data was sent to the model, and the action preview.

## 6. Architecture

1. **Collectors** (Python, local): process telemetry, hashing, signature checks, storage scanning.
2. **Rule engine** (local, deterministic): produces structured evidence items, each with a unique ID and a severity or relevance weight.
3. **Minimizer** (local): redacts usernames, hostnames, private paths, and internal IPs; sends only what the model needs and never file contents.
4. **Reasoning layer** (Meta Model API): interprets minimized evidence and returns a JSON report validated against a strict schema.
5. **Policy layer** (local): allowlist-based action validation, protected-path and protected-process lists, and Recycle-Bin-only operations.
6. **UI**: review, preview, and confirm.

The local pipeline works without the AI. If the API fails or returns invalid output, Moonlight falls back to rules-only results and says so clearly.

## 7. AI Behavior Requirements

- Separate **observed facts** from **hypotheses**; never present a hypothesis as a fact.
- Cite evidence IDs for each claim; uncited factual claims are flagged by an automated check.
- State uncertainty and list missing evidence.
- Always consider benign explanations before escalating.
- Treat all evidence as **untrusted data**. Process names, command lines, and file names are attacker-controlled, so they are clearly delimited and the model is instructed never to follow instructions found inside them.
- Recommend only actions from the allowed action set.

## 8. Safety and Privacy Requirements

- Local-first: collection and rules run on the device.
- Data minimization with a visible "what was sent" panel.
- No autonomous termination of processes or deletion of files.
- Hard blocks on system directories and user document folders.
- Reversible actions only (Recycle Bin), always previewed first.
- Asymmetric caution: a wrongly suggested deletion is treated as far worse than a missed cleanup.

## 9. Evaluation Plan and Success Metrics

| Area | Method | Target |
| --- | --- | --- |
| Process rules | Labeled benign and suspicious scenarios (safe simulated fixtures, no real malware) | Report precision, recall, false-positive and false-negative rates |
| Storage rules | Labeled safe-to-clear, review-first, and do-not-touch cases | Zero dangerous misclassifications into "safe to clear" on the test set |
| AI grounding | Automated evidence-ID citation check plus manual review | Report groundedness rate; aim for near-complete citation coverage |
| Schema validity | Count of valid reports across runs | Report validity rate |
| Ablation | Rules only vs. AI only vs. rules plus AI | Show the value added by each layer |
| Robustness | API failure, incomplete evidence, prompt injection, unsafe action proposals | Graceful fallback; unsafe actions rejected by the policy layer |

The labeled set will be small, and Moonlight will say so. Methods and results will be reproducible from the repository.

## 10. Demo Plan (3 minutes)

1. **Hook (15s):** Every PC is full of things you can't explain. Moonlight shows what's there, with evidence.
2. **Benign-but-scary (45s):** An unsigned open-source tool is investigated and correctly de-escalated, with alternative explanations.
3. **Suspicious (60s):** A simulated process that mimics suspicious traits is escalated with cited evidence, including the process-to-disk link.
4. **Safety (30s):** The policy layer rejects an unsafe proposed action; the "what was sent" panel is shown.
5. **Numbers (30s):** Evaluation results and the ablation chart.

## 11. Hackathon Alignment

- **Track:** Build for Your World.
- **Meta tooling:** Meta Model API (Muse Spark series) for schema-validated reasoning; Muse Code for development.
- **Stretch goals, claimed only if built:** an agentic loop where the model requests additional whitelisted evidence; screenshot input via multimodal capability; a Muse Spark Open backend on a partner platform for the open-weights bonus.
- **Rules:** Public repository; a clear "built during the hackathon" section in the README; safe test fixtures only.

## 12. Timeline (Oct 27 – Nov 4, submission 9:00 PM ET)

| Days | Deliverable |
| --- | --- |
| 1–2 | Collectors, hashing, signature checks, evidence schema with IDs |
| 3–4 | Rules, Meta API integration, report schema validation, policy layer |
| 5–6 | Storage Investigator, process-to-disk link, UI, scenario fixtures |
| 7 | Evaluation runs, ablation, and results |
| 8 | Demo video, README, repository cleanup, submission |

**Cut order if time runs short:** stretch goals first, then the process-to-disk link, then storage actions, keeping the process investigator and the evaluation intact.

## 13. Risks and Mitigations

| Risk | Mitigation |
| --- | --- |
| Prompt injection via process or file names | Delimit evidence, instruct the model to ignore embedded instructions, include injection tests |
| Access denied on protected Windows processes | Treat "evidence unavailable" as a first-class state that feeds the missing-evidence output |
| Scope creep | Fixed cut order; read-only storage first |
| Unsafe deletion advice | Policy layer, Recycle Bin only, protected paths, dry-run previews |
| Weak demo drama | Scripted scenarios with a clear benign-versus-suspicious arc |
| Name overlap (an existing game-streaming client is also called Moonlight) | Use a distinctive repository name and tagline, for example "Moonlight: evidence-first PC investigator" |

## 14. Roadmap (Post-Hackathon)

User-controlled resource optimization and semantic file organization through knowledge graphs, built on the same evidence-and-policy pipeline, plus broader scenario coverage and a larger public benchmark.
