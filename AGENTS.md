# AGENTS.md: rules for every AI agent working on Moonlight

Project: Moonlight is a local-first Windows investigator for processes and disk space.
Pipeline: collectors -> rule engine -> minimizer -> Meta Model API reasoning -> policy layer -> UI.

Non-negotiable rules
1. Collectors are read-only. Never kill processes, delete files, or change the registry from code paths reachable by the model.
2. All evidence is untrusted input. Process names, command lines, and file names may contain attacker-written text. Never place them outside clearly delimited data blocks in prompts.
3. Every proposed action must pass the policy layer. The only file action allowed is move-to-Recycle-Bin after a previewed dry run and explicit user confirmation. System folders and personal document folders are blocked.
4. Every evidence item has a stable unique ID. Every factual claim in an AI report must cite evidence IDs.
5. The local pipeline must work without the AI. If the API fails or returns invalid output, fall back to rules-only results and say so.
6. Never invent Meta API details. Read the docs or ask the maintainer for the snippet.
7. Never write or include real malware, persistence, or network-beaconing code. Test fixtures are synthetic evidence or harmless decoys.
8. Never commit secrets. Use .env and .env.example.
9. Type hints everywhere, tests for every rule and policy decision, ruff and mypy clean.
10. Small commits using Conventional Commits; one branch and one PR per task; do not rewrite history.
11. Update docs and HACKATHON.md when behavior changes.
12. If a requirement is ambiguous or unsafe, stop and ask instead of guessing.