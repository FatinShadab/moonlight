# 02 · Strategy

## Track and problem statement

**Indie Developer track · "Build for Your World".** A full disk and an unexplained process are a problem the
builder knows firsthand, and the product is a desktop tool for that exact pain. "Push the Frontier" (machine
capability / physical systems) is a weaker fit.

Anti-project check: Moonlight is not a chatbot, RAG app or image analyzer. The model is one validated stage
inside a deterministic, local evidence pipeline. Keep the video framed that way ("not a wrapper").

## Stage 1 risk (stated plainly)

**The video will not show a live Meta model call unless you get access.** The Meta provider is implemented
(`src/moonlight/reasoning/provider.py:730`, `response_format: json_schema` at :896–901) and contract-tested against
**simulated** HTTP servers (`tests/test_meta_simulated_endpoint.py`, 12 passed). `results/RESULTS.md` §9 says no live run has
happened. Stage 1 requires "reasonably uses Meta Model API and/or Meta open-weight models". A strict judge may read
"never actually called" as a fail. **This is the biggest single risk to the whole submission.**

### Options, ranked

| Rank | Option | Work | What it changes |
|---|---|---|---|
| 1 | **Partner-hosted Muse Spark Open** (Baseten `meta-models/muse-spark-open-1026`; Fireworks/Modal through the same OpenAI-compatible path) | About 30–60 min, mostly account and credit access. **No code:** 3 env vars, 2 commands, re-record clips 7 and 13 (`03_script.md` swap-in plan) | Stage 1 very likely passes. Eligible for the Open-Weights bonus. Clip 7 becomes a genuine Meta-model report. |
| 2 | **Meta Model API credits** (`MODEL_API_KEY`, `muse-spark-1.3`) | Same, if you can get credits tonight | Stage 1 very likely passes. No open-weights bonus. |
| 3 | **Honest simulated-only fallback** (as scripted) | 0 | Stage 1 uncertain. Everything else stands. |

### Realistic chances by option (my judgment, not data; do not quote)

| | Stage 1 pass | Top 5 in track (Stage 3) | Open-Weights $10K | Agentic $5K | Creative $5K | Viral $20K | Community $10K |
|---|---|---|---|---|---|---|---|
| **1 Partner Muse Spark Open** | High (~80–90%) | Low–moderate (~5–15%) | Plausible contender (~10–25%, depends on how few teams use open weights) | Low (~2–5%) | ~0% | Low (~1–3%) | Low (~2–5%) |
| **2 Meta API credits** | High (~80–90%) | Low–moderate (~5–15%) | Not eligible | Low (~2–5%) | ~0% | Low (~1–3%) | Low (~2–5%) |
| **3 Simulated only** | Uncertain (~35–55%) | Low (~2–6%) | Not eligible | Very low | ~0% | Low (~1–3%) | Low (~2–5%) |

Why the main-prize odds are modest even in the best case: strong engineering and safety story, but the Impact
category favours wide-reach problems, and the demo can't show a "wow" Meta capability (vision, voice, SAM).
The edge comes from Technical Depth and the safety narrative.

## Rubric → video map (weighted)

| Criterion (weight) | Clips that earn it | What the judge sees |
|---|---|---|
| Impact 30% | 1, 2, 5, 11, 12, 17 | A real pain (full disk, odd process), a concrete answer (the PID writing 2.7 MB/s), and safety for normal users (Recycle Bin only, with consent) |
| Meta tooling 25% | 7, 8, 13, 14 (+ the swap-in) | Schema-constrained structured output (`json_schema`), facts vs hypotheses with citations, provider swapped by config, partner endpoint for Muse Spark Open, contract tests. Weakest category without a live call, which is why the swap-in matters most. |
| Technical depth 20% | 4–6, 9, 10, 15, 16 | Read-only collectors, stable evidence IDs, minimizer/redaction, injection defence, grounding validator, a 103-scenario eval with published weaknesses, 138 commits in 9 days |
| Demo 25% | 3, 5, 10–12 (peak), 17 | The isometric world, the live catch, a red "rejected" moment, then green consent. One idea per 10 s. |

## Bonus prizes: what's missing

- **Best Build on Meta Open Weight Models ($10K):** missing a live call through a partner, plus partner verification. The code path exists (`.env.example` Option B). You need a Baseten (or Fireworks/Modal) key, one live `investigate` run, and the partner usage record. Highest-value fix.
- **Best Agentic Use-Case ($5K):** the system is *deliberately* not autonomous (the model can't act). A planner loop calling collectors as tools would be new work. Don't start it. Low odds.
- **Best Creative Build ($5K):** needs original use of Muse Image or Muse Wonder. There is none in the repo. Not reachable without new work. Skip it, and don't generate a logo with Muse Image now just to claim it.
- **Most Viral ($20K):** needs X engagement by Nov 8 EOD. Post the 45 s cut (`07_submission_pack.md`) right after submitting and submit the post link on the platform. Odds depend on your audience.
- **Community Vote ($10K):** post in the hackathon Discord with the video and a one-line ask. Low cost; do it.

## The 3 things judges must remember

1. **It found the culprit, with evidence IDs, locally and read-only.**
2. **The AI is never trusted alone:** ungrounded output is rejected, kills and system paths are refused, and the only action is a consented Recycle Bin dry run.
3. **Measured and honest:** 0/20 false positives, 21/21 unsafe actions blocked, recall 8/15 published.
