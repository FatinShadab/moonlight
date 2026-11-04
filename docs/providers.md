# Reasoning Providers in Moonlight

Moonlight provides a pluggable, local-first reasoning architecture. The local detection pipeline executes deterministic heuristics first, then optionally dispatches minimized, privacy-redacted evidence to an AI provider for deep narrative explanations and hypotheses.

---

## 1. Supported Providers

| Provider Identifier (`MOONLIGHT_PROVIDER`) | Description | Purpose / Typical Usage |
|---|---|---|
| `meta` (Production Default for Submission) | Meta Model API (`dev.meta.ai`) or any OpenAI-compatible partner endpoint serving Muse Spark Open | Grounded, schema-constrained security investigation reports. |
| `ollama` / `ollama-cloud` | Hosted Ollama endpoint (e.g. `https://ollama.com` or local Ollama) | Development stand-in and testing without Meta credentials. |
| `mock` | Fully offline, deterministic report replayer reading synthetic fixtures | CI/CD test suite, local dev without any network dependencies. |

---

## 2. Configuring the `meta` Provider

The `meta` provider communicates via standard HTTP Chat Completions (`POST {base_url}/chat/completions`) using Bearer token authentication and structured JSON Schema constrained output (`response_format`).

### Option A: Official Meta Model API (`dev.meta.ai`)

1. Obtain a model API key from [dev.meta.ai](https://dev.meta.ai).
2. Configure environment variables in `.env` or shell:
   ```env
   MOONLIGHT_PROVIDER=meta
   MODEL_API_KEY=your_meta_api_key_here
   MOONLIGHT_META_BASE_URL=https://api.meta.ai/v1
   MOONLIGHT_META_MODEL=muse-spark-1.3
   ```
3. Test your connection:
   ```bash
   python -m moonlight provider-check --provider meta
   ```

### Option B: OpenAI-Compatible Partner Endpoints (e.g., Baseten)

Partners such as **Baseten** provide hosted endpoints for Meta's open-weight model, **Muse Spark Open** (`meta-models/muse-spark-open-1026` or `meta-models/muse-spark-open`). Because Baseten exposes standard OpenAI-compatible `/v1/chat/completions`, Moonlight works out of the box:

1. Obtain your API key from [baseten.co](https://baseten.co).
2. Configure `.env` or environment:
   ```env
   MOONLIGHT_PROVIDER=meta
   MODEL_API_KEY=your_baseten_api_key
   # or BASETEN_API_KEY=your_baseten_api_key
   MOONLIGHT_META_BASE_URL=https://inference.baseten.co/v1
   MOONLIGHT_META_MODEL=meta-models/muse-spark-open-1026
   ```
3. Test your connection:
   ```bash
   python -m moonlight provider-check --provider meta
   ```

### Option C: Moonlight Desktop UI Settings

You can also configure the provider directly inside the Moonlight desktop app without touching code or `.env`:
1. Launch the Moonlight app (`python -m moonlight.ui.main`).
2. Click **Settings** in the left navigation rail.
3. In **AI Reasoning & Model Providers**:
   - Set **Active Provider** to `meta`.
   - Enter your **Meta API Key** (click Show to verify).
   - Enter the **Base URL** (default: `https://api.meta.ai/v1` or your partner endpoint).
   - Select or enter the **Meta Model** (e.g., `muse-spark-1.3` or `meta-models/muse-spark-open-1026`).
   - Click **Test Connection** to confirm connectivity and latency.
   - Click **Save Settings**. Settings are saved to `state/settings.json` and synchronized across the running process.

---

## 3. Environment Variables Quick Reference

| Environment Variable | Alternate Alias | Default | Description |
|---|---|---|---|
| `MOONLIGHT_PROVIDER` | `PROVIDER` | `ollama` | Active reasoning provider (`mock`, `ollama`, `meta`). |
| `MODEL_API_KEY` | `META_API_KEY`, `BASETEN_API_KEY` | *(empty)* | Secret Bearer token for Meta API or partner endpoint. |
| `MOONLIGHT_META_BASE_URL` | `META_BASE_URL` | `https://api.meta.ai/v1` | Root HTTP base URL for Chat Completions. |
| `MOONLIGHT_META_MODEL` | `META_MODEL` | `muse-spark-1.3` | Model identifier string. |

---

## 4. Robustness & Offline Fallback Guarantee

Moonlight is designed under the **Local-First Resilience Guarantee** (`AGENTS.md` Rule 5):
- If the AI reasoning provider fails (missing key, unauthorized 401, rate limit 429, timeout, network failure, or bad schema):
  1. The orchestrator attempts exactly **one repair retry** if the failure was a malformed schema or ungrounded citation.
  2. If the failure persists, Moonlight immediately falls back to a deterministic, rules-only report (`is_fallback=True`, `provider="rules_only_fallback"`).
  3. The local investigator, policy guardrails, and UI continue to operate with 100% functionality.
  4. The user is clearly notified that reasoning used local rules fallback.
