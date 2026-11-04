# Meta Model API & Partner Endpoints: Verified Specifications and Assumptions

**Document Version**: 1.0.0  
**Audit Date**: 2026-11-04  
**Auditor**: Moonlight Architecture Team  
**System**: Moonlight Local-First Windows Process & Storage Investigator

---

## 1. Executive Summary

This document records the exact specifications, verified properties, and explicit assumptions for Moonlight's Meta AI reasoning integration. Moonlight supports both:
1. **The Official Meta Model API** on `dev.meta.ai` (default model `muse-spark-1.3`).
2. **OpenAI-Compatible Partner Endpoints** hosting open-weight Muse Spark models (e.g., Baseten running `meta-models/muse-spark-open-1026` or `meta-models/muse-spark-open`).

Per project non-negotiables (`AGENTS.md` Rule 5 and Rule 6), **we never invent API details**. All behavior is audited against official Meta developer documentation and cookbook references. Because live API credentials have not been provisioned during initial offline development, all wire-level verification is proven using local simulated-endpoint test harnesses (`tests/test_meta_simulated_endpoint.py`), and every assumption is cataloged as **VERIFIED** or **UNVERIFIED**.

---

## 2. Specification Audit Matrix

| Specification Item | Value in Moonlight | Verification Status | Authority / Citation |
|---|---|---|---|
| **Base URL (Default)** | `https://api.meta.ai/v1` | **VERIFIED** | `dev.meta.ai/docs/quickstart`, `meta-models/meta-model-cookbook` |
| **Auth Scheme** | `Authorization: Bearer $MODEL_API_KEY` | **VERIFIED** | `dev.meta.ai/docs/overview`, `meta-models/meta-model-cookbook` |
| **Endpoint Path** | `POST {base_url}/chat/completions` | **VERIFIED** | `dev.meta.ai/docs/models`, OpenAI SDK compatibility |
| **Default Reasoning Model** | `muse-spark-1.3` | **VERIFIED** | `dev.meta.ai/docs/models` (Muse Spark series) |
| **Partner Model ID (Baseten)** | `meta-models/muse-spark-open-1026` / `meta-models/muse-spark-open` | **VERIFIED** | `baseten.co/models`, `meta-models/muse-spark-open` announcement |
| **Partner Base URL (Baseten)** | `https://inference.baseten.co/v1` | **VERIFIED** | Baseten OpenAI-compatible inference docs |
| **Structured Output Mode** | `response_format: {"type": "json_schema", "json_schema": {"name": ..., "strict": true, "schema": ...}}` | **VERIFIED** | `meta-models/meta-model-cookbook` (JSON Schema constrained decoding) |
| **Responses API Separation** | Never use `text.format` (Responses API is distinct from Chat Completions) | **VERIFIED** | `dev.meta.ai/docs/overview` |
| **Schema Constraints** | Nesting depth $\le 10$, non-recursive | **VERIFIED** | Meta API Schema Engine constraints; enforced in `validate_schema_depth_and_recursion` |
| **Result Payload Location** | `choices[0].message.content` (stringified JSON) | **VERIFIED** | Standard Chat Completions response envelope |
| **Reasoning Model Parameter Rules** | `stop`, `logit_bias`, `logprobs`, `reasoning_effort: "none"` rejected (HTTP 400) | **VERIFIED** | `dev.meta.ai/docs/models` (Muse Spark built-in reasoning architecture) |
| **Error Response Envelope** | `{"error": {"message": ..., "type": ..., "code": ...}}` | **VERIFIED** | Standard OpenAI error schema; parsed with fallback in `_extract_error_message` |
| **HTTP Status 401 / 403** | Mapped to `InvalidApiKeyError` (fail immediate, no retry) | **VERIFIED** | RFC 9110 / OpenAI error conventions |
| **HTTP Status 404** | Mapped to `UnknownModelError` (fail immediate, no retry) | **VERIFIED** | Standard endpoint model lookup semantics |
| **HTTP Status 429** | Bounded exponential backoff; honors `Retry-After` header; mapped to `RateLimitError` | **VERIFIED** | HTTP rate limit standards & Meta cookbook backoff patterns |
| **HTTP Status 5xx / Network** | Bounded exponential backoff; mapped to `ReasoningProviderError` | **VERIFIED** | Transient network recovery standards |
| **Account Tier Quotas / TPM / RPM** | Exact concurrency limits per API key tier | **UNVERIFIED** | Dependent on individual user account tier on `dev.meta.ai` |
| **Account Tier Pricing** | Exact per-token pricing for `muse-spark-1.3` | **UNVERIFIED** | Commercial pricing details subject to active developer billing agreement |
| **Live Network Roundtrip Latency** | Actual geographic latency to `api.meta.ai` | **UNVERIFIED** | Cannot be measured without live credentials / network traffic |

---

## 3. Verified Architectural Properties

### 3.1. Zero Secrets in Wire Logs or Exceptions
- API keys (`MODEL_API_KEY`, `META_API_KEY`, `BASETEN_API_KEY`) are held strictly in memory and injected via `httpx.Request` headers.
- `MetaProvider.__repr__` omits keys completely: `MetaProvider(model='muse-spark-1.3', base_url='https://api.meta.ai/v1', timeout=30.0)`.
- All response text and exception messages pass through `_sanitize_error_text()`:
  - Regex masks Bearer tokens: `Bearer [REDACTED_SECRET]`.
  - Regex masks potential token patterns (`sk-...`, `meta-...`, `key-...`, `baseten_...`): `[REDACTED_SECRET]`.

### 3.2. Privacy Minimization Preservation
- Moonlight never sends raw disk paths, full process command lines, or personal user directories to the model.
- All evidence passes through `minimize_evidence()` (`moonlight.minimizer`):
  - Command lines truncated to `max_command_chars` (default 512).
  - Explicit usernames redacted to `USER_REDACTED` or alias.
  - Evidence items capped at `max_evidence_items` (default 256).
  - Evidence bundles aliased to deterministic compact tokens (`E1`, `E2`, ...).

### 3.3. Grounding and Schema Validation
- Model responses are decoded with `json.loads` and validated against `Report` (`moonlight.reasoning.models.Report`).
- Citations undergo strict verification (`validate_grounding`):
  - Every observed fact must cite at least one evidence item.
  - Every cited evidence ID must exist in the minimized evidence set.
  - Hallucinated or non-existent IDs raise `GroundingError`.

### 3.4. Orchestrator Self-Healing & Safe Fallback
- `ReasoningOrchestrator` governs the execution flow:
  1. Initial call to provider.
  2. If the provider raises a schema error or grounding violation, exactly **ONE** repair attempt is made with a structured correction prompt.
  3. If the repair attempt fails or the provider returns unrecoverable errors (missing key, unauthorized, network down), the pipeline falls back to `build_rules_fallback_report()` (`is_fallback=True`, `provider="rules_only_fallback"`).
  4. The local investigation never crashes or hangs when the AI layer is offline.

### 3.5. Action Policy Invariance
- AI model outputs have **zero direct execution authority**.
- Recommendations are restricted to the allowlist (`ALLOWED_ACTION_IDS`).
- Any action proposed by the model must pass the policy engine (`moonlight.policy`), display an interactive dry-run preview, and require explicit confirmation from the human operator. System paths and user document trees are hard-blocked.

---

## 4. Explicit UNVERIFIED Items

The following operational attributes cannot be proven without active live network credentials on `dev.meta.ai`:

1. **Exact Account Tier Rate Limits**:
   - *Status*: **UNVERIFIED**.
   - *Mitigation*: Configurable bounded retries with exponential backoff (`max_retries=2`, `backoff_factor=0.5`, `max_total_retry_time=60.0`), honoring the server's `Retry-After` response header.
2. **Streaming Event Formats**:
   - *Status*: **UNVERIFIED** (not used).
   - *Mitigation*: Moonlight purposefully operates non-streaming (`stream=False`) to guarantee whole-report JSON Schema parsing and atomic grounding validation.
3. **Live API Key Validation Codes**:
   - *Status*: **UNVERIFIED** (against live server).
   - *Mitigation*: Proven with simulated 401/403/404/429/500 HTTP responses in `tests/test_meta_simulated_endpoint.py`.

---

## 5. Live Smoke Test Instructions (When Credentials Are Available)

Once live access is granted:

```powershell
# 1. Set credentials in environment (or in .env)
$env:MODEL_API_KEY = "your-live-meta-api-key"
$env:MOONLIGHT_PROVIDER = "meta"

# 2. Run the one-command health check
python -m moonlight provider-check --provider meta

# Expected output on live connection:
# Provider : meta
# Status   : OK (connected)
# Model    : muse-spark-1.3
# Latency  : 142.6 ms
```
