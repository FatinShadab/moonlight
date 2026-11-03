"""Tests for MetaProvider and Meta Model API integration.

Covers:
- Schema limits: nesting depth <= 10, no recursive schemas
- Successful call with structured output and alias remapping
- Malformed JSON output handling
- Schema violation handling
- Hallucinated evidence ID rejection via grounding checks
- HTTP 401 invalid_api_key (non-retryable, key redacted)
- HTTP 404 model_not_found (non-retryable)
- HTTP 400 bad schema
- HTTP 429 rate limit with backoff then success
- HTTP 500 server error exhaustion
- Request timeout with retries and clean exception
- Missing API key (MODEL_API_KEY) raising provider-unavailable error
- Secret redaction (key never in repr, cache, or logs)
- Provider-check CLI command
- Eval --provider meta support (skipped without key, opt-in metrics)
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from moonlight.cli import main
from moonlight.core.evidence import (
    EvidenceBundle,
    EvidenceItem,
    EvidenceKind,
    SeverityHint,
    make_evidence_id,
)
from moonlight.eval.harness import _eval_live_provider, run_offline_eval
from moonlight.eval.scenarios import load_process_scenarios
from moonlight.reasoning.cache import ReasoningCache
from moonlight.reasoning.exceptions import (
    InvalidApiKeyError,
    MalformedOutputError,
    MissingApiKeyError,
    ProviderTimeoutError,
    ReasoningProviderError,
    UnknownModelError,
)
from moonlight.reasoning.grounding import UngroundedCitationError
from moonlight.reasoning.models import Report
from moonlight.reasoning.orchestrator import ReasoningOrchestrator
from moonlight.reasoning.prompting import PROMPT_VERSION
from moonlight.reasoning.provider import (
    MetaProvider,
    get_provider,
    validate_schema_depth_and_recursion,
)


def make_test_bundle() -> EvidenceBundle:
    timestamp = datetime(2026, 11, 3, 12, 0, 0, tzinfo=UTC)
    id1 = make_evidence_id(
        "process", "6000", "process_collector", EvidenceKind.EXECUTABLE_PATH
    )
    id2 = make_evidence_id(
        "process", "6000", "signature_collector", EvidenceKind.SIGNATURE_STATUS
    )
    items = [
        EvidenceItem(
            id=id1,
            source="process_collector",
            kind=EvidenceKind.EXECUTABLE_PATH,
            value={"path": "C:/Windows/System32/explorer.exe"},
            severity_hint=SeverityHint.INFO,
            availability="observed",
            reason=None,
            timestamp=timestamp,
        ),
        EvidenceItem(
            id=id2,
            source="signature_collector",
            kind=EvidenceKind.SIGNATURE_STATUS,
            value={"status": "signed_valid"},
            severity_hint=SeverityHint.INFO,
            availability="observed",
            reason=None,
            timestamp=timestamp,
        ),
    ]
    return EvidenceBundle(
        subject_type="process",
        subject_id="6000",
        items=tuple(items),
    )


def sample_valid_meta_report_dict(bundle: EvidenceBundle) -> dict[str, Any]:
    return {
        "summary": "Verified Windows Explorer process with valid Microsoft signature.",
        "risk_tier": "low",
        "confidence": 0.98,
        "observed_facts": [
            {
                "text": "Executable is explorer.exe citing short alias E1.",
                "evidence_ids": ["E1"],
            },
            {
                "text": "Signed valid citing short alias E2.",
                "evidence_ids": ["E2"],
            },
        ],
        "hypotheses": [
            {
                "text": "Standard Windows shell process.",
                "evidence_ids": ["E1", "E2"],
                "likelihood": "high",
            }
        ],
        "benign_explanations": ["Operating system user desktop shell."],
        "missing_evidence": [],
        "recommended_actions": [
            {
                "action_id": "mark_reviewed",
                "reason": "Standard verified operating system binary.",
                "evidence_ids": ["E1"],
            }
        ],
        "uncertainty_notes": "None observed.",
        "metadata": {
            "provider": "meta",
            "model": "muse-spark-1.3",
            "prompt_version": PROMPT_VERSION,
            "timestamp": "2026-11-03T12:00:00Z",
        },
    }


# ---------------------------------------------------------------------------
# Test 1: Schema limits (Nesting depth <= 10, no recursive schemas)
# ---------------------------------------------------------------------------


def test_schema_limits_our_schema_conforms() -> None:
    schema = Report.model_json_schema()
    # Must not raise; Report schema depth is <= 10 and has no recursion
    validate_schema_depth_and_recursion(schema, max_depth=10)


def test_schema_limits_fails_on_recursive_schema() -> None:
    recursive_schema: dict[str, Any] = {
        "$defs": {
            "Node": {
                "type": "object",
                "properties": {
                    "child": {"$ref": "#/$defs/Node"},
                },
            }
        },
        "$ref": "#/$defs/Node",
    }
    with pytest.raises(ValueError, match="Recursive schema detected"):
        validate_schema_depth_and_recursion(recursive_schema, max_depth=10)


def test_schema_limits_fails_on_excessive_nesting_depth() -> None:
    # Build a schema with depth 12
    deep_schema: dict[str, Any] = {"type": "string"}
    for i in range(12):
        deep_schema = {"type": "object", "properties": {f"prop_{i}": deep_schema}}

    with pytest.raises(ValueError, match="exceeds maximum allowed depth"):
        validate_schema_depth_and_recursion(deep_schema, max_depth=10)


# ---------------------------------------------------------------------------
# Test 2: Success with structured output, alias remapping & caching
# ---------------------------------------------------------------------------


def test_meta_provider_success() -> None:
    bundle = make_test_bundle()
    valid_report = sample_valid_meta_report_dict(bundle)
    call_count = 0
    recorded_requests: list[httpx.Request] = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        recorded_requests.append(request)

        # Verify contract from dev.meta.ai docs:
        # POST {base}/chat/completions, Authorization: Bearer $MODEL_API_KEY
        assert request.method == "POST"
        assert str(request.url) == "https://api.meta.ai/v1/chat/completions"
        assert request.headers["Authorization"] == "Bearer secret-meta-token"

        body = json.loads(request.read())
        assert body["model"] == "muse-spark-1.3"
        assert "response_format" in body
        rf = body["response_format"]
        assert rf["type"] == "json_schema"
        assert rf["json_schema"]["name"] == "InvestigationReport"
        assert isinstance(rf["json_schema"]["schema"], dict)
        # Ensure text.format (Responses API) was NOT used
        assert "format" not in body

        response_payload = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": json.dumps(valid_report),
                    }
                }
            ]
        }
        return httpx.Response(200, json=response_payload)

    transport = httpx.MockTransport(mock_handler)
    cache = ReasoningCache()

    provider = MetaProvider(
        model="muse-spark-1.3",
        api_key="secret-meta-token",
        transport=transport,
        cache=cache,
    )

    report = provider.investigate(bundle)
    assert report.is_fallback is False
    assert report.risk_tier == "low"
    assert report.confidence == 0.98
    assert report.metadata.provider == "meta"
    assert report.metadata.model == "muse-spark-1.3"
    assert report.metadata.structured_output_mode == "json_schema"

    # Verify short aliases E1, E2 remapped to actual evidence IDs
    ev_ids = sorted(item.id for item in bundle.items)
    assert report.observed_facts[0].evidence_ids == (ev_ids[0],)
    assert report.observed_facts[1].evidence_ids == (ev_ids[1],)

    assert call_count == 1
    stats = cache.get_stats("meta")
    assert stats["requests"] == 1
    assert stats["misses"] == 1
    assert stats["hits"] == 0

    # Second call should hit the cache without network call
    second_report = provider.investigate(bundle)
    assert second_report.summary == report.summary
    assert call_count == 1
    stats = cache.get_stats("meta")
    assert stats["requests"] == 2
    assert stats["hits"] == 1


# ---------------------------------------------------------------------------
# Test 3: Malformed JSON output
# ---------------------------------------------------------------------------


def test_meta_provider_malformed_json() -> None:
    bundle = make_test_bundle()

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {"message": {"role": "assistant", "content": "Not a JSON document"}}
                ]
            },
        )

    transport = httpx.MockTransport(mock_handler)
    provider = MetaProvider(api_key="key", transport=transport)

    with pytest.raises(MalformedOutputError, match="Failed to parse report content"):
        provider.investigate(bundle)


# ---------------------------------------------------------------------------
# Test 4: Schema violation
# ---------------------------------------------------------------------------


def test_meta_provider_schema_violation() -> None:
    bundle = make_test_bundle()

    def mock_handler(request: httpx.Request) -> httpx.Response:
        # Valid JSON, but missing required Report fields (e.g. risk_tier, confidence)
        bad_report = {"summary": "Only a summary"}
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(bad_report),
                        }
                    }
                ]
            },
        )

    transport = httpx.MockTransport(mock_handler)
    provider = MetaProvider(api_key="key", transport=transport)

    with pytest.raises(MalformedOutputError, match="failed schema validation"):
        provider.investigate(bundle)


# ---------------------------------------------------------------------------
# Test 5: Hallucinated evidence ID rejected
# ---------------------------------------------------------------------------


def test_meta_provider_hallucinated_evidence_id() -> None:
    bundle = make_test_bundle()
    bad_report = sample_valid_meta_report_dict(bundle)
    # Inject hallucinated evidence ID
    bad_report["observed_facts"][0]["evidence_ids"] = ["ev-hallucinated-fake-id-9999"]

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(bad_report),
                        }
                    }
                ]
            },
        )

    transport = httpx.MockTransport(mock_handler)
    provider = MetaProvider(api_key="key", transport=transport)

    with pytest.raises(UngroundedCitationError, match="unknown evidence ID"):
        provider.investigate(bundle)


# ---------------------------------------------------------------------------
# Test 6: HTTP 401 invalid_api_key (non-retryable, key redacted)
# ---------------------------------------------------------------------------


def test_meta_provider_401_invalid_key() -> None:
    bundle = make_test_bundle()
    secret_key = "super-secret-meta-credential-value"

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={"error": {"message": "invalid_api_key"}},
        )

    transport = httpx.MockTransport(mock_handler)
    provider = MetaProvider(api_key=secret_key, transport=transport)

    with pytest.raises(InvalidApiKeyError) as exc_info:
        provider.investigate(bundle)

    err_text = str(exc_info.value)
    assert "401" in err_text
    assert "invalid_api_key" in err_text
    # Secret key must NEVER leak in exception message
    assert secret_key not in err_text


# ---------------------------------------------------------------------------
# Test 7: HTTP 404 model_not_found
# ---------------------------------------------------------------------------


def test_meta_provider_404_model_not_found() -> None:
    bundle = make_test_bundle()

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            404,
            json={"error": {"message": "model_not_found"}},
        )

    transport = httpx.MockTransport(mock_handler)
    provider = MetaProvider(
        model="non-existent-model",
        api_key="valid-key",
        transport=transport,
    )

    with pytest.raises(UnknownModelError, match="non-existent-model"):
        provider.investigate(bundle)


# ---------------------------------------------------------------------------
# Test 8: HTTP 400 bad schema
# ---------------------------------------------------------------------------


def test_meta_provider_400_bad_schema() -> None:
    bundle = make_test_bundle()

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            json={"error": {"message": "bad schema: nesting exceeds limit"}},
        )

    transport = httpx.MockTransport(mock_handler)
    provider = MetaProvider(api_key="valid-key", transport=transport)

    with pytest.raises(ReasoningProviderError, match="400"):
        provider.investigate(bundle)


# ---------------------------------------------------------------------------
# Test 9: HTTP 429 then success on retry
# ---------------------------------------------------------------------------


def test_meta_provider_429_then_success() -> None:
    bundle = make_test_bundle()
    valid_report = sample_valid_meta_report_dict(bundle)
    calls = 0
    sleeps: list[float] = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(
                429,
                headers={"Retry-After": "2"},
                json={"error": {"message": "rate_limit_exceeded"}},
            )
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(valid_report),
                        }
                    }
                ]
            },
        )

    transport = httpx.MockTransport(mock_handler)
    provider = MetaProvider(
        api_key="valid-key",
        transport=transport,
        max_retries=2,
        sleep_fn=sleeps.append,
    )

    report = provider.investigate(bundle)
    assert report.is_fallback is False
    assert calls == 2
    assert sleeps == [2.0]


# ---------------------------------------------------------------------------
# Test 10: HTTP 500 exhaustion
# ---------------------------------------------------------------------------


def test_meta_provider_500_exhaustion() -> None:
    bundle = make_test_bundle()
    calls = 0
    sleeps: list[float] = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            500,
            json={"error": {"message": "internal_server_error"}},
        )

    transport = httpx.MockTransport(mock_handler)
    provider = MetaProvider(
        api_key="valid-key",
        transport=transport,
        max_retries=2,
        backoff_factor=0.25,
        sleep_fn=sleeps.append,
    )

    with pytest.raises(ReasoningProviderError, match="server error \\(500\\)"):
        provider.investigate(bundle)

    # Initial attempt + 2 retries = 3 calls
    assert calls == 3
    assert len(sleeps) == 2


# ---------------------------------------------------------------------------
# Test 11: Timeout with retries
# ---------------------------------------------------------------------------


def test_meta_provider_timeout_exhausted() -> None:
    bundle = make_test_bundle()
    calls = 0
    sleeps: list[float] = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ReadTimeout("Request timed out", request=request)

    transport = httpx.MockTransport(mock_handler)
    provider = MetaProvider(
        api_key="valid-key",
        transport=transport,
        max_retries=2,
        timeout=10.0,
        sleep_fn=sleeps.append,
    )

    with pytest.raises(ProviderTimeoutError, match="timed out"):
        provider.investigate(bundle)

    assert calls == 3
    assert len(sleeps) == 2


# ---------------------------------------------------------------------------
# Test 12: Missing API key
# ---------------------------------------------------------------------------


def test_meta_provider_missing_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    monkeypatch.delenv("META_API_KEY", raising=False)
    bundle = make_test_bundle()

    provider = MetaProvider(api_key="")
    with pytest.raises(MissingApiKeyError, match="MODEL_API_KEY"):
        provider.investigate(bundle)


def test_meta_provider_missing_key_triggers_orchestrator_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    monkeypatch.delenv("META_API_KEY", raising=False)
    bundle = make_test_bundle()

    provider = MetaProvider(api_key="")
    orch = ReasoningOrchestrator(provider=provider)
    report = orch.investigate(bundle)

    assert report.is_fallback is True
    assert report.metadata.provider == "rules_only_fallback"
    assert "MODEL_API_KEY" in (report.fallback_reason or "")


# ---------------------------------------------------------------------------
# Test 13: Secret protection (Never in repr, never in cache)
# ---------------------------------------------------------------------------


def test_meta_provider_secret_protection(tmp_path: Path) -> None:
    secret = "meta-classified-token-do-not-expose"
    cache = ReasoningCache(cache_dir=tmp_path)
    bundle = make_test_bundle()
    valid_report = sample_valid_meta_report_dict(bundle)

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(valid_report),
                        }
                    }
                ]
            },
        )

    transport = httpx.MockTransport(mock_handler)
    provider = MetaProvider(
        api_key=secret,
        transport=transport,
        cache=cache,
    )

    # Key must NOT appear in repr
    assert secret not in repr(provider)

    provider.investigate(bundle)

    # Key must NOT appear in any cache file
    for cached_file in tmp_path.rglob("*.json"):
        content = cached_file.read_text(encoding="utf-8")
        assert secret not in content


# ---------------------------------------------------------------------------
# Test 14: Provider selection via get_provider and env
# ---------------------------------------------------------------------------


def test_get_provider_meta(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MOONLIGHT_PROVIDER", "meta")
    prov = get_provider()
    assert isinstance(prov, MetaProvider)
    assert prov.model == "muse-spark-1.3"


def test_get_provider_ollama_alias() -> None:
    prov = get_provider(provider="ollama")
    assert prov.__class__.__name__ == "OllamaCloudProvider"


# ---------------------------------------------------------------------------
# Test 15: CLI provider-check command
# ---------------------------------------------------------------------------


def test_cli_provider_check_without_key(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    monkeypatch.delenv("META_API_KEY", raising=False)

    exit_code = main(["provider-check", "--provider", "meta"])
    assert exit_code == 1

    captured = capsys.readouterr()
    assert "MODEL_API_KEY environment variable is missing" in captured.err


def test_cli_provider_check_mock(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["provider-check", "--provider", "mock"])
    assert exit_code == 0

    captured = capsys.readouterr()
    assert "Provider : mock" in captured.out
    assert "Status   : OK" in captured.out


# ---------------------------------------------------------------------------
# Test 16: Eval --provider meta skipped without key
# ---------------------------------------------------------------------------


def test_eval_provider_meta_skipped_without_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    monkeypatch.delenv("META_API_KEY", raising=False)

    report = run_offline_eval(output_dir=tmp_path, provider="meta")
    assert report.overall_passed is True

    live_rows = [r for r in report.scenario_rows if r.suite == "live_model_evaluation"]
    assert len(live_rows) > 0
    for r in live_rows:
        assert r.provider == "meta"
        assert r.is_mock is False
        assert r.actual == "skipped (no MODEL_API_KEY)"
        assert r.passed is True

    live_metric = report.metrics.get("live_model_evaluation", {})
    assert live_metric.get("status") == "skipped"
    assert live_metric.get("reason") == "no MODEL_API_KEY"


def test_eval_live_provider_with_mock_transport() -> None:
    scenarios = load_process_scenarios()[:3]
    now = datetime.now(UTC)

    def mock_handler(request: httpx.Request) -> httpx.Response:
        # Generate valid response citing E1
        rep = {
            "summary": "Process verified normal.",
            "risk_tier": "low",
            "confidence": 0.95,
            "observed_facts": [
                {"text": "Observed normal execution citing E1.", "evidence_ids": ["E1"]}
            ],
            "hypotheses": [],
            "benign_explanations": ["Normal activity."],
            "missing_evidence": [],
            "recommended_actions": [
                {
                    "action_id": "mark_reviewed",
                    "reason": "Normal",
                    "evidence_ids": ["E1"],
                }
            ],
            "uncertainty_notes": "",
            "metadata": {
                "provider": "meta",
                "model": "muse-spark-1.3",
                "prompt_version": PROMPT_VERSION,
                "timestamp": "2026-11-03T12:00:00Z",
            },
        }
        return httpx.Response(
            200,
            json={
                "choices": [
                    {"message": {"role": "assistant", "content": json.dumps(rep)}}
                ]
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(mock_handler))
    summary, rows, metrics = _eval_live_provider(
        provider_name="meta",
        process_scenarios=scenarios,
        now=now,
        client=client,
        api_key="valid-test-key",
    )

    assert summary.passed is True
    assert len(rows) == 3
    assert metrics["schema_valid_rate"] == 1.0
    assert metrics["grounded_rate"] == 1.0
    assert metrics["hallucinated_evidence_count"] == 0
