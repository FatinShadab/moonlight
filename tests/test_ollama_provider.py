"""Mocked-HTTP tests for OllamaCloudProvider.

Covers:
- Successful call with schema-constrained JSON and prompt citation remapping
- Missing and invalid API keys (401, 403) with no secret leakage
- Unknown or retired models (404)
- Rate limiting (429) with exponential backoff and bounded retries
- Request timeout handling with retries and clean exception
- Malformed JSON and invalid schema outputs
- Provider-segregated caching (keyed by provider, model, payload hash, prompt version)
- Never mixing caches across providers
- Logging and tracking request counts
- Seamless switching between mock and ollama-cloud in orchestrator and CLI
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
from moonlight.reasoning.cache import ReasoningCache, compute_payload_hash
from moonlight.reasoning.exceptions import (
    InvalidApiKeyError,
    MalformedOutputError,
    MissingApiKeyError,
    ProviderTimeoutError,
    RateLimitError,
    UnknownModelError,
)
from moonlight.reasoning.models import (
    Report,
)
from moonlight.reasoning.orchestrator import ReasoningOrchestrator
from moonlight.reasoning.prompting import PROMPT_VERSION
from moonlight.reasoning.provider import (
    MockProvider,
    OllamaCloudProvider,
)


def make_test_bundle() -> EvidenceBundle:
    timestamp = datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC)
    id1 = make_evidence_id(
        "process", "5000", "process_collector", EvidenceKind.EXECUTABLE_PATH
    )
    id2 = make_evidence_id(
        "process", "5000", "signature_collector", EvidenceKind.SIGNATURE_STATUS
    )
    items = [
        EvidenceItem(
            id=id1,
            source="process_collector",
            kind=EvidenceKind.EXECUTABLE_PATH,
            value={"path": "C:/Windows/System32/svchost.exe"},
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
        subject_id="5000",
        items=tuple(items),
    )


def sample_valid_report_dict(bundle: EvidenceBundle) -> dict[str, Any]:
    return {
        "summary": "Verified Windows svchost process with valid signature.",
        "risk_tier": "low",
        "confidence": 0.95,
        "observed_facts": [
            {
                "text": "Executable is svchost.exe citing short alias E1.",
                "evidence_ids": ["E1"],
            },
            {
                "text": "Signed valid citing short alias E2.",
                "evidence_ids": ["E2"],
            },
        ],
        "hypotheses": [
            {
                "text": "Legitimate OS service host.",
                "evidence_ids": ["E1", "E2"],
                "likelihood": "high",
            }
        ],
        "benign_explanations": ["Standard operating system process."],
        "missing_evidence": [],
        "recommended_actions": [
            {
                "action_id": "mark_reviewed",
                "reason": "Signed system binary verified.",
                "evidence_ids": ["E1"],
            }
        ],
        "uncertainty_notes": "",
        "metadata": {
            "provider": "ollama-cloud",
            "model": "test-cloud-model:31b",
            "prompt_version": PROMPT_VERSION,
            "timestamp": "2026-10-27T12:00:00Z",
        },
    }


# ---------------------------------------------------------------------------
# Test 1: Success with schema-constrained JSON & alias remapping
# ---------------------------------------------------------------------------


def test_ollama_provider_success() -> None:
    bundle = make_test_bundle()
    valid_report = sample_valid_report_dict(bundle)
    call_count = 0
    recorded_requests: list[httpx.Request] = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        recorded_requests.append(request)

        # Verify endpoint and Authorization Bearer header
        assert str(request.url) == "https://ollama.com/api/chat"
        assert request.headers["Authorization"] == "Bearer test-secret-token"

        # Verify payload structure
        body = json.loads(request.read())
        assert body["model"] == "test-cloud-model:31b"
        assert body["stream"] is False
        assert "format" in body
        assert isinstance(body["format"], dict)  # JSON schema used
        assert len(body["messages"]) >= 2

        response_payload = {
            "model": "test-cloud-model:31b",
            "created_at": "2026-10-27T12:00:00Z",
            "message": {
                "role": "assistant",
                "content": json.dumps(valid_report),
            },
            "done": True,
        }
        return httpx.Response(200, json=response_payload)

    transport = httpx.MockTransport(mock_handler)
    client = httpx.Client(transport=transport)
    cache = ReasoningCache()

    provider = OllamaCloudProvider(
        model="test-cloud-model:31b",
        api_key="test-secret-token",
        client=client,
        cache=cache,
    )

    report = provider.investigate(bundle)
    assert report.is_fallback is False
    assert report.risk_tier == "low"
    assert report.confidence == 0.95
    assert report.metadata.provider == "ollama-cloud"
    assert report.metadata.model == "test-cloud-model:31b"

    # Verify short aliases E1, E2 remapped to actual evidence IDs
    ev_ids = sorted(item.id for item in bundle.items)
    assert report.observed_facts[0].evidence_ids == (ev_ids[0],)
    assert report.observed_facts[1].evidence_ids == (ev_ids[1],)

    assert call_count == 1
    stats = cache.get_stats("ollama-cloud")
    assert stats["requests"] == 1
    assert stats["misses"] == 1
    assert stats["hits"] == 0

    # Second call should hit the cache without invoking the HTTP client
    second_report = provider.investigate(bundle)
    assert second_report.summary == report.summary
    assert call_count == 1  # transport not called again!

    stats = cache.get_stats("ollama-cloud")
    assert stats["requests"] == 2
    assert stats["hits"] == 1


# ---------------------------------------------------------------------------
# Test 2: Missing & Invalid Key (401, 403)
# ---------------------------------------------------------------------------


def test_ollama_provider_missing_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    bundle = make_test_bundle()

    provider = OllamaCloudProvider(model="test-cloud-model", api_key="")
    with pytest.raises(MissingApiKeyError, match="missing or empty"):
        provider.investigate(bundle)


def test_ollama_provider_invalid_key_401() -> None:
    bundle = make_test_bundle()

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "unauthorized token"})

    transport = httpx.MockTransport(mock_handler)
    client = httpx.Client(transport=transport)

    secret_key = "super-secret-xyz-12345"
    provider = OllamaCloudProvider(
        model="test-model",
        api_key=secret_key,
        client=client,
    )

    with pytest.raises(InvalidApiKeyError) as exc_info:
        provider.investigate(bundle)

    # Secret key must NEVER be included in the error message
    assert secret_key not in str(exc_info.value)
    assert "401" in str(exc_info.value)


def test_ollama_provider_forbidden_key_403() -> None:
    bundle = make_test_bundle()

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": "forbidden"})

    transport = httpx.MockTransport(mock_handler)
    client = httpx.Client(transport=transport)

    provider = OllamaCloudProvider(
        model="test-model",
        api_key="secret-key",
        client=client,
    )

    with pytest.raises(InvalidApiKeyError, match="403"):
        provider.investigate(bundle)


# ---------------------------------------------------------------------------
# Test 3: Unknown Model (404 and empty model)
# ---------------------------------------------------------------------------


def test_ollama_provider_unknown_model_404() -> None:
    bundle = make_test_bundle()

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "model 'retired-model' not found"})

    transport = httpx.MockTransport(mock_handler)
    client = httpx.Client(transport=transport)

    provider = OllamaCloudProvider(
        model="retired-model",
        api_key="valid-key",
        client=client,
    )

    with pytest.raises(UnknownModelError, match="retired-model"):
        provider.investigate(bundle)


def test_ollama_provider_missing_model_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OLLAMA_MODEL", raising=False)
    bundle = make_test_bundle()

    provider = OllamaCloudProvider(model="", api_key="valid-key")
    with pytest.raises(UnknownModelError, match="model name is required"):
        provider.investigate(bundle)


# ---------------------------------------------------------------------------
# Test 4: Rate Limiting (429) with Backoff & Retries
# ---------------------------------------------------------------------------


def test_ollama_provider_rate_limit_429_exhausted() -> None:
    bundle = make_test_bundle()
    calls = 0
    sleeps: list[float] = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(429, json={"error": "rate limit exceeded"})

    transport = httpx.MockTransport(mock_handler)
    client = httpx.Client(transport=transport)

    provider = OllamaCloudProvider(
        model="test-model",
        api_key="valid-key",
        client=client,
        max_retries=2,
        backoff_factor=0.25,
        sleep_fn=sleeps.append,
    )

    with pytest.raises(RateLimitError, match="rate limit exceeded"):
        provider.investigate(bundle)

    # 1 initial attempt + 2 retries = 3 calls
    assert calls == 3
    assert len(sleeps) == 2
    # Verify exponential backoff: 0.25 * (2**0) = 0.25, 0.25 * (2**1) = 0.5
    assert sleeps == [0.25, 0.5]


def test_ollama_provider_rate_limit_429_recovers_on_retry() -> None:
    bundle = make_test_bundle()
    calls = 0
    sleeps: list[float] = []
    valid_report = sample_valid_report_dict(bundle)

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(
                429, headers={"Retry-After": "2"}, json={"error": "busy"}
            )
        return httpx.Response(
            200,
            json={
                "message": {"role": "assistant", "content": json.dumps(valid_report)}
            },
        )

    transport = httpx.MockTransport(mock_handler)
    client = httpx.Client(transport=transport)

    provider = OllamaCloudProvider(
        model="test-model",
        api_key="valid-key",
        client=client,
        max_retries=2,
        sleep_fn=sleeps.append,
    )

    report = provider.investigate(bundle)
    assert report.is_fallback is False
    assert calls == 2
    assert sleeps == [2.0]  # Parsed Retry-After header


# ---------------------------------------------------------------------------
# Test 5: Timeout with Retries
# ---------------------------------------------------------------------------


def test_ollama_provider_timeout_exhausted() -> None:
    bundle = make_test_bundle()
    calls = 0
    sleeps: list[float] = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ReadTimeout("Connection timed out", request=request)

    transport = httpx.MockTransport(mock_handler)
    client = httpx.Client(transport=transport)

    provider = OllamaCloudProvider(
        model="test-model",
        api_key="valid-key",
        client=client,
        max_retries=2,
        timeout=10.0,
        sleep_fn=sleeps.append,
    )

    with pytest.raises(ProviderTimeoutError, match="timed out"):
        provider.investigate(bundle)

    assert calls == 3
    assert len(sleeps) == 2


def test_ollama_provider_timeout_recovers_on_retry() -> None:
    bundle = make_test_bundle()
    calls = 0
    valid_report = sample_valid_report_dict(bundle)

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise httpx.ConnectTimeout("Connect timeout", request=request)
        return httpx.Response(
            200,
            json={
                "message": {"role": "assistant", "content": json.dumps(valid_report)}
            },
        )

    transport = httpx.MockTransport(mock_handler)
    client = httpx.Client(transport=transport)

    provider = OllamaCloudProvider(
        model="test-model",
        api_key="valid-key",
        client=client,
        max_retries=2,
        sleep_fn=lambda _: None,
    )

    report = provider.investigate(bundle)
    assert report.is_fallback is False
    assert calls == 2


# ---------------------------------------------------------------------------
# Test 6: Malformed Output Handling
# ---------------------------------------------------------------------------


def test_ollama_provider_malformed_raw_json() -> None:
    bundle = make_test_bundle()

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="Not a JSON response")

    transport = httpx.MockTransport(mock_handler)
    client = httpx.Client(transport=transport)

    provider = OllamaCloudProvider(
        model="test-model",
        api_key="valid-key",
        client=client,
    )

    with pytest.raises(MalformedOutputError, match="not valid JSON"):
        provider.investigate(bundle)


def test_ollama_provider_missing_message_content() -> None:
    bundle = make_test_bundle()

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"done": True})

    transport = httpx.MockTransport(mock_handler)
    client = httpx.Client(transport=transport)

    provider = OllamaCloudProvider(
        model="test-model",
        api_key="valid-key",
        client=client,
    )

    with pytest.raises(MalformedOutputError, match="message.content"):
        provider.investigate(bundle)


def test_ollama_provider_content_not_valid_report() -> None:
    bundle = make_test_bundle()

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "message": {"role": "assistant", "content": json.dumps({"foo": "bar"})}
            },
        )

    transport = httpx.MockTransport(mock_handler)
    client = httpx.Client(transport=transport)

    provider = OllamaCloudProvider(
        model="test-model",
        api_key="valid-key",
        client=client,
    )

    with pytest.raises(MalformedOutputError, match="failed schema validation"):
        provider.investigate(bundle)


# ---------------------------------------------------------------------------
# Test 7: Schema Fallback on 400
# ---------------------------------------------------------------------------


def test_ollama_provider_schema_fallback_to_json_on_400() -> None:
    bundle = make_test_bundle()
    calls = 0
    valid_report = sample_valid_report_dict(bundle)

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        body = json.loads(request.read())
        if calls == 1:
            # First call with schema format is rejected by an older ollama endpoint
            assert isinstance(body["format"], dict)
            return httpx.Response(400, json={"error": "format schema not supported"})
        # Fallback call sends format="json"
        assert body["format"] == "json"
        return httpx.Response(
            200,
            json={
                "message": {"role": "assistant", "content": json.dumps(valid_report)}
            },
        )

    transport = httpx.MockTransport(mock_handler)
    client = httpx.Client(transport=transport)

    provider = OllamaCloudProvider(
        model="test-model",
        api_key="valid-key",
        client=client,
    )

    report = provider.investigate(bundle)
    assert report.is_fallback is False
    assert calls == 2


# ---------------------------------------------------------------------------
# Test 8: Cache Segregation (Never Mix Caches Across Providers)
# ---------------------------------------------------------------------------


def test_cache_never_mixes_across_providers(tmp_path: Path) -> None:
    cache = ReasoningCache(cache_dir=tmp_path)
    model = "llama-model"
    payload_hash = compute_payload_hash("sample_prompt")
    prompt_version = "1.0.0"

    ollama_text = '{"summary": "Ollama report"}'
    meta_text = '{"summary": "Meta report"}'

    cache.set("ollama-cloud", model, payload_hash, prompt_version, ollama_text)
    cache.set("meta", model, payload_hash, prompt_version, meta_text)

    # Retrieval for ollama-cloud returns ollama response
    assert cache.get("ollama-cloud", model, payload_hash, prompt_version) == ollama_text
    # Retrieval for meta returns meta response
    assert cache.get("meta", model, payload_hash, prompt_version) == meta_text
    # Retrieval for mock returns None
    assert cache.get("mock", model, payload_hash, prompt_version) is None

    # Disk inspection: separate subdirectories per provider
    ollama_dir = tmp_path / "ollama-cloud"
    meta_dir = tmp_path / "meta"
    assert ollama_dir.is_dir()
    assert meta_dir.is_dir()

    ollama_files = list(ollama_dir.glob("*.json"))
    meta_files = list(meta_dir.glob("*.json"))
    assert len(ollama_files) == 1
    assert len(meta_files) == 1
    assert ollama_files[0].read_text(encoding="utf-8") == ollama_text
    assert meta_files[0].read_text(encoding="utf-8") == meta_text


# ---------------------------------------------------------------------------
# Test 9: Secret Protection (Never Logged, Never in Repr, Never in Caches)
# ---------------------------------------------------------------------------


def test_secret_protection(tmp_path: Path) -> None:
    secret = "my-super-secret-token-do-not-leak"
    cache = ReasoningCache(cache_dir=tmp_path)
    bundle = make_test_bundle()
    valid_report = sample_valid_report_dict(bundle)

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "message": {"role": "assistant", "content": json.dumps(valid_report)}
            },
        )

    transport = httpx.MockTransport(mock_handler)
    client = httpx.Client(transport=transport)

    provider = OllamaCloudProvider(
        model="test-model",
        api_key=secret,
        client=client,
        cache=cache,
    )

    # Key must not be in repr
    assert secret not in repr(provider)

    provider.investigate(bundle)

    # Key must not appear in any cache file on disk
    for cached_file in tmp_path.rglob("*.json"):
        content = cached_file.read_text(encoding="utf-8")
        assert secret not in content


# ---------------------------------------------------------------------------
# Test 10: App Works Unchanged Switching Between Mock and Ollama-Cloud
# ---------------------------------------------------------------------------


def test_orchestrator_switching_between_mock_and_ollama(tmp_path: Path) -> None:
    bundle = make_test_bundle()
    valid_report = sample_valid_report_dict(bundle)

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "message": {"role": "assistant", "content": json.dumps(valid_report)}
            },
        )

    transport = httpx.MockTransport(mock_handler)
    client = httpx.Client(transport=transport)

    # 1. Run with MockProvider
    mock_prov = MockProvider(replay_sequence=[Report.model_validate(valid_report)])
    orch_mock = ReasoningOrchestrator(provider=mock_prov)
    rep_mock = orch_mock.investigate(bundle)
    assert isinstance(rep_mock, Report)
    assert rep_mock.is_fallback is False

    # 2. Run with OllamaCloudProvider
    ollama_prov = OllamaCloudProvider(
        model="test-cloud-model:31b",
        api_key="valid-key",
        client=client,
    )
    orch_ollama = ReasoningOrchestrator(provider=ollama_prov)
    rep_ollama = orch_ollama.investigate(bundle)
    assert isinstance(rep_ollama, Report)
    assert rep_ollama.is_fallback is False
    assert rep_ollama.metadata.provider == "ollama-cloud"


def test_cli_investigate_switching_providers(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = make_test_bundle()
    bundle_file = tmp_path / "bundle.json"
    bundle_file.write_text(bundle.model_dump_json(indent=2), encoding="utf-8")

    # CLI with mock provider
    exit_mock = main(["investigate", "--input", str(bundle_file), "--provider", "mock"])
    assert exit_mock == 0
    captured_mock = capsys.readouterr()
    rep_mock = json.loads(captured_mock.out)
    assert rep_mock["risk_tier"] in ("low", "review", "high", "inconclusive")

    # CLI with ollama-cloud without key falls back gracefully to rules-only report
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    exit_ollama = main(
        [
            "investigate",
            "--input",
            str(bundle_file),
            "--provider",
            "ollama-cloud",
            "--model",
            "test-model",
        ]
    )
    assert exit_ollama == 0
    captured_ollama = capsys.readouterr()
    rep_ollama = json.loads(captured_ollama.out)
    assert rep_ollama["is_fallback"] is True
    assert rep_ollama["metadata"]["provider"] == "rules_only_fallback"
