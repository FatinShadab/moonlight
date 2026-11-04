"""Wire-level simulated-endpoint tests for MetaProvider and partner endpoints.

These tests run against a local loopback HTTP server (stdlib ThreadingHTTPServer)
emulating the Chat Completions endpoint. They test real socket I/O, actual TCP
connections, HTTP request serialization, response headers, status codes, timeouts,
and retries WITHOUT requiring live Meta API credentials or internet access.

IMPORTANT: These tests are simulated-endpoint tests, NOT live API results.
"""

from __future__ import annotations

import http.server
import json
import threading
import time
from collections.abc import Generator
from datetime import UTC, datetime
from typing import Any

import pytest

from moonlight.cli import main
from moonlight.core.evidence import (
    EvidenceBundle,
    EvidenceItem,
    EvidenceKind,
    SeverityHint,
    make_evidence_id,
)
from moonlight.reasoning.cache import ReasoningCache
from moonlight.reasoning.exceptions import (
    InvalidApiKeyError,
    MalformedOutputError,
    ProviderTimeoutError,
    ReasoningProviderError,
)
from moonlight.reasoning.orchestrator import ReasoningOrchestrator
from moonlight.reasoning.prompting import PROMPT_VERSION
from moonlight.reasoning.provider import MetaProvider


def make_test_bundle() -> EvidenceBundle:
    timestamp = datetime(2026, 11, 4, 12, 0, 0, tzinfo=UTC)
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
            value={"path": "C:/Windows/System32/notepad.exe"},
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
    return EvidenceBundle(subject_type="process", subject_id="5000", items=tuple(items))


def sample_valid_report_dict() -> dict[str, Any]:
    return {
        "summary": (
            "Verified Windows Notepad application with valid Microsoft signature."
        ),
        "risk_tier": "low",
        "confidence": 0.99,
        "observed_facts": [
            {
                "text": "Executable path is notepad.exe citing alias E1.",
                "evidence_ids": ["E1"],
            },
            {
                "text": "Binary signature is verified citing alias E2.",
                "evidence_ids": ["E2"],
            },
        ],
        "hypotheses": [
            {
                "text": "Standard benign Windows text editor.",
                "evidence_ids": ["E1", "E2"],
                "likelihood": "high",
            }
        ],
        "benign_explanations": ["Built-in standard Windows accessory."],
        "missing_evidence": [],
        "recommended_actions": [
            {
                "action_id": "mark_reviewed",
                "reason": "Verified Microsoft signed binary.",
                "evidence_ids": ["E1"],
            }
        ],
        "uncertainty_notes": "No anomalies identified.",
        "metadata": {
            "provider": "meta",
            "model": "muse-spark-1.3",
            "prompt_version": PROMPT_VERSION,
            "timestamp": "2026-11-04T12:00:00Z",
        },
    }


class SimulatedMetaServerState:
    """Shared state for controlling simulated Meta / partner endpoint responses."""

    def __init__(self) -> None:
        self.received_requests: list[dict[str, Any]] = []
        self.response_queue: list[tuple[int, dict[str, str], bytes]] = []
        self.default_response_status = 200
        self.default_response_body: bytes = b""
        self.response_delay = 0.0

    def set_default_success_report(self, report_dict: dict[str, Any]) -> None:
        payload = {
            "id": "chatcmpl-simulated-123",
            "object": "chat.completion",
            "created": 1730718000,
            "model": "muse-spark-1.3",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": json.dumps(report_dict),
                    },
                    "finish_reason": "stop",
                }
            ],
        }
        self.default_response_status = 200
        self.default_response_body = json.dumps(payload).encode("utf-8")


class SimulatedMetaHTTPHandler(http.server.BaseHTTPRequestHandler):
    """HTTP Request handler emulating OpenAI-compatible /v1/chat/completions."""

    server_state: SimulatedMetaServerState

    def log_message(self, format: str, *args: Any) -> None:
        # Silence standard HTTP access logging during tests
        pass

    def do_POST(self) -> None:  # noqa: N802
        if self.server_state.response_delay > 0.0:
            time.sleep(self.server_state.response_delay)

        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length) if length > 0 else b""
        parsed_body: Any = None
        try:
            parsed_body = json.loads(raw_body.decode("utf-8"))
        except Exception:
            parsed_body = raw_body

        req_record = {
            "path": self.path,
            "headers": dict(self.headers),
            "body": parsed_body,
        }
        self.server_state.received_requests.append(req_record)

        if self.server_state.response_queue:
            status, extra_headers, body_bytes = self.server_state.response_queue.pop(0)
        else:
            status = self.server_state.default_response_status
            extra_headers = {"Content-Type": "application/json"}
            body_bytes = self.server_state.default_response_body

        self.send_response(status)
        for h_k, h_v in extra_headers.items():
            self.send_header(h_k, h_v)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)


@pytest.fixture
def simulated_meta_server() -> Generator[
    tuple[str, SimulatedMetaServerState], None, None
]:
    """Launch local TCP HTTP server emulating Meta Model API."""
    state = SimulatedMetaServerState()
    state.set_default_success_report(sample_valid_report_dict())

    class CustomHandler(SimulatedMetaHTTPHandler):
        server_state = state

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CustomHandler)
    base_url = f"http://127.0.0.1:{server.server_port}/v1"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        yield base_url, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


# ===========================================================================
# 1. Success with JSON Schema Structured Output
# ===========================================================================


def test_simulated_endpoint_success_with_json_schema(
    simulated_meta_server: tuple[str, SimulatedMetaServerState],
) -> None:
    """Prove wire-level success against simulated endpoint with json_schema."""
    base_url, state = simulated_meta_server
    bundle = make_test_bundle()

    provider = MetaProvider(
        base_url=base_url,
        api_key="sk-meta-test-secret-key",
        model="muse-spark-1.3",
        cache=ReasoningCache(enabled=False),
    )

    report = provider.investigate(bundle)

    # 1. Validate returned report properties
    assert report.summary.startswith("Verified Windows Notepad")
    assert report.risk_tier == "low"
    assert report.confidence == 0.99
    assert report.metadata.provider == "meta"
    assert report.metadata.model == "muse-spark-1.3"
    assert len(report.observed_facts) == 2

    # 2. Verify exact wire-level request sent to simulated endpoint
    assert len(state.received_requests) == 1
    req = state.received_requests[0]
    assert req["path"] == "/v1/chat/completions"
    assert req["headers"]["Authorization"] == "Bearer sk-meta-test-secret-key"

    body = req["body"]
    assert body["model"] == "muse-spark-1.3"
    assert "response_format" in body
    rf = body["response_format"]
    assert rf["type"] == "json_schema"
    assert rf["json_schema"]["name"] == "InvestigationReport"
    assert rf["json_schema"]["strict"] is True
    assert isinstance(rf["json_schema"]["schema"], dict)


# ===========================================================================
# 2. Malformed JSON Response Body
# ===========================================================================


def test_simulated_endpoint_malformed_json(
    simulated_meta_server: tuple[str, SimulatedMetaServerState],
) -> None:
    """Prove MalformedOutputError when endpoint returns unparseable content."""
    base_url, state = simulated_meta_server
    bundle = make_test_bundle()

    bad_payload = {
        "id": "chatcmpl-bad-1",
        "choices": [{"message": {"content": "not_valid_json{{{"}}],
    }
    state.response_queue.append(
        (200, {"Content-Type": "application/json"}, json.dumps(bad_payload).encode())
    )

    provider = MetaProvider(
        base_url=base_url,
        api_key="sk-test-key",
        cache=ReasoningCache(enabled=False),
    )

    with pytest.raises(MalformedOutputError, match="Failed to parse report content"):
        provider.investigate(bundle)


# ===========================================================================
# 3. Schema Violation Handling
# ===========================================================================


def test_simulated_endpoint_schema_violation(
    simulated_meta_server: tuple[str, SimulatedMetaServerState],
) -> None:
    """Prove MalformedOutputError when model returns JSON missing required fields."""
    base_url, state = simulated_meta_server
    bundle = make_test_bundle()

    bad_schema_report = {"random_key": "some_value"}
    payload = {
        "id": "chatcmpl-bad-schema",
        "choices": [{"message": {"content": json.dumps(bad_schema_report)}}],
    }
    state.response_queue.append(
        (200, {"Content-Type": "application/json"}, json.dumps(payload).encode())
    )

    provider = MetaProvider(
        base_url=base_url,
        api_key="sk-test-key",
        cache=ReasoningCache(enabled=False),
    )

    with pytest.raises(MalformedOutputError, match="failed schema validation"):
        provider.investigate(bundle)


# ===========================================================================
# 4. HTTP 401 Unauthorized (Invalid API Key)
# ===========================================================================


def test_simulated_endpoint_401_unauthorized(
    simulated_meta_server: tuple[str, SimulatedMetaServerState],
) -> None:
    """Prove InvalidApiKeyError on 401 without wasteful retry loops."""
    base_url, state = simulated_meta_server
    bundle = make_test_bundle()

    err_payload = {
        "error": {
            "message": "Invalid API key provided",
            "type": "invalid_request_error",
        }
    }
    state.response_queue.append(
        (401, {"Content-Type": "application/json"}, json.dumps(err_payload).encode())
    )

    provider = MetaProvider(
        base_url=base_url,
        api_key="sk-bad-token",
        max_retries=3,
        cache=ReasoningCache(enabled=False),
    )

    with pytest.raises(InvalidApiKeyError, match="Meta API key invalid \\(401\\)"):
        provider.investigate(bundle)

    # 401 must fail immediately on attempt 0 (no retries)
    assert len(state.received_requests) == 1


# ===========================================================================
# 5. HTTP 403 Forbidden (Model Access Denied)
# ===========================================================================


def test_simulated_endpoint_403_forbidden(
    simulated_meta_server: tuple[str, SimulatedMetaServerState],
) -> None:
    """Prove InvalidApiKeyError on 403 without retries."""
    base_url, state = simulated_meta_server
    bundle = make_test_bundle()

    err_payload = {
        "error": {
            "message": "Model access forbidden for current key",
            "type": "permission_error",
        }
    }
    state.response_queue.append(
        (403, {"Content-Type": "application/json"}, json.dumps(err_payload).encode())
    )

    provider = MetaProvider(
        base_url=base_url,
        api_key="sk-no-perms",
        max_retries=2,
        cache=ReasoningCache(enabled=False),
    )

    with pytest.raises(InvalidApiKeyError, match="Meta API key invalid \\(403\\)"):
        provider.investigate(bundle)

    assert len(state.received_requests) == 1


# ===========================================================================
# 6. HTTP 429 Rate Limit with Retry-After Header and Recovery
# ===========================================================================


def test_simulated_endpoint_429_retry_then_success(
    simulated_meta_server: tuple[str, SimulatedMetaServerState],
) -> None:
    """Prove rate limit backoff honors Retry-After header and succeeds on retry."""
    base_url, state = simulated_meta_server
    bundle = make_test_bundle()

    rate_limit_payload = {
        "error": {
            "message": "Rate limit exceeded. Please wait.",
            "type": "rate_limit_exceeded",
        }
    }
    # Call 1: 429 with Retry-After: 0.05
    state.response_queue.append(
        (
            429,
            {"Content-Type": "application/json", "Retry-After": "0.05"},
            json.dumps(rate_limit_payload).encode(),
        )
    )
    # Call 2: Default 200 success

    slept_intervals: list[float] = []

    provider = MetaProvider(
        base_url=base_url,
        api_key="sk-test",
        max_retries=2,
        sleep_fn=slept_intervals.append,
        cache=ReasoningCache(enabled=False),
    )

    report = provider.investigate(bundle)

    assert report.summary.startswith("Verified Windows Notepad")
    assert len(state.received_requests) == 2
    assert len(slept_intervals) == 1
    assert slept_intervals[0] == pytest.approx(0.05)


# ===========================================================================
# 7. HTTP 500 Server Error Exhaustion
# ===========================================================================


def test_simulated_endpoint_500_server_error_exhaustion(
    simulated_meta_server: tuple[str, SimulatedMetaServerState],
) -> None:
    """Prove bounded retries on 500 raise ReasoningProviderError when exhausted."""
    base_url, state = simulated_meta_server
    bundle = make_test_bundle()

    server_err = {
        "error": {"message": "Internal inference error", "type": "server_error"}
    }
    for _ in range(3):
        state.response_queue.append(
            (500, {"Content-Type": "application/json"}, json.dumps(server_err).encode())
        )

    provider = MetaProvider(
        base_url=base_url,
        api_key="sk-test",
        max_retries=2,
        sleep_fn=lambda _: None,
        cache=ReasoningCache(enabled=False),
    )

    with pytest.raises(ReasoningProviderError, match="Meta server error \\(500\\)"):
        provider.investigate(bundle)

    # 1 initial + 2 retries = 3 requests total
    assert len(state.received_requests) == 3


# ===========================================================================
# 8. Timeout Handling
# ===========================================================================


def test_simulated_endpoint_timeout(
    simulated_meta_server: tuple[str, SimulatedMetaServerState],
) -> None:
    """Prove ProviderTimeoutError when simulated endpoint hangs beyond timeout."""
    base_url, state = simulated_meta_server
    bundle = make_test_bundle()

    # Server sleeps for 0.4s while client timeout is 0.1s
    state.response_delay = 0.4

    provider = MetaProvider(
        base_url=base_url,
        api_key="sk-test",
        timeout=0.1,
        max_retries=1,
        sleep_fn=lambda _: None,
        cache=ReasoningCache(enabled=False),
    )

    with pytest.raises(ProviderTimeoutError, match="timed out"):
        provider.investigate(bundle)


# ===========================================================================
# 9. Partner-Style Base URL & Model (e.g. Baseten Muse Spark Open)
# ===========================================================================


def test_simulated_endpoint_partner_baseten_url_and_model(
    simulated_meta_server: tuple[str, SimulatedMetaServerState],
) -> None:
    """Prove MetaProvider works with partner endpoint URLs and model names."""
    base_url, state = simulated_meta_server
    bundle = make_test_bundle()

    # Configure partner-style model
    partner_model = "meta-models/muse-spark-open-1026"
    partner_key = "baseten_live_test_key_12345"

    provider = MetaProvider(
        base_url=base_url,
        model=partner_model,
        api_key=partner_key,
        cache=ReasoningCache(enabled=False),
    )

    report = provider.investigate(bundle)

    assert report.metadata.model == partner_model
    assert len(state.received_requests) == 1
    req = state.received_requests[0]
    assert req["body"]["model"] == partner_model
    assert req["headers"]["Authorization"] == f"Bearer {partner_key}"


# ===========================================================================
# 10. Orchestrator Self-Healing & Safe Fallback on Simulated Endpoint
# ===========================================================================


def test_simulated_endpoint_orchestrator_repair_then_fallback(
    simulated_meta_server: tuple[str, SimulatedMetaServerState],
) -> None:
    """Prove orchestrator runs 1 repair attempt, then falls back safely to rules."""
    base_url, state = simulated_meta_server
    bundle = make_test_bundle()

    # Attempt 1 returns schema violation
    bad_payload = {
        "id": "chatcmpl-bad",
        "choices": [{"message": {"content": json.dumps({"bad": "data"})}}],
    }
    state.response_queue.append(
        (200, {"Content-Type": "application/json"}, json.dumps(bad_payload).encode())
    )

    # Attempt 2 (repair retry) returns valid report
    valid_payload = {
        "id": "chatcmpl-repaired",
        "choices": [{"message": {"content": json.dumps(sample_valid_report_dict())}}],
    }
    state.response_queue.append(
        (200, {"Content-Type": "application/json"}, json.dumps(valid_payload).encode())
    )

    provider = MetaProvider(
        base_url=base_url,
        api_key="sk-test",
        cache=ReasoningCache(enabled=False),
    )
    orchestrator = ReasoningOrchestrator(provider=provider)

    repaired_report = orchestrator.investigate(bundle)

    assert repaired_report.is_fallback is False
    assert len(state.received_requests) == 2
    # Verify the second request had repair instructions
    req2 = state.received_requests[1]
    assert "Previous attempt failed" in req2["body"]["messages"][1]["content"]

    # Now test scenario where BOTH initial call and repair retry fail
    state.received_requests.clear()
    state.response_queue.append(
        (200, {"Content-Type": "application/json"}, json.dumps(bad_payload).encode())
    )
    state.response_queue.append(
        (200, {"Content-Type": "application/json"}, json.dumps(bad_payload).encode())
    )

    fallback_report = orchestrator.investigate(bundle)

    assert fallback_report.is_fallback is True
    assert fallback_report.metadata.provider == "rules_only_fallback"
    assert "Repair retry provider error" in (fallback_report.fallback_reason or "")


# ===========================================================================
# 11. Secret Redaction from Endpoint Exceptions
# ===========================================================================


def test_simulated_endpoint_secret_redaction(
    simulated_meta_server: tuple[str, SimulatedMetaServerState],
) -> None:
    """Prove API keys and Bearer tokens are scrubbed from exception messages."""
    base_url, state = simulated_meta_server
    bundle = make_test_bundle()

    leaked_token = "sk-super-secret-auth-token-12345678"
    err_body = {"error": f"Authentication failed with Bearer {leaked_token}."}
    state.response_queue.append(
        (401, {"Content-Type": "application/json"}, json.dumps(err_body).encode())
    )

    provider = MetaProvider(
        base_url=base_url,
        api_key=leaked_token,
        cache=ReasoningCache(enabled=False),
    )

    with pytest.raises(InvalidApiKeyError) as exc_info:
        provider.investigate(bundle)

    exc_text = str(exc_info.value)
    assert leaked_token not in exc_text
    assert "[REDACTED_SECRET]" in exc_text


# ===========================================================================
# 12. CLI provider-check against Simulated Endpoint
# ===========================================================================


def test_simulated_endpoint_provider_check_cli(
    simulated_meta_server: tuple[str, SimulatedMetaServerState],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prove moonlight provider-check succeeds against an active simulated endpoint."""
    base_url, _ = simulated_meta_server

    monkeypatch.setenv("MODEL_API_KEY", "sk-valid-simulated-key")
    monkeypatch.setenv("MOONLIGHT_META_BASE_URL", base_url)
    monkeypatch.setenv("MOONLIGHT_META_MODEL", "muse-spark-1.3")

    exit_code = main(["provider-check", "--provider", "meta"])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Provider : meta" in captured.out
    assert "Status   : OK (connected)" in captured.out
    assert "Model    : muse-spark-1.3" in captured.out
    assert "Latency  :" in captured.out
