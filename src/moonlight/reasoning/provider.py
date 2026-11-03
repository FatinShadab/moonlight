"""ReportProvider protocol and implementations: Mock, OllamaCloud, Meta."""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.parse
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

import httpx
from pydantic import BaseModel, ConfigDict, Field

from moonlight.core.evidence import EvidenceBundle
from moonlight.minimizer.models import MinimizedBundle, ModelPayload
from moonlight.reasoning.cache import ReasoningCache, compute_payload_hash
from moonlight.reasoning.exceptions import (
    InvalidApiKeyError,
    MalformedOutputError,
    MissingApiKeyError,
    ProviderTimeoutError,
    RateLimitError,
    ReasoningProviderError,
    UnknownModelError,
)
from moonlight.reasoning.grounding import (
    validate_grounding,
    validate_grounding_or_raise,
)
from moonlight.reasoning.models import REPORT_SCHEMA_VERSION, Report
from moonlight.reasoning.prompting import (
    PROMPT_VERSION,
    build_investigation_prompt,
    remap_report_citations,
)

logger = logging.getLogger(__name__)

ProviderType = Literal["mock", "ollama", "ollama-cloud", "meta"]

_DEFAULT_FIXTURES_DIR = Path(__file__).resolve().parents[3] / "fixtures" / "reports"


@runtime_checkable
class ReportProvider(Protocol):
    """Protocol for providers that perform reasoning over minimized payloads."""

    def investigate(
        self,
        minimized_payload: ModelPayload | EvidenceBundle | dict[str, Any] | str,
        *,
        repair_instruction: str | None = None,
    ) -> Report:
        """Produce an investigation report from a minimized evidence payload.

        Args:
            minimized_payload: The minimized evidence payload.
            repair_instruction: Optional feedback from prior failed validation.

        Returns:
            A schema-validated Report.
        """
        ...


class MockProvider:
    """Offline mock provider that replays reports from fixtures/reports/."""

    def __init__(
        self,
        fixtures_dir: Path | str | None = None,
        default_fixture: str = "default.json",
        replay_sequence: (
            Sequence[Report | dict[str, Any] | str | Exception] | None
        ) = None,
    ) -> None:
        self.fixtures_dir = (
            Path(fixtures_dir) if fixtures_dir else _DEFAULT_FIXTURES_DIR
        )
        self.default_fixture = default_fixture
        self._replay_queue: list[Report | dict[str, Any] | str | Exception] = (
            list(replay_sequence) if replay_sequence is not None else []
        )

    def queue_response(
        self, response: Report | dict[str, Any] | str | Exception
    ) -> None:
        """Enqueue a canned response or exception for successive calls."""
        self._replay_queue.append(response)

    def investigate(
        self,
        minimized_payload: ModelPayload | EvidenceBundle | dict[str, Any] | str,
        *,
        repair_instruction: str | None = None,
    ) -> Report:
        """Replay a report from the replay queue or fixtures directory."""
        if self._replay_queue:
            item = self._replay_queue.pop(0)
            if isinstance(item, Exception):
                raise item
            if isinstance(item, Report):
                return item
            if isinstance(item, dict):
                return Report.model_validate(item)
            if isinstance(item, str):
                return Report.model_validate_json(item)

        if not self.fixtures_dir.exists():
            raise FileNotFoundError(
                f"Mock reports directory not found: {self.fixtures_dir}"
            )

        target_file: Path | None = None

        if repair_instruction:
            candidate_repair = self.fixtures_dir / "repair_report.json"
            if candidate_repair.exists():
                target_file = candidate_repair

        if target_file is None:
            subject: str | None = None
            if (
                isinstance(minimized_payload, ModelPayload)
                and minimized_payload.untrusted_evidence
            ):
                subject = minimized_payload.untrusted_evidence[0].subject
            elif (
                isinstance(minimized_payload, dict)
                and "untrusted_evidence" in minimized_payload
            ):
                bundles = minimized_payload["untrusted_evidence"]
                if (
                    isinstance(bundles, list)
                    and bundles
                    and isinstance(bundles[0], dict)
                ):
                    subject = str(bundles[0].get("subject", ""))

            if subject:
                candidate_subject = self.fixtures_dir / f"{subject}.json"
                if candidate_subject.exists():
                    target_file = candidate_subject

        if target_file is None:
            target_file = self.fixtures_dir / self.default_fixture

        if not target_file.exists():
            json_files = list(self.fixtures_dir.glob("*.json"))
            if json_files:
                target_file = json_files[0]
            else:
                raise FileNotFoundError(
                    f"No fixture report found in {self.fixtures_dir} "
                    f"(looked for {self.default_fixture})"
                )

        content = target_file.read_text(encoding="utf-8")
        return Report.model_validate_json(content)


def _extract_error_message(response: httpx.Response) -> str:
    """Safely extract error string from HTTP response without leaking secrets."""
    try:
        data = response.json()
        if isinstance(data, dict):
            if "error" in data:
                err = data["error"]
                if isinstance(err, dict):
                    return str(err.get("message", err))
                return str(err)
            if "message" in data:
                return str(data["message"])
    except Exception:
        pass
    return response.text[:200]


def _coerce_evidence_payload(
    payload: (
        EvidenceBundle
        | ModelPayload
        | MinimizedBundle
        | Sequence[EvidenceBundle]
        | Sequence[MinimizedBundle]
        | dict[str, Any]
        | str
    ),
) -> (
    EvidenceBundle
    | ModelPayload
    | MinimizedBundle
    | Sequence[EvidenceBundle]
    | Sequence[MinimizedBundle]
):
    """Coerce payload into a type accepted by prompt builders."""
    if isinstance(payload, (EvidenceBundle, ModelPayload, MinimizedBundle)):
        return payload
    if isinstance(payload, Sequence) and not isinstance(payload, (str, bytes)):
        return payload
    if isinstance(payload, str):
        try:
            parsed = json.loads(payload)
            if isinstance(parsed, dict):
                if "untrusted_evidence" in parsed:
                    return ModelPayload.model_validate(parsed)
                if "items" in parsed:
                    return EvidenceBundle.model_validate(parsed)
        except Exception:
            pass
    elif isinstance(payload, dict):
        try:
            if "untrusted_evidence" in payload:
                return ModelPayload.model_validate(payload)
            if "items" in payload:
                return EvidenceBundle.model_validate(payload)
        except Exception:
            pass
    # If not coercible, wrap in an empty ModelPayload container
    return ModelPayload(untrusted_evidence=())


class OllamaCloudProvider:
    """Temporary stand-in provider calling Ollama's hosted API.

    Development placeholder only; the final system uses MetaProvider.
    Features:
    - Calls https://ollama.com/api/chat with Bearer auth
    - Base URL requires HTTPS and defaults to https://ollama.com
    - Rejects non-ollama.com hosts unless allow_custom_host is explicitly True
    - Never follows redirects (follow_redirects=False)
    - Schema JSON output with 1-time fallback to plain JSON on 400 unsupported format
    - Bounded retries for 429 and timeouts (Retry-After capped at 30s)
    - Total retry delay strictly bounded by max_total_retry_time
    - Response cache keyed by (provider, model, hash, prompt_ver, schema, mode)
    - Re-validates grounding of cached reports on read and discards invalid ones
    - Records provider ('ollama-cloud'), model, and mode in Report metadata
    - Never logs or exposes API keys
    """

    def __init__(
        self,
        model: str | None = None,
        base_url: str = "https://ollama.com",
        timeout: float = 30.0,
        max_retries: int = 2,
        backoff_factor: float = 0.5,
        max_total_retry_time: float = 60.0,
        format_schema: bool = True,
        allow_custom_host: bool = False,
        cache: ReasoningCache | None = None,
        prompt_version: str = PROMPT_VERSION,
        report_schema_version: str = REPORT_SCHEMA_VERSION,
        client: httpx.Client | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        api_key: str | None = None,
    ) -> None:
        self.model = model or os.environ.get("OLLAMA_MODEL", "")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.max_total_retry_time = max_total_retry_time
        self.format_schema = format_schema
        self.allow_custom_host = allow_custom_host
        self.cache = cache or ReasoningCache()
        self.prompt_version = prompt_version
        self.report_schema_version = report_schema_version
        self._client = client
        self._sleep_fn = sleep_fn
        # The key is read only from environment (or explicit non-logged param)
        self._api_key = api_key

        # Validate base_url: HTTPS required, host ollama.com unless allow_custom_host
        parsed = urllib.parse.urlparse(self.base_url)
        if parsed.scheme.lower() != "https":
            raise ValueError(
                f"Ollama base URL must use HTTPS scheme (got {self.base_url!r})"
            )
        host = (parsed.hostname or "").lower()
        if host != "ollama.com" and not self.allow_custom_host:
            raise ValueError(
                "Ollama base URL host must be 'ollama.com' unless "
                f"allow_custom_host=True (got {host!r})"
            )

        # Enforce that client does not follow redirects
        if self._client is not None and getattr(
            self._client, "follow_redirects", False
        ):
            raise ValueError(
                "Ollama client must not follow redirects "
                "(follow_redirects must be False)"
            )

    def __repr__(self) -> str:
        # Never expose the API key in representations
        return (
            f"OllamaCloudProvider(model={self.model!r}, "
            f"base_url={self.base_url!r}, timeout={self.timeout})"
        )

    def _get_api_key(self) -> str:
        key = self._api_key or os.environ.get("OLLAMA_API_KEY", "")
        if not key.strip():
            raise MissingApiKeyError(
                "OLLAMA_API_KEY environment variable is missing or empty"
            )
        return key.strip()

    def _compute_backoff(
        self, attempt: int, response: httpx.Response | None = None
    ) -> float:
        if response is not None and "Retry-After" in response.headers:
            try:
                seconds = float(response.headers["Retry-After"])
                if seconds > 0:
                    return min(seconds, 30.0)
            except ValueError:
                pass
        backoff = float(self.backoff_factor * (2**attempt))
        return min(backoff, 30.0)

    def investigate(
        self,
        minimized_payload: ModelPayload | EvidenceBundle | dict[str, Any] | str,
        *,
        repair_instruction: str | None = None,
    ) -> Report:
        """Call Ollama Cloud API and return a validated, grounded Report."""
        api_key = self._get_api_key()

        if not self.model.strip():
            raise UnknownModelError(
                "Ollama model name is required; set OLLAMA_MODEL environment variable "
                "or pass model to OllamaCloudProvider."
            )

        evidence = _coerce_evidence_payload(minimized_payload)
        system_prompt, user_prompt, alias_map = build_investigation_prompt(evidence)

        if repair_instruction:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": repair_instruction},
            ]
        else:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]

        payload_hash = compute_payload_hash(messages)
        self.cache.record_request("ollama-cloud")

        initial_mode = "schema" if self.format_schema else "json"

        # Check cache: must be re-validated by grounding validator on read
        cached_content = self.cache.get(
            provider="ollama-cloud",
            model=self.model,
            payload_hash=payload_hash,
            prompt_version=self.prompt_version,
            report_schema_version=self.report_schema_version,
            structured_output_mode=initial_mode,
        )
        if cached_content is not None:
            self.cache.record_hit("ollama-cloud", self.model)
            try:
                cached_report = Report.model_validate_json(cached_content)
                remapped = remap_report_citations(cached_report, alias_map)
                grounding_res = validate_grounding(remapped, evidence)
                if not grounding_res.is_valid:
                    logger.warning(
                        "Cached report failed grounding validation: %s; "
                        "discarding cached report",
                        grounding_res.errors,
                    )
                    self.cache.invalidate(
                        provider="ollama-cloud",
                        model=self.model,
                        payload_hash=payload_hash,
                        prompt_version=self.prompt_version,
                        report_schema_version=self.report_schema_version,
                        structured_output_mode=initial_mode,
                    )
                else:
                    return remapped
            except Exception as exc:
                logger.warning("Cached report validation failed: %s; refetching", exc)
                self.cache.invalidate(
                    provider="ollama-cloud",
                    model=self.model,
                    payload_hash=payload_hash,
                    prompt_version=self.prompt_version,
                    report_schema_version=self.report_schema_version,
                    structured_output_mode=initial_mode,
                )

        self.cache.record_miss("ollama-cloud", self.model)

        mode_used = initial_mode
        request_body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
        }
        if mode_used == "schema":
            request_body["format"] = Report.model_json_schema()
        else:
            request_body["format"] = "json"

        endpoint = f"{self.base_url}/api/chat"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        response: httpx.Response | None = None
        owns_client = self._client is None
        client = self._client or httpx.Client(
            timeout=self.timeout, follow_redirects=False
        )

        total_retry_time: float = 0.0

        def check_and_sleep(
            sleep_sec: float, exc_on_exceeded: Exception | None = None
        ) -> None:
            nonlocal total_retry_time
            if total_retry_time + sleep_sec > self.max_total_retry_time:
                if exc_on_exceeded is not None:
                    raise exc_on_exceeded
                raise RateLimitError(
                    f"Total retry delay ({total_retry_time + sleep_sec:.1f}s) "
                    f"exceeded maximum allowed limit ({self.max_total_retry_time}s)"
                )
            total_retry_time += sleep_sec
            self._sleep_fn(sleep_sec)

        schema_fallback_attempted = False

        try:
            for attempt in range(self.max_retries + 1):
                try:
                    response = client.post(
                        endpoint,
                        headers=headers,
                        json=request_body,
                        timeout=self.timeout,
                    )

                    # Never follow redirects
                    if 300 <= response.status_code < 400:
                        raise ReasoningProviderError(
                            f"Ollama redirect ({response.status_code}) refused; "
                            "redirects are disabled."
                        )

                    if response.status_code == 200:
                        break

                    if response.status_code in (401, 403):
                        err_msg = _extract_error_message(response)
                        raise InvalidApiKeyError(
                            f"Ollama API key invalid ({response.status_code}): "
                            f"{err_msg}"
                        )

                    if response.status_code == 404:
                        err_msg = _extract_error_message(response)
                        raise UnknownModelError(
                            f"Ollama model '{self.model}' unknown (404): {err_msg}"
                        )

                    if response.status_code == 429:
                        if attempt < self.max_retries:
                            sleep_sec = self._compute_backoff(attempt, response)
                            check_and_sleep(sleep_sec)
                            continue
                        err_msg = _extract_error_message(response)
                        raise RateLimitError(
                            f"Ollama rate limit exceeded (429) after "
                            f"{self.max_retries} retries: {err_msg}"
                        )

                    if response.status_code == 400:
                        err_msg = _extract_error_message(response)
                        # Fall back from schema to JSON mode only once on 400
                        # when error clearly indicates format is unsupported.
                        is_unsupported_format = any(
                            keyword in err_msg.lower()
                            for keyword in ("format", "schema", "unsupported")
                        )
                        if (
                            mode_used == "schema"
                            and not schema_fallback_attempted
                            and is_unsupported_format
                        ):
                            schema_fallback_attempted = True
                            mode_used = "json"
                            request_body["format"] = "json"
                            logger.info(
                                "Falling back from schema to JSON mode after 400: %s",
                                err_msg,
                            )
                            response = client.post(
                                endpoint,
                                headers=headers,
                                json=request_body,
                                timeout=self.timeout,
                            )
                            if response.status_code == 200:
                                break
                            err_msg = _extract_error_message(response)
                        raise ReasoningProviderError(
                            f"Ollama request error (400): {err_msg}"
                        )

                    if response.status_code >= 500:
                        if attempt < self.max_retries:
                            sleep_sec = self._compute_backoff(attempt, response)
                            check_and_sleep(sleep_sec)
                            continue
                        err_msg = _extract_error_message(response)
                        raise ReasoningProviderError(
                            f"Ollama server error ({response.status_code}): {err_msg}"
                        )

                    err_msg = _extract_error_message(response)
                    raise ReasoningProviderError(
                        f"Ollama unexpected HTTP status ({response.status_code}): "
                        f"{err_msg}"
                    )

                except httpx.TimeoutException as exc:
                    if attempt < self.max_retries:
                        sleep_sec = self._compute_backoff(attempt)
                        timeout_err = ProviderTimeoutError(
                            "Ollama request timed out; total retry time "
                            f"({total_retry_time + sleep_sec:.1f}s) exceeded limit: "
                            f"{exc}"
                        )
                        check_and_sleep(sleep_sec, exc_on_exceeded=timeout_err)
                        continue
                    raise ProviderTimeoutError(
                        f"Ollama request timed out after {self.timeout}s and "
                        f"{self.max_retries} retries: {exc}"
                    ) from exc
                except (
                    InvalidApiKeyError,
                    UnknownModelError,
                    RateLimitError,
                    ProviderTimeoutError,
                    ReasoningProviderError,
                ):
                    raise
                except httpx.RequestError as exc:
                    if attempt < self.max_retries:
                        sleep_sec = self._compute_backoff(attempt)
                        net_err = ReasoningProviderError(
                            "Network error contacting Ollama; total retry time "
                            f"({total_retry_time + sleep_sec:.1f}s) exceeded limit: "
                            f"{exc}"
                        )
                        check_and_sleep(sleep_sec, exc_on_exceeded=net_err)
                        continue
                    raise ReasoningProviderError(
                        f"Network error contacting Ollama: {exc}"
                    ) from exc
        finally:
            if owns_client:
                client.close()

        if response is None:
            raise ReasoningProviderError("No response received from Ollama API")

        # Parse response JSON
        try:
            resp_data = response.json()
        except Exception as exc:
            raise MalformedOutputError(
                f"Ollama response body is not valid JSON: {exc}"
            ) from exc

        if not isinstance(resp_data, dict):
            raise MalformedOutputError("Ollama response body must be a JSON object")

        message = resp_data.get("message")
        if not isinstance(message, dict) or "content" not in message:
            raise MalformedOutputError(
                "Ollama response missing expected 'message.content' field"
            )

        content_raw = message["content"]
        if not isinstance(content_raw, str):
            raise MalformedOutputError(
                "Ollama response 'message.content' must be a string"
            )

        try:
            report_dict = json.loads(content_raw)
        except Exception as exc:
            raise MalformedOutputError(
                f"Failed to parse report content from model as JSON: {exc}"
            ) from exc

        if not isinstance(report_dict, dict):
            raise MalformedOutputError("Model report content must be a JSON object")

        # Ensure metadata records provider, model, and structured_output_mode
        metadata_dict = report_dict.get("metadata")
        if not isinstance(metadata_dict, dict):
            metadata_dict = {}
        metadata_dict["provider"] = "ollama-cloud"
        metadata_dict["model"] = self.model
        metadata_dict["structured_output_mode"] = mode_used
        if "prompt_version" not in metadata_dict:
            metadata_dict["prompt_version"] = self.prompt_version
        if "timestamp" not in metadata_dict:
            metadata_dict["timestamp"] = datetime.now(UTC).isoformat()
        report_dict["metadata"] = metadata_dict

        try:
            report = Report.model_validate(report_dict)
        except Exception as exc:
            raise MalformedOutputError(
                f"Model report failed schema validation: {exc}"
            ) from exc

        remapped = remap_report_citations(report, alias_map)

        # Store in provider-segregated cache with schema version and output mode
        self.cache.set(
            provider="ollama-cloud",
            model=self.model,
            payload_hash=payload_hash,
            prompt_version=self.prompt_version,
            response_text=remapped.model_dump_json(),
            report_schema_version=self.report_schema_version,
            structured_output_mode=mode_used,
        )

        return remapped


def validate_schema_depth_and_recursion(
    schema: dict[str, Any], max_depth: int = 10
) -> None:
    """Validate that schema does not contain circular references and depth <= max_depth.

    Args:
        schema: A JSON schema dictionary.
        max_depth: Maximum allowed nesting depth (default: 10 per Meta API limit).

    Raises:
        ValueError: If a recursive circular reference is detected or
            nesting depth exceeds max_depth.
    """
    defs = schema.get("$defs", {}) or schema.get("definitions", {})

    def resolve_ref(ref_str: str) -> dict[str, Any]:
        if ref_str.startswith("#/$defs/"):
            name = ref_str[len("#/$defs/") :]
            target = defs.get(name)
            if isinstance(target, dict):
                return target
        elif ref_str.startswith("#/definitions/"):
            name = ref_str[len("#/definitions/") :]
            target = defs.get(name)
            if isinstance(target, dict):
                return target
        return {}

    def compute_depth(node: Any, visited_refs: frozenset[str]) -> int:
        if not isinstance(node, dict):
            return 0
        if "$ref" in node:
            ref = str(node["$ref"])
            if ref in visited_refs:
                raise ValueError(
                    f"Recursive schema detected: circular reference to {ref!r}"
                )
            target = resolve_ref(ref)
            return compute_depth(target, visited_refs | {ref})

        max_sub = 0
        for val in node.values():
            if isinstance(val, dict):
                max_sub = max(max_sub, 1 + compute_depth(val, visited_refs))
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, dict):
                        max_sub = max(max_sub, 1 + compute_depth(item, visited_refs))
        return max_sub

    depth = compute_depth(schema, frozenset())
    if depth > max_depth:
        raise ValueError(
            f"Schema nesting depth ({depth}) exceeds maximum allowed depth "
            f"of {max_depth}"
        )


class MetaProvider:
    """Production provider calling the Meta Model API chat completions endpoint.

    Features:
    - POST {base}/chat/completions (default: https://api.meta.ai/v1/chat/completions)
    - Bearer authorization with MODEL_API_KEY (or META_API_KEY)
    - Default model: muse-spark-1.3 (overridden by MOONLIGHT_META_MODEL or param)
    - Structured output: response_format with json_schema name InvestigationReport
    - Does NOT use text.format (Responses API)
    - Result is extracted from choices[0].message.content
    - Validates schema limits (no recursive schemas, nesting depth <= 10)
    - Plain HTTP client with injectable client/transport for offline unit tests
    - Bounded retries with exponential backoff for 429, 5xx, and timeouts
    - Non-retryable: 401 (InvalidApiKeyError), 404 (UnknownModelError),
      400 (ReasoningProviderError)
    - Missing key raises MissingApiKeyError (orchestrator fallback runs)
    - Runs schema validation and grounding checks (every cited evidence ID must exist)
    - Never logs or exposes API keys (redacted from logs, __repr__, and cache)
    """

    def __init__(
        self,
        model: str | None = None,
        base_url: str | None = None,
        timeout: float = 30.0,
        max_retries: int = 2,
        backoff_factor: float = 0.5,
        max_total_retry_time: float = 60.0,
        cache: ReasoningCache | None = None,
        prompt_version: str = PROMPT_VERSION,
        report_schema_version: str = REPORT_SCHEMA_VERSION,
        client: httpx.Client | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        api_key: str | None = None,
    ) -> None:
        self.model = (
            model
            or os.environ.get("MOONLIGHT_META_MODEL")
            or os.environ.get("META_MODEL")
            or "muse-spark-1.3"
        )
        raw_base = (
            base_url
            or os.environ.get("MOONLIGHT_META_BASE_URL")
            or os.environ.get("META_BASE_URL")
            or "https://api.meta.ai/v1"
        )
        self.base_url = raw_base.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.max_total_retry_time = max_total_retry_time
        self.cache = cache or ReasoningCache()
        self.prompt_version = prompt_version
        self.report_schema_version = report_schema_version
        self._sleep_fn = sleep_fn
        self._api_key = api_key

        self._client: httpx.Client | None
        if transport is not None and client is None:
            self._client = httpx.Client(transport=transport, timeout=self.timeout)
        else:
            self._client = client

        # Validate that the Report schema respects Meta's limits
        schema = Report.model_json_schema()
        validate_schema_depth_and_recursion(schema, max_depth=10)

    def __repr__(self) -> str:
        # Never expose the API key in representations
        return (
            f"MetaProvider(model={self.model!r}, "
            f"base_url={self.base_url!r}, timeout={self.timeout})"
        )

    def _get_api_key(self) -> str:
        key = (
            self._api_key
            or os.environ.get("MODEL_API_KEY")
            or os.environ.get("META_API_KEY", "")
        )
        if not key.strip():
            raise MissingApiKeyError(
                "MODEL_API_KEY environment variable is missing or empty"
            )
        return key.strip()

    def _compute_backoff(
        self, attempt: int, response: httpx.Response | None = None
    ) -> float:
        if response is not None and "Retry-After" in response.headers:
            try:
                seconds = float(response.headers["Retry-After"])
                if seconds > 0:
                    return min(seconds, 30.0)
            except ValueError:
                pass
        backoff = float(self.backoff_factor * (2**attempt))
        return min(backoff, 30.0)

    def investigate(
        self,
        minimized_payload: ModelPayload | EvidenceBundle | dict[str, Any] | str,
        *,
        repair_instruction: str | None = None,
    ) -> Report:
        """Call Meta Model API and return a validated, grounded Report."""
        api_key = self._get_api_key()

        if not self.model.strip():
            raise UnknownModelError(
                "Meta model name is required; set MOONLIGHT_META_MODEL "
                "environment variable or pass model to MetaProvider."
            )

        evidence = _coerce_evidence_payload(minimized_payload)
        system_prompt, user_prompt, alias_map = build_investigation_prompt(evidence)

        if repair_instruction:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": repair_instruction},
            ]
        else:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]

        payload_hash = compute_payload_hash(messages)
        self.cache.record_request("meta")

        # Check provider-segregated cache
        cached_content = self.cache.get(
            provider="meta",
            model=self.model,
            payload_hash=payload_hash,
            prompt_version=self.prompt_version,
            report_schema_version=self.report_schema_version,
            structured_output_mode="json_schema",
        )
        if cached_content is not None:
            self.cache.record_hit("meta", self.model)
            try:
                cached_report = Report.model_validate_json(cached_content)
                remapped = remap_report_citations(cached_report, alias_map)
                validate_grounding_or_raise(remapped, evidence)
                return remapped
            except Exception as exc:
                logger.warning("Cached report validation failed: %s; refetching", exc)
                self.cache.invalidate(
                    provider="meta",
                    model=self.model,
                    payload_hash=payload_hash,
                    prompt_version=self.prompt_version,
                    report_schema_version=self.report_schema_version,
                    structured_output_mode="json_schema",
                )

        self.cache.record_miss("meta", self.model)

        request_body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "InvestigationReport",
                    "schema": Report.model_json_schema(),
                },
            },
        }

        endpoint = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        response: httpx.Response | None = None
        owns_client = self._client is None
        client = self._client or httpx.Client(
            timeout=self.timeout, follow_redirects=False
        )

        total_retry_time: float = 0.0

        def check_and_sleep(
            sleep_sec: float, exc_on_exceeded: Exception | None = None
        ) -> None:
            nonlocal total_retry_time
            if total_retry_time + sleep_sec > self.max_total_retry_time:
                if exc_on_exceeded is not None:
                    raise exc_on_exceeded
                raise RateLimitError(
                    f"Total retry delay ({total_retry_time + sleep_sec:.1f}s) "
                    f"exceeded maximum allowed limit ({self.max_total_retry_time}s)"
                )
            total_retry_time += sleep_sec
            self._sleep_fn(sleep_sec)

        try:
            for attempt in range(self.max_retries + 1):
                try:
                    response = client.post(
                        endpoint,
                        headers=headers,
                        json=request_body,
                        timeout=self.timeout,
                    )

                    if response.status_code == 200:
                        break

                    if response.status_code in (401, 403):
                        err_msg = _extract_error_message(response)
                        raise InvalidApiKeyError(
                            f"Meta API key invalid ({response.status_code}): {err_msg}"
                        )

                    if response.status_code == 404:
                        err_msg = _extract_error_message(response)
                        raise UnknownModelError(
                            f"Meta model '{self.model}' not found (404): {err_msg}"
                        )

                    if response.status_code == 400:
                        err_msg = _extract_error_message(response)
                        raise ReasoningProviderError(
                            f"Meta request error / bad schema (400): {err_msg}"
                        )

                    if response.status_code == 429:
                        if attempt < self.max_retries:
                            sleep_sec = self._compute_backoff(attempt, response)
                            check_and_sleep(sleep_sec)
                            continue
                        err_msg = _extract_error_message(response)
                        raise RateLimitError(
                            f"Meta rate limit exceeded (429) after "
                            f"{self.max_retries} retries: {err_msg}"
                        )

                    if response.status_code >= 500:
                        if attempt < self.max_retries:
                            sleep_sec = self._compute_backoff(attempt, response)
                            check_and_sleep(sleep_sec)
                            continue
                        err_msg = _extract_error_message(response)
                        raise ReasoningProviderError(
                            f"Meta server error ({response.status_code}): {err_msg}"
                        )

                    err_msg = _extract_error_message(response)
                    raise ReasoningProviderError(
                        f"Meta unexpected HTTP status ({response.status_code}): "
                        f"{err_msg}"
                    )

                except httpx.TimeoutException as exc:
                    if attempt < self.max_retries:
                        sleep_sec = self._compute_backoff(attempt)
                        timeout_err = ProviderTimeoutError(
                            "Meta request timed out; total retry time "
                            f"({total_retry_time + sleep_sec:.1f}s) exceeded limit: "
                            f"{exc}"
                        )
                        check_and_sleep(sleep_sec, exc_on_exceeded=timeout_err)
                        continue
                    raise ProviderTimeoutError(
                        f"Meta request timed out after {self.timeout}s and "
                        f"{self.max_retries} retries: {exc}"
                    ) from exc
                except (
                    InvalidApiKeyError,
                    UnknownModelError,
                    RateLimitError,
                    ProviderTimeoutError,
                    ReasoningProviderError,
                ):
                    raise
                except httpx.RequestError as exc:
                    if attempt < self.max_retries:
                        sleep_sec = self._compute_backoff(attempt)
                        net_err = ReasoningProviderError(
                            "Network error contacting Meta API; total retry time "
                            f"({total_retry_time + sleep_sec:.1f}s) exceeded limit: "
                            f"{exc}"
                        )
                        check_and_sleep(sleep_sec, exc_on_exceeded=net_err)
                        continue
                    raise ReasoningProviderError(
                        f"Network error contacting Meta API: {exc}"
                    ) from exc
        finally:
            if owns_client:
                client.close()

        if response is None:
            raise ReasoningProviderError("No response received from Meta Model API")

        # Parse response JSON
        try:
            resp_data = response.json()
        except Exception as exc:
            raise MalformedOutputError(
                f"Meta response body is not valid JSON: {exc}"
            ) from exc

        if not isinstance(resp_data, dict):
            raise MalformedOutputError("Meta response body must be a JSON object")

        choices = resp_data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise MalformedOutputError("Meta response missing or empty 'choices' field")

        choice = choices[0]
        if not isinstance(choice, dict):
            raise MalformedOutputError("Meta response choice must be an object")

        message = choice.get("message")
        if not isinstance(message, dict) or "content" not in message:
            raise MalformedOutputError(
                "Meta response missing expected 'message.content' field"
            )

        content_raw = message["content"]
        if not isinstance(content_raw, str):
            raise MalformedOutputError(
                "Meta response 'message.content' must be a string"
            )

        try:
            report_dict = json.loads(content_raw)
        except Exception as exc:
            raise MalformedOutputError(
                f"Failed to parse report content from Meta model as JSON: {exc}"
            ) from exc

        if not isinstance(report_dict, dict):
            raise MalformedOutputError(
                "Meta model report content must be a JSON object"
            )

        metadata_dict = report_dict.get("metadata")
        if not isinstance(metadata_dict, dict):
            metadata_dict = {}
        metadata_dict["provider"] = "meta"
        metadata_dict["model"] = self.model
        metadata_dict["structured_output_mode"] = "json_schema"
        if "prompt_version" not in metadata_dict:
            metadata_dict["prompt_version"] = self.prompt_version
        if "timestamp" not in metadata_dict:
            metadata_dict["timestamp"] = datetime.now(UTC).isoformat()
        report_dict["metadata"] = metadata_dict

        try:
            report = Report.model_validate(report_dict)
        except Exception as exc:
            raise MalformedOutputError(
                f"Model report failed schema validation: {exc}"
            ) from exc

        remapped = remap_report_citations(report, alias_map)
        validate_grounding_or_raise(remapped, evidence)

        self.cache.set(
            provider="meta",
            model=self.model,
            payload_hash=payload_hash,
            prompt_version=self.prompt_version,
            response_text=remapped.model_dump_json(),
            report_schema_version=self.report_schema_version,
            structured_output_mode="json_schema",
        )

        return remapped


class ReasoningConfig(BaseModel):
    """Configuration for AI reasoning layer and provider selection."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    provider: ProviderType = Field(
        default="mock",
        description="Reasoning provider to use: 'mock', 'ollama-cloud', or 'meta'.",
    )
    model: str = Field(
        default="mock-model",
        description="Model name or identifier.",
    )
    ollama_base_url: str = Field(
        default="https://ollama.com",
        description="Base URL for Ollama API endpoint.",
    )
    ollama_model: str | None = Field(
        default=None,
        description="Ollama model name. Defaults to OLLAMA_MODEL environment variable.",
    )
    timeout: float = Field(
        default=30.0,
        ge=0.1,
        description="Request timeout in seconds.",
    )
    max_retries: int = Field(
        default=2,
        ge=0,
        description="Maximum retry attempts for transient errors and rate limits.",
    )
    backoff_factor: float = Field(
        default=0.5,
        ge=0.0,
        description="Initial backoff factor in seconds for exponential backoff.",
    )
    enable_cache: bool = Field(
        default=True,
        description="Whether to enable isolated response caching.",
    )
    cache_dir: Path | None = Field(
        default=None,
        description=(
            "Optional directory for disk caching. Uses in-memory cache if None."
        ),
    )
    fixtures_dir: Path | None = Field(
        default=None,
        description="Optional override directory for MockProvider reports.",
    )
    default_fixture: str = Field(
        default="default.json",
        description="Default fixture file name for MockProvider.",
    )
    prompt_version: str = Field(
        default=PROMPT_VERSION,
        description="Semantic version of prompt templates.",
    )
    allow_custom_host: bool = Field(
        default=False,
        description="Allow Ollama base URLs with hosts other than ollama.com.",
    )
    max_total_retry_time: float = Field(
        default=60.0,
        ge=0.0,
        description="Maximum cumulative retry delay in seconds.",
    )
    meta_base_url: str = Field(
        default="https://api.meta.ai/v1",
        description="Base URL for Meta Model API endpoint.",
    )
    meta_model: str = Field(
        default="muse-spark-1.3",
        description="Meta model name (MOONLIGHT_META_MODEL / muse-spark-1.3).",
    )


def get_provider(
    config: ReasoningConfig | None = None,
    provider: ProviderType | str | None = None,
    **kwargs: Any,
) -> ReportProvider:
    """Select and instantiate a ReportProvider based on configuration or environment.

    Precedence:
    1. Explicit `provider` argument
    2. `config.provider`
    3. `PROVIDER` environment variable
    4. Default: "mock"
    """
    selected: str = (
        provider
        or (config.provider if config else None)
        or os.environ.get("MOONLIGHT_PROVIDER")
        or os.environ.get("PROVIDER")
        or "ollama"
    ).lower()

    if selected == "mock":
        fixtures_dir = kwargs.get("fixtures_dir") or (
            config.fixtures_dir if config else None
        )
        default_fixture = kwargs.get("default_fixture") or (
            config.default_fixture if config else "default.json"
        )
        return MockProvider(fixtures_dir=fixtures_dir, default_fixture=default_fixture)

    if selected in ("ollama", "ollama-cloud"):
        model = (
            kwargs.get("model")
            or (config.ollama_model if config else None)
            or os.environ.get("OLLAMA_MODEL")
            or (config.model if config and config.model != "mock-model" else None)
            or ""
        )
        base_url = (
            kwargs.get("base_url")
            or (config.ollama_base_url if config else None)
            or os.environ.get("OLLAMA_BASE_URL")
            or "https://ollama.com"
        )
        cache = kwargs.get("cache") or (
            ReasoningCache(
                cache_dir=config.cache_dir if config else None,
                enabled=config.enable_cache if config else True,
            )
        )
        allow_custom_host = bool(
            kwargs.get("allow_custom_host")
            or (config.allow_custom_host if config else False)
        )
        max_total_retry_time = float(
            kwargs.get("max_total_retry_time")
            or (config.max_total_retry_time if config else 60.0)
        )
        return OllamaCloudProvider(
            model=model,
            base_url=base_url,
            timeout=config.timeout if config else 30.0,
            max_retries=config.max_retries if config else 2,
            backoff_factor=config.backoff_factor if config else 0.5,
            max_total_retry_time=max_total_retry_time,
            allow_custom_host=allow_custom_host,
            cache=cache,
            prompt_version=config.prompt_version if config else PROMPT_VERSION,
            client=kwargs.get("client"),
            sleep_fn=kwargs.get("sleep_fn", time.sleep),
            api_key=kwargs.get("api_key"),
        )

    if selected == "meta":
        meta_m = (
            kwargs.get("model")
            or (
                config.meta_model
                if config and getattr(config, "meta_model", None)
                else None
            )
            or os.environ.get("MOONLIGHT_META_MODEL")
            or os.environ.get("META_MODEL")
            or (config.model if config and config.model != "mock-model" else None)
            or "muse-spark-1.3"
        )
        meta_b = (
            kwargs.get("base_url")
            or (
                config.meta_base_url
                if config and getattr(config, "meta_base_url", None)
                else None
            )
            or os.environ.get("MOONLIGHT_META_BASE_URL")
            or os.environ.get("META_BASE_URL")
            or "https://api.meta.ai/v1"
        )
        cache = kwargs.get("cache") or (
            ReasoningCache(
                cache_dir=config.cache_dir if config else None,
                enabled=config.enable_cache if config else True,
            )
        )
        max_total_retry_time = float(
            kwargs.get("max_total_retry_time")
            or (config.max_total_retry_time if config else 60.0)
        )
        return MetaProvider(
            model=meta_m,
            base_url=meta_b,
            timeout=config.timeout if config else 30.0,
            max_retries=config.max_retries if config else 2,
            backoff_factor=config.backoff_factor if config else 0.5,
            max_total_retry_time=max_total_retry_time,
            cache=cache,
            prompt_version=config.prompt_version if config else PROMPT_VERSION,
            client=kwargs.get("client"),
            transport=kwargs.get("transport"),
            sleep_fn=kwargs.get("sleep_fn", time.sleep),
            api_key=kwargs.get("api_key"),
        )

    raise ValueError(
        f"Unknown reasoning provider '{selected}'. "
        "Supported providers: mock, ollama, meta."
    )
