"""Manual smoke test script for Ollama Cloud provider.

This script is intended for manual developer verification against the live
Ollama hosted endpoint (https://ollama.com). It is NOT run in CI.

Usage:
    export OLLAMA_API_KEY="your_api_key_here"
    export OLLAMA_MODEL="gemma4:31b"  # optional; defaults to first available model
    python scripts/ollama_smoke.py

Security:
    The API key is read only from the environment and is never logged or printed.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import UTC, datetime

import httpx

from moonlight.core.evidence import (
    EvidenceBundle,
    EvidenceItem,
    EvidenceKind,
    SeverityHint,
    make_evidence_id,
)
from moonlight.reasoning.exceptions import (
    InvalidApiKeyError,
    MissingApiKeyError,
    ReasoningProviderError,
    UnknownModelError,
)
from moonlight.reasoning.provider import OllamaCloudProvider


def build_sample_bundle() -> EvidenceBundle:
    """Construct a synthetic, harmless sample evidence bundle for smoke testing."""
    timestamp = datetime.now(UTC)
    id1 = make_evidence_id(
        "process", "1001", "process_collector", EvidenceKind.EXECUTABLE_PATH
    )
    id2 = make_evidence_id(
        "process", "1001", "signature_collector", EvidenceKind.SIGNATURE_STATUS
    )
    items = [
        EvidenceItem(
            id=id1,
            source="process_collector",
            kind=EvidenceKind.EXECUTABLE_PATH,
            value={"path": "C:/Windows/explorer.exe"},
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
        subject_id="1001",
        items=tuple(items),
    )


def list_cloud_models(base_url: str, api_key: str) -> list[str]:
    """Query GET /api/tags on the hosted Ollama endpoint."""
    url = f"{base_url.rstrip('/')}/api/tags"
    headers = {"Authorization": f"Bearer {api_key}"}

    with httpx.Client(timeout=15.0) as client:
        response = client.get(url, headers=headers)
        if response.status_code in (401, 403):
            raise InvalidApiKeyError(
                f"Failed to list models: API key unauthorized ({response.status_code})"
            )
        response.raise_for_status()
        data = response.json()

    models: list[str] = []
    if isinstance(data, dict) and "models" in data and isinstance(data["models"], list):
        for m in data["models"]:
            if isinstance(m, dict) and "name" in m:
                models.append(str(m["name"]))
    return models


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default=os.environ.get("OLLAMA_BASE_URL", "https://ollama.com"),
        help="Base URL for Ollama hosted API (default: https://ollama.com)",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("OLLAMA_MODEL"),
        help=(
            "Model identifier (e.g. gemma4:31b). "
            "If omitted, first listed model is used."
        ),
    )
    args = parser.parse_args()

    api_key = os.environ.get("OLLAMA_API_KEY", "").strip()
    if not api_key:
        print(
            "ERROR: OLLAMA_API_KEY environment variable is not set.\n"
            "Please set your key before running this manual smoke script:\n"
            "  $env:OLLAMA_API_KEY = 'your_api_key'  (PowerShell)\n"
            "  export OLLAMA_API_KEY='your_api_key'  (bash)",
            file=sys.stderr,
        )
        return 1

    print(f"Connecting to hosted Ollama endpoint at: {args.base_url}")
    print("Listing available cloud models (GET /api/tags)...")

    try:
        models = list_cloud_models(args.base_url, api_key)
    except Exception as exc:
        print(f"Failed to query model list: {exc}", file=sys.stderr)
        return 1

    if not models:
        print("Warning: No models returned from GET /api/tags.")
    else:
        print(f"Available models ({len(models)}):")
        for m in models:
            print(f"  - {m}")

    chosen_model = args.model or (models[0] if models else "")
    if not chosen_model:
        print(
            "ERROR: No model specified and none returned from /api/tags. "
            "Please set OLLAMA_MODEL.",
            file=sys.stderr,
        )
        return 1

    print(f"\nMaking smoke test investigation call with model: {chosen_model}...")
    bundle = build_sample_bundle()

    allow_custom_host = args.base_url.rstrip("/") != "https://ollama.com"
    provider = OllamaCloudProvider(
        model=chosen_model,
        base_url=args.base_url,
        allow_custom_host=allow_custom_host,
        api_key=api_key,
    )

    try:
        report = provider.investigate(bundle)
    except (MissingApiKeyError, InvalidApiKeyError, UnknownModelError) as exc:
        print(f"Smoke call failed with provider error: {exc}", file=sys.stderr)
        return 1
    except ReasoningProviderError as exc:
        print(f"Smoke call failed with reasoning error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Smoke call failed unexpectedly: {exc}", file=sys.stderr)
        return 1

    print("\n--- Smoke Test Succeeded! ---")
    print(f"Summary:       {report.summary}")
    print(f"Risk Tier:     {report.risk_tier}")
    print(f"Confidence:    {report.confidence:.2f}")
    print(f"Facts Cited:   {len(report.observed_facts)}")
    print(f"Provider:      {report.metadata.provider}")
    print(f"Model:         {report.metadata.model}")
    print(f"Prompt Ver:    {report.metadata.prompt_version}")
    print(f"Timestamp:     {report.metadata.timestamp.isoformat()}")
    print("-----------------------------")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
