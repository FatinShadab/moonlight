"""Application settings and local configuration management for Moonlight."""

from __future__ import annotations

import json
import logging
import os
import urllib.parse
from pathlib import Path
from typing import Final, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from moonlight.reasoning.exceptions import (
    InvalidApiKeyError,
    MissingApiKeyError,
    ReasoningProviderError,
)

logger = logging.getLogger(__name__)

DEFAULT_SETTINGS_DIR: Final[Path] = Path("state")
DEFAULT_SETTINGS_FILE: Final[Path] = DEFAULT_SETTINGS_DIR / "settings.json"

ProviderType = Literal["mock", "ollama-cloud", "meta"]
AppMode = Literal["replay", "live"]


class AppSettings(BaseModel):
    """Central configuration for Moonlight runtime, AI providers, and heuristics."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    # AI Reasoning & Provider Settings
    provider: ProviderType = Field(
        default="mock",
        description="Reasoning provider to use: 'mock', 'ollama-cloud', or 'meta'.",
    )
    meta_api_key: str = Field(
        default="",
        description="API key for Meta Model API.",
    )
    meta_model: str = Field(
        default="llama-3.3-70b-instruct",
        description="Model identifier for Meta Model API.",
    )
    ollama_api_key: str = Field(
        default="",
        description="API key for Ollama Cloud.",
    )
    ollama_model: str = Field(
        default="gemma4:31b",
        description="Model identifier for Ollama Cloud.",
    )
    ollama_base_url: str = Field(
        default="https://ollama.com",
        description="Base URL for Ollama API endpoint.",
    )
    allow_custom_host: bool = Field(
        default=False,
        description="Allow Ollama base URLs with hosts other than ollama.com.",
    )
    timeout: float = Field(
        default=30.0,
        ge=1.0,
        le=300.0,
        description="AI request timeout in seconds.",
    )
    max_retries: int = Field(
        default=2,
        ge=0,
        le=5,
        description="Maximum retry attempts for AI requests.",
    )
    enable_cache: bool = Field(
        default=True,
        description="Enable isolated response caching for model inferences.",
    )

    # Privacy Minimizer Settings
    max_command_chars: int = Field(
        default=512,
        ge=32,
        le=8192,
        description="Maximum command line characters sent to reasoning provider.",
    )
    max_evidence_items: int = Field(
        default=256,
        ge=1,
        le=4096,
        description="Maximum number of evidence items sent to reasoning provider.",
    )
    custom_username_aliases: str = Field(
        default="",
        description="Comma-separated explicit usernames to redact.",
    )

    # Storage Investigator & Attribution Settings
    min_growth_bytes_per_second: float = Field(
        default=1024.0 * 1024.0,  # 1 MB/s
        ge=0.0,
        description="Minimum disk growth rate in bytes/s to trigger attribution.",
    )
    max_endpoint_skew_seconds: float = Field(
        default=5.0,
        ge=0.0,
        le=60.0,
        description="Maximum endpoint skew tolerance in seconds for disk snapshots.",
    )

    # UI Preferences
    default_mode: AppMode = Field(
        default="replay",
        description="Default investigation mode on launch ('replay' or 'live').",
    )


def get_default_settings_path() -> Path:
    """Return the default configuration file location."""
    return DEFAULT_SETTINGS_FILE


def load_settings(path: Path | str | None = None) -> AppSettings:
    """Load configuration from file or fall back to environment variables.

    Precedence:
    1. Saved JSON settings file if present
    2. Environment variables (META_API_KEY, OLLAMA_API_KEY, OLLAMA_MODEL, etc.)
    3. Model defaults
    """
    target_path = Path(path) if path is not None else get_default_settings_path()

    if target_path.exists():
        try:
            content = target_path.read_text(encoding="utf-8")
            data = json.loads(content)
            if isinstance(data, dict):
                return AppSettings.model_validate(data)
        except Exception as exc:
            logger.warning(
                "Failed to read settings from %s (%s); falling back to env/defaults",
                target_path,
                exc,
            )

    # Fall back to environment variables
    env_provider = os.environ.get("PROVIDER", "mock").lower()
    valid_provider: ProviderType = (
        env_provider
        if env_provider in ("mock", "ollama-cloud", "meta")
        else "mock"  # type: ignore[assignment]
    )

    return AppSettings(
        provider=valid_provider,
        meta_api_key=os.environ.get("META_API_KEY", ""),
        ollama_api_key=os.environ.get("OLLAMA_API_KEY", ""),
        ollama_model=os.environ.get("OLLAMA_MODEL", "gemma4:31b"),
        ollama_base_url=os.environ.get("OLLAMA_BASE_URL", "https://ollama.com"),
    )


def save_settings(
    settings: AppSettings,
    path: Path | str | None = None,
    sync_env: bool = False,
) -> None:
    """Persist settings to disk and optionally sync process environment."""
    target_path = Path(path) if path is not None else get_default_settings_path()
    target_path.parent.mkdir(parents=True, exist_ok=True)

    json_data = settings.model_dump_json(indent=2)
    target_path.write_text(json_data, encoding="utf-8")

    if sync_env:
        if settings.meta_api_key:
            os.environ["META_API_KEY"] = settings.meta_api_key
        elif "META_API_KEY" in os.environ:
            os.environ.pop("META_API_KEY", None)

        if settings.ollama_api_key:
            os.environ["OLLAMA_API_KEY"] = settings.ollama_api_key
        elif "OLLAMA_API_KEY" in os.environ:
            os.environ.pop("OLLAMA_API_KEY", None)

        if settings.ollama_model:
            os.environ["OLLAMA_MODEL"] = settings.ollama_model

        if settings.ollama_base_url:
            os.environ["OLLAMA_BASE_URL"] = settings.ollama_base_url

        os.environ["PROVIDER"] = settings.provider


def fetch_ollama_models(
    base_url: str,
    api_key: str,
    allow_custom_host: bool = False,
    timeout: float = 15.0,
    client: httpx.Client | None = None,
) -> list[str]:
    """Query GET /api/tags on the Ollama endpoint to discover available models.

    Args:
        base_url: Target base URL (e.g. https://ollama.com).
        api_key: API token for Bearer authentication.
        allow_custom_host: Whether hosts other than ollama.com are accepted.
        timeout: Network timeout in seconds.
        client: Optional injected httpx Client (for testing).

    Returns:
        List of available model identifiers.
    """
    clean_url = base_url.rstrip("/")
    parsed = urllib.parse.urlparse(clean_url)
    if parsed.scheme.lower() != "https" and not (
        allow_custom_host and parsed.scheme.lower() == "http"
    ):
        raise ValueError(f"Ollama base URL must use HTTPS scheme (got {clean_url!r})")

    host = (parsed.hostname or "").lower()
    if host != "ollama.com" and not allow_custom_host:
        raise ValueError(
            "Ollama base URL host must be 'ollama.com' unless "
            f"allow_custom_host=True (got {host!r})"
        )

    if not api_key.strip():
        raise MissingApiKeyError("Ollama API key is required to query models.")

    tags_endpoint = f"{clean_url}/api/tags"
    headers = {
        "Authorization": f"Bearer {api_key.strip()}",
        "Content-Type": "application/json",
    }

    owns_client = client is None
    http_client = client or httpx.Client(timeout=timeout, follow_redirects=False)

    try:
        response = http_client.get(tags_endpoint, headers=headers)
        if response.status_code in (401, 403):
            raise InvalidApiKeyError(
                f"Unauthorized ({response.status_code}): "
                "Invalid or missing Ollama API key."
            )
        response.raise_for_status()
        data = response.json()
    except httpx.HTTPStatusError as exc:
        raise ReasoningProviderError(f"HTTP error fetching models: {exc}") from exc
    except (MissingApiKeyError, InvalidApiKeyError):
        raise
    except Exception as exc:
        raise ReasoningProviderError(f"Network error contacting Ollama: {exc}") from exc
    finally:
        if owns_client:
            http_client.close()

    models: list[str] = []
    if isinstance(data, dict) and "models" in data and isinstance(data["models"], list):
        for item in data["models"]:
            if isinstance(item, dict) and "name" in item:
                models.append(str(item["name"]))

    return sorted(models)


def verify_ollama_connection(
    base_url: str,
    api_key: str,
    allow_custom_host: bool = False,
    timeout: float = 15.0,
    client: httpx.Client | None = None,
) -> tuple[bool, str, list[str]]:
    """Verify connection to Ollama API and return status, message, and models."""
    try:
        models = fetch_ollama_models(
            base_url=base_url,
            api_key=api_key,
            allow_custom_host=allow_custom_host,
            timeout=timeout,
            client=client,
        )
        return (
            True,
            f"Connected successfully! Found {len(models)} available model(s).",
            models,
        )
    except Exception as exc:
        return False, str(exc), []
