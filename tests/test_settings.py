"""Unit tests for AppSettings configuration and model discovery."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
from pydantic import ValidationError

from moonlight.core.config import (
    AppSettings,
    fetch_ollama_models,
    load_settings,
    save_settings,
    verify_ollama_connection,
)
from moonlight.reasoning.exceptions import (
    InvalidApiKeyError,
    MissingApiKeyError,
)


def test_app_settings_defaults() -> None:
    settings = AppSettings()
    assert settings.provider == "mock"
    assert settings.meta_api_key == ""
    assert settings.meta_model == "llama-3.3-70b-instruct"
    assert settings.ollama_api_key == ""
    assert settings.ollama_model == "gemma4:31b"
    assert settings.ollama_base_url == "https://ollama.com"
    assert settings.allow_custom_host is False
    assert settings.timeout == 30.0
    assert settings.max_retries == 2
    assert settings.enable_cache is True
    assert settings.max_command_chars == 512
    assert settings.max_evidence_items == 256
    assert settings.min_growth_bytes_per_second == 1024.0 * 1024.0
    assert settings.max_endpoint_skew_seconds == 5.0
    assert settings.default_mode == "replay"


def test_app_settings_validation_ranges() -> None:
    with pytest.raises(ValidationError):
        AppSettings(timeout=0.0)  # ge=1.0

    with pytest.raises(ValidationError):
        AppSettings(max_retries=10)  # le=5

    with pytest.raises(ValidationError):
        AppSettings(max_command_chars=10)  # ge=32


def test_settings_save_and_load_roundtrip(tmp_path: Path) -> None:
    settings_file = tmp_path / "custom_settings.json"
    custom = AppSettings(
        provider="ollama-cloud",
        meta_api_key="test-meta-key",
        meta_model="llama-3.1-70b-instruct",
        ollama_api_key="test-ollama-key",
        ollama_model="llama3.3:latest",
        ollama_base_url="https://ollama.com",
        allow_custom_host=False,
        timeout=45.0,
        max_retries=3,
        enable_cache=False,
        max_command_chars=1024,
        max_evidence_items=512,
        custom_username_aliases="Admin,Tester",
        min_growth_bytes_per_second=2.0 * 1024 * 1024,
        max_endpoint_skew_seconds=10.0,
        default_mode="live",
    )

    save_settings(custom, path=settings_file)
    assert settings_file.exists()

    loaded = load_settings(path=settings_file)
    assert loaded == custom

    # Verify JSON content is valid
    raw = json.loads(settings_file.read_text(encoding="utf-8"))
    assert raw["provider"] == "ollama-cloud"
    assert raw["ollama_model"] == "llama3.3:latest"


def test_settings_load_env_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    non_existent = tmp_path / "does_not_exist.json"
    monkeypatch.setenv("PROVIDER", "ollama-cloud")
    monkeypatch.setenv("META_API_KEY", "env-meta-key")
    monkeypatch.setenv("OLLAMA_API_KEY", "env-ollama-key")
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5:latest")
    monkeypatch.setenv("OLLAMA_BASE_URL", "https://ollama.com")

    settings = load_settings(path=non_existent)
    assert settings.provider == "ollama-cloud"
    assert settings.meta_api_key == "env-meta-key"
    assert settings.ollama_api_key == "env-ollama-key"
    assert settings.ollama_model == "qwen2.5:latest"
    assert settings.ollama_base_url == "https://ollama.com"


def test_fetch_ollama_models_success() -> None:
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "models": [
            {"name": "llama3.3:latest"},
            {"name": "gemma4:31b"},
            {"name": "qwen2.5:latest"},
        ]
    }

    mock_client = MagicMock(spec=httpx.Client)
    mock_client.get.return_value = mock_response

    models = fetch_ollama_models(
        base_url="https://ollama.com",
        api_key="valid-key",
        client=mock_client,
    )
    assert models == ["gemma4:31b", "llama3.3:latest", "qwen2.5:latest"]
    mock_client.get.assert_called_once()
    assert mock_client.get.call_args[0][0] == "https://ollama.com/api/tags"


def test_fetch_ollama_models_unauthorized() -> None:
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 401

    mock_client = MagicMock(spec=httpx.Client)
    mock_client.get.return_value = mock_response

    with pytest.raises(InvalidApiKeyError):
        fetch_ollama_models(
            base_url="https://ollama.com",
            api_key="invalid-key",
            client=mock_client,
        )


def test_fetch_ollama_models_missing_key() -> None:
    with pytest.raises(MissingApiKeyError):
        fetch_ollama_models(
            base_url="https://ollama.com",
            api_key="",
        )


def test_fetch_ollama_models_rejects_non_https() -> None:
    with pytest.raises(ValueError, match="must use HTTPS scheme"):
        fetch_ollama_models(
            base_url="http://insecure.com",
            api_key="key",
        )


def test_fetch_ollama_models_rejects_custom_host_by_default() -> None:
    with pytest.raises(ValueError, match="host must be 'ollama.com'"):
        fetch_ollama_models(
            base_url="https://evil.com",
            api_key="key",
            allow_custom_host=False,
        )


def test_verify_ollama_connection_helper() -> None:
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {"models": [{"name": "gemma4:31b"}]}

    mock_client = MagicMock(spec=httpx.Client)
    mock_client.get.return_value = mock_response

    success, msg, models = verify_ollama_connection(
        base_url="https://ollama.com",
        api_key="key",
        client=mock_client,
    )
    assert success is True
    assert "Connected successfully" in msg
    assert models == ["gemma4:31b"]
