"""Isolated caching and request counting for reasoning providers.

Responses are strictly keyed by (provider, model, payload_hash, prompt_version).
Cache storage is segregated per provider and never mixed.
API keys and secrets are never stored in cache entries or logs.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def compute_payload_hash(payload: Any) -> str:
    """Compute deterministic SHA-256 hex digest for a prompt payload."""
    if isinstance(payload, bytes):
        raw_bytes = payload
    elif isinstance(payload, str):
        raw_bytes = payload.encode("utf-8")
    else:
        raw_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    return hashlib.sha256(raw_bytes).hexdigest()


def _sanitize_filename_part(text: str) -> str:
    """Sanitize model or version strings for safe file path usage."""
    return re.sub(r"[^a-zA-Z0-9_\-\.]", "_", text)


class ReasoningCache:
    """Provider-isolated response cache with per-provider request metrics.

    Caches are separated into distinct provider namespaces in memory and
    on disk so responses can never collide or cross provider boundaries.
    """

    def __init__(
        self,
        cache_dir: Path | str | None = None,
        enabled: bool = True,
    ) -> None:
        self.cache_dir = Path(cache_dir).resolve() if cache_dir else None
        self.enabled = enabled

        # Partitioned store: {provider: {(model, hash, ver): response_text}}
        self._memory_cache: dict[str, dict[tuple[str, str, str], str]] = defaultdict(
            dict
        )

        # Metrics per provider
        self._request_counts: dict[str, int] = defaultdict(int)
        self._hit_counts: dict[str, int] = defaultdict(int)
        self._miss_counts: dict[str, int] = defaultdict(int)

    def record_request(self, provider: str) -> int:
        """Increment and return the total request count for a provider."""
        self._request_counts[provider] += 1
        return self._request_counts[provider]

    def record_hit(self, provider: str, model: str) -> int:
        """Record a cache hit and log request counts."""
        self._hit_counts[provider] += 1
        count = self._request_counts[provider]
        hits = self._hit_counts[provider]
        misses = self._miss_counts[provider]
        logger.info(
            "Reasoning cache HIT: provider=%s model=%s (req #%d, hits=%d, misses=%d)",
            provider,
            model,
            count,
            hits,
            misses,
        )
        return hits

    def record_miss(self, provider: str, model: str) -> int:
        """Record a cache miss and log request counts."""
        self._miss_counts[provider] += 1
        count = self._request_counts[provider]
        hits = self._hit_counts[provider]
        misses = self._miss_counts[provider]
        logger.info(
            "Reasoning cache MISS: provider=%s model=%s (req #%d, hits=%d, misses=%d)",
            provider,
            model,
            count,
            hits,
            misses,
        )
        return misses

    def get_stats(self, provider: str) -> dict[str, int]:
        """Return metric counts for a provider."""
        return {
            "requests": self._request_counts[provider],
            "hits": self._hit_counts[provider],
            "misses": self._miss_counts[provider],
        }

    def _file_path(
        self, provider: str, model: str, payload_hash: str, prompt_version: str
    ) -> Path | None:
        if not self.cache_dir:
            return None
        safe_prov = _sanitize_filename_part(provider)
        safe_mod = _sanitize_filename_part(model)
        safe_ver = _sanitize_filename_part(prompt_version)
        # Dedicated subdirectory per provider ensures strict partition
        provider_dir = self.cache_dir / safe_prov
        return provider_dir / f"{safe_mod}__{safe_ver}__{payload_hash}.json"

    def get(
        self,
        provider: str,
        model: str,
        payload_hash: str,
        prompt_version: str,
    ) -> str | None:
        """Retrieve a cached response if present.

        Returns None if caching is disabled or no entry exists.
        """
        if not self.enabled:
            return None

        # Check memory cache first
        key = (model, payload_hash, prompt_version)
        if key in self._memory_cache[provider]:
            return self._memory_cache[provider][key]

        # Check disk cache
        path = self._file_path(provider, model, payload_hash, prompt_version)
        if path and path.is_file():
            try:
                content = path.read_text(encoding="utf-8")
                self._memory_cache[provider][key] = content
                return content
            except OSError as err:
                logger.warning("Failed to read cache file %s: %s", path, err)

        return None

    def set(
        self,
        provider: str,
        model: str,
        payload_hash: str,
        prompt_version: str,
        response_text: str,
    ) -> None:
        """Store a response in the provider's isolated cache."""
        if not self.enabled:
            return

        key = (model, payload_hash, prompt_version)
        self._memory_cache[provider][key] = response_text

        path = self._file_path(provider, model, payload_hash, prompt_version)
        if path:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(response_text, encoding="utf-8")
            except OSError as err:
                logger.warning("Failed to write cache file %s: %s", path, err)

    def clear(self, provider: str | None = None) -> None:
        """Clear cache entries in-memory and on disk."""
        if provider:
            self._memory_cache[provider].clear()
            if self.cache_dir:
                safe_prov = _sanitize_filename_part(provider)
                provider_dir = self.cache_dir / safe_prov
                if provider_dir.exists():
                    for f in provider_dir.glob("*.json"):
                        try:
                            f.unlink()
                        except OSError:
                            pass
        else:
            self._memory_cache.clear()
            if self.cache_dir and self.cache_dir.exists():
                for sub in self.cache_dir.iterdir():
                    if sub.is_dir():
                        for f in sub.glob("*.json"):
                            try:
                                f.unlink()
                            except OSError:
                                pass
