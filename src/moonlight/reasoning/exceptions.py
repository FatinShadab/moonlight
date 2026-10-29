"""Exception hierarchy for reasoning providers."""

from __future__ import annotations


class ReasoningProviderError(Exception):
    """Base exception for reasoning provider errors."""


class MissingApiKeyError(ReasoningProviderError):
    """Raised when an API key is required but missing from the environment."""


class InvalidApiKeyError(ReasoningProviderError):
    """Raised when an API key is rejected (e.g. HTTP 401 or 403)."""


class UnknownModelError(ReasoningProviderError):
    """Raised when the specified model is unknown or retired (e.g. HTTP 404)."""


class RateLimitError(ReasoningProviderError):
    """Raised when request rate limits are exceeded (e.g. HTTP 429)."""


class ProviderTimeoutError(ReasoningProviderError):
    """Raised when a provider request times out."""


class MalformedOutputError(ReasoningProviderError):
    """Raised when provider output cannot be parsed into a valid Report."""
