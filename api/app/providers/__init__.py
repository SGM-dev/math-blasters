from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class ProviderProfile:
    """The identity and profile fields resolved from an OAuth sign-in."""

    provider: str
    provider_account_id: str
    email: str | None
    email_verified: bool
    display_name: str | None
    avatar_url: str | None


@runtime_checkable
class OAuthProvider(Protocol):
    """Protocol satisfied by sign-in providers."""

    name: str

    def authorize_url(self, state: str, code_challenge: str) -> str:
        """Return the URL to redirect the learner to for authorization."""
        ...

    def exchange_code(self, code: str, code_verifier: str) -> dict[str, str]:
        """Exchange the authorization code and PKCE verifier for token response."""
        ...

    def fetch_profile(self, tokens: dict[str, str]) -> ProviderProfile:
        """Fetch and return the user profile using the exchanged tokens."""
        ...


_registry: dict[str, OAuthProvider] = {}


def register(provider: OAuthProvider) -> None:
    """Register a provider; modules call this only when their client id and secret are set."""
    if provider.name in _registry:
        raise ValueError(f"OAuth provider {provider.name!r} is already registered")
    _registry[provider.name] = provider


def get_provider(name: str) -> OAuthProvider | None:
    """Retrieve a registered provider by name, or None if not registered."""
    return _registry.get(name)


__all__ = [
    "OAuthProvider",
    "ProviderProfile",
    "get_provider",
    "register",
]
