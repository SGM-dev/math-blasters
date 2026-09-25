from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlencode

from app.providers import ProviderProfile


@dataclass
class FakeProvider:
    """In-memory OAuth provider for testing flows without external network or secrets."""

    name: str = "fake"
    # None means a canned profile whose provider matches `name`.
    profile: ProviderProfile | None = None
    tokens: dict[str, str] = field(
        default_factory=lambda: {
            "access_token": "fake-access-token",
            "token_type": "bearer",
        }
    )

    def authorize_url(self, state: str, code_challenge: str) -> str:
        query = urlencode({"state": state, "code_challenge": code_challenge})
        return f"https://auth.example.com/fake/authorize?{query}"

    def exchange_code(self, code: str, code_verifier: str) -> dict[str, str]:
        return dict(self.tokens)

    def fetch_profile(self, tokens: dict[str, str]) -> ProviderProfile:
        if self.profile is not None:
            return self.profile
        return ProviderProfile(
            provider=self.name,
            provider_account_id="fake-user-123",
            email="user@example.com",
            email_verified=True,
            display_name="Fake User",
            avatar_url="https://example.com/avatar.png",
        )
