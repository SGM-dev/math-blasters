from __future__ import annotations

from dataclasses import dataclass, field

from app.providers import ProviderProfile


@dataclass
class FakeProvider:
    """In-memory OAuth provider for testing flows without external network or secrets."""

    name: str = "fake"
    profile: ProviderProfile = field(
        default_factory=lambda: ProviderProfile(
            provider="fake",
            provider_account_id="fake-user-123",
            email="user@example.com",
            email_verified=True,
            display_name="Fake User",
            avatar_url="https://example.com/avatar.png",
        )
    )
    tokens: dict[str, str] = field(
        default_factory=lambda: {
            "access_token": "fake-access-token",
            "token_type": "bearer",
        }
    )

    def authorize_url(self, state: str, code_challenge: str) -> str:
        return (
            f"https://auth.example.com/fake/authorize?state={state}&code_challenge={code_challenge}"
        )

    def exchange_code(self, code: str, code_verifier: str) -> dict[str, str]:
        return dict(self.tokens)

    def fetch_profile(self, tokens: dict[str, str]) -> ProviderProfile:
        return self.profile
