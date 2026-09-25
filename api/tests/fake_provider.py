from __future__ import annotations

from dataclasses import dataclass, field

from app.providers import ProviderProfile


@dataclass
class FakeProvider:
    """In-memory OAuth provider for testing flows without external network or secrets."""

    name: str = "fake"
    # Defaults to a canned profile whose provider matches `name`.
    profile: ProviderProfile | None = None
    tokens: dict[str, str] = field(
        default_factory=lambda: {
            "access_token": "fake-access-token",
            "token_type": "bearer",
        }
    )

    def __post_init__(self) -> None:
        if self.profile is None:
            self.profile = ProviderProfile(
                provider=self.name,
                provider_account_id="fake-user-123",
                email="user@example.com",
                email_verified=True,
                display_name="Fake User",
                avatar_url="https://example.com/avatar.png",
            )

    def authorize_url(self, state: str, code_challenge: str) -> str:
        return (
            f"https://auth.example.com/fake/authorize?state={state}&code_challenge={code_challenge}"
        )

    def exchange_code(self, code: str, code_verifier: str) -> dict[str, str]:
        return dict(self.tokens)

    def fetch_profile(self, tokens: dict[str, str]) -> ProviderProfile:
        assert self.profile is not None
        return self.profile
