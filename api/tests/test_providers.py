from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from app.providers import (
    OAuthProvider,
    ProviderProfile,
    clear_registry,
    get_provider,
    register,
)
from tests.fake_provider import FakeProvider


@pytest.fixture(autouse=True)
def clean_registry():
    """Ensure provider registry is clean before and after each test."""
    clear_registry()
    yield
    clear_registry()


def test_fake_provider_satisfies_oauth_provider_protocol():
    fake = FakeProvider()
    assert isinstance(fake, OAuthProvider)


def test_fake_provider_methods():
    fake = FakeProvider()
    url = fake.authorize_url(state="test-state", code_challenge="test-challenge")
    assert "state=test-state" in url
    assert "code_challenge=test-challenge" in url

    tokens = fake.exchange_code(code="test-code", code_verifier="test-verifier")
    assert tokens["access_token"] == "fake-access-token"

    profile = fake.fetch_profile(tokens)
    assert profile.provider == "fake"
    assert profile.provider_account_id == "fake-user-123"
    assert profile.email == "user@example.com"
    assert profile.email_verified is True
    assert profile.display_name == "Fake User"
    assert profile.avatar_url == "https://example.com/avatar.png"


def test_provider_profile_is_frozen():
    profile = ProviderProfile(
        provider="github",
        provider_account_id="12345",
        email="dev@example.com",
        email_verified=True,
        display_name="Dev",
        avatar_url=None,
    )
    with pytest.raises(FrozenInstanceError):
        profile.display_name = "New Name"  # type: ignore[misc]


def test_registry_starts_empty():
    assert get_provider("fake") is None
    assert get_provider("github") is None
    assert get_provider("google") is None


def test_register_and_get_provider():
    fake = FakeProvider()
    register(fake)
    assert get_provider("fake") is fake


def test_get_unknown_provider_returns_none():
    fake = FakeProvider()
    register(fake)
    assert get_provider("nonexistent") is None
