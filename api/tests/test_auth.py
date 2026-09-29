import time
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import create_app
from app.providers import ProviderProfile, register
from app.routers.auth import (
    default_on_profile,
    set_on_profile_hook,
    sign_state_cookie,
    verify_state_cookie,
)
from tests.fake_provider import FakeProvider


@pytest.fixture(autouse=True)
def clean_registry(monkeypatch):
    """Ensure each test runs with a clean provider registry and default on_profile hook."""
    monkeypatch.setattr("app.providers._registry", {})
    set_on_profile_hook(default_on_profile)


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


def extract_cookie_value(response, cookie_name: str = "oauth_flow") -> str | None:
    cookie_header = response.headers.get("set-cookie")
    if not cookie_header:
        return None
    for part in cookie_header.split(";"):
        part = part.strip()
        if part.startswith(f"{cookie_name}="):
            return part.split("=", 1)[1]
    return None


def test_start_unknown_provider_returns_404(client):
    response = client.get("/api/auth/nonexistent/start")
    assert response.status_code == 404
    data = response.json()
    assert data["error"]["code"] == "not_found"
    error_msg = data["error"]["message"].lower()
    assert "not configured" in error_msg or "not found" in error_msg


def test_start_flow_redirects_to_authorize_url_and_sets_cookie(client):
    fake = FakeProvider(name="fake")
    register(fake)

    response = client.get("/api/auth/fake/start", follow_redirects=False)
    assert response.status_code == 307

    location = response.headers.get("location")
    assert location is not None
    assert location.startswith("https://auth.example.com/fake/authorize")

    params = parse_qs(urlsplit(location).query)
    assert "state" in params and len(params["state"][0]) > 0
    assert "code_challenge" in params and len(params["code_challenge"][0]) > 0

    # Cookie checks
    cookie_header = response.headers.get("set-cookie")
    assert cookie_header is not None
    assert "oauth_flow=" in cookie_header
    assert "httponly" in cookie_header.lower()
    assert "samesite=lax" in cookie_header.lower()


def test_start_rejects_disallowed_redirect_target_with_400_validation_error(client):
    fake = FakeProvider(name="fake")
    register(fake)

    # External malicious domain
    resp_ext = client.get("/api/auth/fake/start?next=https://evil.example/phish")
    assert resp_ext.status_code == 400
    data_ext = resp_ext.json()
    assert data_ext["error"]["code"] == "validation_error"
    assert "not allowed" in data_ext["error"]["message"]

    # Protocol-relative URL
    resp_rel = client.get("/api/auth/fake/start?next=//attacker.example/phish")
    assert resp_rel.status_code == 400
    data_rel = resp_rel.json()
    assert data_rel["error"]["code"] == "validation_error"
    assert "not allowed" in data_rel["error"]["message"]


def test_start_accepts_allowed_redirect_target(client):
    fake = FakeProvider(name="fake")
    register(fake)

    response = client.get("/api/auth/fake/start?next=/dashboard", follow_redirects=False)
    assert response.status_code == 307

    cookie_val = extract_cookie_value(response)
    assert cookie_val is not None
    payload = verify_state_cookie(cookie_val, get_settings().auth_secret_key)
    assert payload is not None
    assert payload["next"] == "/dashboard"


def test_start_cookie_contains_expected_payload_and_valid_signature(client):
    fake = FakeProvider(name="fake")
    register(fake)

    response = client.get("/api/auth/fake/start", follow_redirects=False)
    cookie_val = extract_cookie_value(response)
    assert cookie_val is not None

    payload = verify_state_cookie(cookie_val, get_settings().auth_secret_key)
    assert payload is not None
    assert payload["provider"] == "fake"
    assert "state" in payload and len(payload["state"]) > 16
    assert "verifier" in payload and len(payload["verifier"]) > 32
    assert payload["exp"] > time.time()


def test_start_never_leaks_secrets(client):
    fake = FakeProvider(name="fake")
    register(fake)

    secret = "secret-super-confidential-token-12345"
    get_settings().auth_secret_key = secret

    response = client.get("/api/auth/fake/start", follow_redirects=False)
    assert secret not in response.headers.get("location", "")
    assert secret not in response.headers.get("set-cookie", "")
    assert secret not in response.text


def test_callback_unknown_provider_returns_404(client):
    response = client.get("/api/auth/nonexistent/callback?code=foo&state=bar")
    assert response.status_code == 404
    data = response.json()
    assert data["error"]["code"] == "not_found"


def test_callback_missing_cookie_returns_400_validation_error(client):
    fake = FakeProvider(name="fake")
    register(fake)

    response = client.get("/api/auth/fake/callback?code=test-code&state=test-state")
    assert response.status_code == 400
    data = response.json()
    assert data["error"]["code"] == "validation_error"


def test_callback_happy_path_exchanges_code_calls_hook_and_redirects(client):
    fake = FakeProvider(name="fake")
    register(fake)

    captured_profiles: list[ProviderProfile] = []
    set_on_profile_hook(lambda p: captured_profiles.append(p))

    # 1. Start flow to get cookie and state
    start_resp = client.get("/api/auth/fake/start?next=/dashboard", follow_redirects=False)
    assert start_resp.status_code == 307
    location = start_resp.headers["location"]
    params = parse_qs(urlsplit(location).query)
    state = params["state"][0]
    cookie_val = extract_cookie_value(start_resp)

    # 2. Callback with valid code and state
    client.cookies.set("oauth_flow", cookie_val, path="/api/auth")
    callback_resp = client.get(
        f"/api/auth/fake/callback?code=test-auth-code&state={state}",
        follow_redirects=False,
    )

    assert callback_resp.status_code == 307
    assert callback_resp.headers["location"] == "/dashboard"

    # State cookie should be cleared
    cookie_header = callback_resp.headers.get("set-cookie")
    assert cookie_header is not None
    assert 'oauth_flow=""' in cookie_header or "oauth_flow=;" in cookie_header

    # Profile hook should have been called
    assert len(captured_profiles) == 1
    profile = captured_profiles[0]
    assert profile.provider == "fake"
    assert profile.provider_account_id == "fake-user-123"
    assert profile.email == "user@example.com"


def test_callback_mismatched_state_returns_400_validation_error(client):
    class ExchangeTrackingFake(FakeProvider):
        def __init__(self):
            super().__init__(name="fake")
            self.exchange_called = False

        def exchange_code(self, code, code_verifier):
            self.exchange_called = True
            return super().exchange_code(code, code_verifier)

    fake = ExchangeTrackingFake()
    register(fake)

    start_resp = client.get("/api/auth/fake/start", follow_redirects=False)
    cookie_val = extract_cookie_value(start_resp)

    client.cookies.set("oauth_flow", cookie_val, path="/api/auth")
    callback_resp = client.get(
        "/api/auth/fake/callback?code=test-code&state=tampered-state",
        follow_redirects=False,
    )

    assert callback_resp.status_code == 400
    data = callback_resp.json()
    assert data["error"]["code"] == "validation_error"
    assert "state" in data["error"]["message"].lower()

    # Code exchange must NOT be called on state mismatch!
    assert fake.exchange_called is False


def test_callback_missing_state_returns_400_validation_error(client):
    class ExchangeTrackingFake(FakeProvider):
        def __init__(self):
            super().__init__(name="fake")
            self.exchange_called = False

        def exchange_code(self, code, code_verifier):
            self.exchange_called = True
            return super().exchange_code(code, code_verifier)

    fake = ExchangeTrackingFake()
    register(fake)

    start_resp = client.get("/api/auth/fake/start", follow_redirects=False)
    cookie_val = extract_cookie_value(start_resp)

    client.cookies.set("oauth_flow", cookie_val, path="/api/auth")
    callback_resp = client.get(
        "/api/auth/fake/callback?code=test-code",
        follow_redirects=False,
    )

    assert callback_resp.status_code == 400
    data = callback_resp.json()
    assert data["error"]["code"] == "validation_error"

    # Code exchange must NOT be called!
    assert fake.exchange_called is False


def test_callback_provider_mismatch_returns_400_validation_error(client):
    fake = FakeProvider(name="fake")
    other = FakeProvider(name="other")
    register(fake)
    register(other)

    start_resp = client.get("/api/auth/fake/start", follow_redirects=False)
    location = start_resp.headers["location"]
    state = parse_qs(urlsplit(location).query)["state"][0]
    cookie_val = extract_cookie_value(start_resp)

    # Attempt to send the "fake" cookie to "other" callback
    client.cookies.set("oauth_flow", cookie_val, path="/api/auth")
    callback_resp = client.get(
        f"/api/auth/other/callback?code=test-code&state={state}",
        follow_redirects=False,
    )

    assert callback_resp.status_code == 400
    data = callback_resp.json()
    assert data["error"]["code"] == "validation_error"
    assert "mismatch" in data["error"]["message"].lower()


def test_callback_provider_access_denied_redirects_and_clears_cookie(client):
    class ExchangeTrackingFake(FakeProvider):
        def __init__(self):
            super().__init__(name="fake")
            self.exchange_called = False

        def exchange_code(self, code, code_verifier):
            self.exchange_called = True
            return super().exchange_code(code, code_verifier)

    fake = ExchangeTrackingFake()
    register(fake)

    start_resp = client.get("/api/auth/fake/start?next=/dashboard", follow_redirects=False)
    location = start_resp.headers["location"]
    state = parse_qs(urlsplit(location).query)["state"][0]
    cookie_val = extract_cookie_value(start_resp)

    client.cookies.set("oauth_flow", cookie_val, path="/api/auth")
    callback_resp = client.get(
        f"/api/auth/fake/callback?error=access_denied&error_description=User+declined&state={state}",
        follow_redirects=False,
    )

    assert callback_resp.status_code == 307
    redirect_loc = callback_resp.headers["location"]
    assert "/dashboard" in redirect_loc
    assert "error=" in redirect_loc

    # State cookie should be cleared
    cookie_header = callback_resp.headers.get("set-cookie")
    assert cookie_header is not None
    assert 'oauth_flow=""' in cookie_header or "oauth_flow=;" in cookie_header

    # Code exchange must NOT be attempted when access was denied
    assert fake.exchange_called is False


def test_callback_fallback_redirect_respects_settings_allowlist(client, monkeypatch):
    monkeypatch.setattr(
        get_settings(),
        "allowed_post_login_redirects",
        "https://prod.mathblasters.org,/",
    )
    fake = FakeProvider(name="fake")
    register(fake)

    cookie_payload = {
        "state": "state-xyz",
        "verifier": "verifier-xyz",
        "provider": "fake",
        "next": None,
    }
    cookie_val = sign_state_cookie(cookie_payload, get_settings().auth_secret_key)
    client.cookies.set("oauth_flow", cookie_val, path="/api/auth")

    resp = client.get(
        "/api/auth/fake/callback?code=good-code&state=state-xyz",
        follow_redirects=False,
    )
    assert resp.status_code == 307
    assert resp.headers["location"] == "https://prod.mathblasters.org"


def test_callback_token_exchange_failure_redirects_and_clears_cookie(client):
    class FailingExchangeFake(FakeProvider):
        def __init__(self):
            super().__init__(name="fake")

        def exchange_code(self, code, code_verifier):
            raise RuntimeError("Secret internal database or provider error")

    fake = FailingExchangeFake()
    register(fake)

    start_resp = client.get("/api/auth/fake/start?next=/dashboard", follow_redirects=False)
    location = start_resp.headers["location"]
    state = parse_qs(urlsplit(location).query)["state"][0]
    cookie_val = extract_cookie_value(start_resp)

    client.cookies.set("oauth_flow", cookie_val, path="/api/auth")
    callback_resp = client.get(
        f"/api/auth/fake/callback?code=bad-code&state={state}",
        follow_redirects=False,
    )

    assert callback_resp.status_code == 307
    redirect_loc = callback_resp.headers["location"]
    assert "/dashboard" in redirect_loc
    assert "error=provider_error" in redirect_loc
    assert "Secret internal" not in redirect_loc

    # Cookie must be cleared so no half-session remains
    cookie_header = callback_resp.headers.get("set-cookie")
    assert cookie_header is not None
    assert 'oauth_flow=""' in cookie_header or "oauth_flow=;" in cookie_header


def test_callback_unreachable_provider_network_error_redirects_cleanly(client):
    class NetworkErrorFake(FakeProvider):
        def __init__(self):
            super().__init__(name="fake")

        def exchange_code(self, code, code_verifier):
            raise ConnectionError("Connection refused to auth provider")

    fake = NetworkErrorFake()
    register(fake)

    start_resp = client.get("/api/auth/fake/start?next=/dashboard", follow_redirects=False)
    location = start_resp.headers["location"]
    state = parse_qs(urlsplit(location).query)["state"][0]
    cookie_val = extract_cookie_value(start_resp)

    client.cookies.set("oauth_flow", cookie_val, path="/api/auth")
    callback_resp = client.get(
        f"/api/auth/fake/callback?code=good-code&state={state}",
        follow_redirects=False,
    )

    # Must redirect cleanly with generic provider_error rather than leaking raw exception
    assert callback_resp.status_code == 307
    redirect_loc = callback_resp.headers["location"]
    assert "error=provider_error" in redirect_loc
    assert "Connection refused" not in redirect_loc


def test_client_secrets_never_leak_in_logs_or_responses(client, caplog):
    secret_value = "super-secret-client-credential-xyz987"
    get_settings().github_client_secret = secret_value
    get_settings().auth_secret_key = secret_value

    fake = FakeProvider(name="fake")
    register(fake)

    start_resp = client.get("/api/auth/fake/start?next=/dashboard", follow_redirects=False)
    assert secret_value not in start_resp.headers.get("location", "")
    assert secret_value not in start_resp.headers.get("set-cookie", "")

    # Check request log output
    assert secret_value not in caplog.text
