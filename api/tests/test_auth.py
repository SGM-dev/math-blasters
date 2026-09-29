import time
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import create_app
from app.providers import register
from app.routers.auth import verify_state_cookie
from tests.fake_provider import FakeProvider


@pytest.fixture(autouse=True)
def clean_registry(monkeypatch):
    """Ensure each test runs with a clean provider registry."""
    monkeypatch.setattr("app.providers._registry", {})


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
    # Verify that secret keys or sensitive configuration never appear in response
    fake = FakeProvider(name="fake")
    register(fake)

    secret = "secret-super-confidential-token-12345"
    get_settings().auth_secret_key = secret

    response = client.get("/api/auth/fake/start", follow_redirects=False)
    assert secret not in response.headers.get("location", "")
    assert secret not in response.headers.get("set-cookie", "")
    assert secret not in response.text
