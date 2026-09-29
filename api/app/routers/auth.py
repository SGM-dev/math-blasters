"""Auth routes: OAuth code flow, current account, and logout."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Callable
from typing import Annotated, Any
from urllib.parse import quote, urlsplit

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select

from app.auth import OptionalCurrentAccountDep
from app.config import Settings, get_settings
from app.db import SessionDep
from app.exceptions import APIException
from app.learner import LEARNER_COOKIE_NAME, LEARNER_TOKEN_PATTERN, issue_learner_identity
from app.models import Learner, OAuthIdentity
from app.providers import ProviderProfile, get_provider
from app.schemas import AccountMeGetResponse

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/me", response_model=AccountMeGetResponse | None)
def get_me(account: OptionalCurrentAccountDep, session: SessionDep) -> AccountMeGetResponse | None:
    if account is None:
        return None

    providers = session.scalars(
        select(OAuthIdentity.provider).where(OAuthIdentity.account_id == account.id).distinct()
    ).all()

    return AccountMeGetResponse(
        display_name=account.display_name,
        avatar_url=account.avatar_url,
        email=account.email,
        providers=sorted(providers),
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
def logout(request: Request, response: Response, session: SessionDep) -> None:
    token = request.cookies.get(LEARNER_COOKIE_NAME)

    if token and LEARNER_TOKEN_PATTERN.fullmatch(token):
        learner = session.scalar(select(Learner).where(Learner.token == token))
        if learner:
            session.delete(learner)

    issue_learner_identity(session, response)


# Default on_profile stub hook; wire issue #117 points this to resolve_account from #85.
def default_on_profile(profile: ProviderProfile) -> None:
    pass


_on_profile_hook: Callable[[ProviderProfile], Any] = default_on_profile


def set_on_profile_hook(hook: Callable[[ProviderProfile], Any]) -> None:
    """Configure the hook invoked with the resolved ProviderProfile upon successful callback."""
    global _on_profile_hook
    _on_profile_hook = hook


def get_on_profile_hook() -> Callable[[ProviderProfile], Any]:
    return _on_profile_hook


def generate_pkce_pair() -> tuple[str, str]:
    """Generate a random code_verifier and its S256 code_challenge per RFC 7636."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def sign_state_cookie(payload: dict[str, Any], secret_key: str, max_age: int = 600) -> str:
    """Serialize and sign payload with an expiration timestamp using HMAC-SHA256."""
    data = dict(payload)
    data["exp"] = int(time.time()) + max_age
    payload_bytes = json.dumps(data, separators=(",", ":")).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
    sig = hmac.new(
        secret_key.encode("utf-8"),
        payload_b64.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload_b64}.{sig}"


def verify_state_cookie(cookie_value: str, secret_key: str) -> dict[str, Any] | None:
    """Verify HMAC signature and timestamp; return payload dict if valid, else None."""
    if not cookie_value or "." not in cookie_value:
        return None

    payload_b64, sig = cookie_value.split(".", 1)
    expected_sig = hmac.new(
        secret_key.encode("utf-8"),
        payload_b64.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return None

    padding = len(payload_b64) % 4
    padded_b64 = payload_b64 + ("=" * (4 - padding) if padding else "")

    try:
        data = json.loads(base64.urlsafe_b64decode(padded_b64.encode("ascii")).decode("utf-8"))
    except Exception:
        return None

    if not isinstance(data, dict):
        return None

    if time.time() > data.get("exp", 0):
        return None

    return data


def validate_redirect_target(target: str | None, settings: Settings) -> str:
    """Validate that target matches the allowed post-login redirect allowlist."""
    allowlist = settings.allowed_post_login_redirect_list
    default_target = allowlist[0] if allowlist else "http://localhost:5173"

    if not target:
        return default_target

    # Reject protocol-relative URLs (e.g. "//evil.example")
    if target.startswith("//"):
        raise APIException(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="validation_error",
            message=f"Redirect target '{target}' is not allowed",
        )

    # Relative paths (e.g. "/dashboard") are safe if root "/" or path prefixes are allowed
    if target.startswith("/"):
        has_root = "/" in allowlist
        matches_prefix = any(
            target.startswith(prefix) for prefix in allowlist if prefix.startswith("/")
        )
        if has_root or matches_prefix:
            return target
        raise APIException(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="validation_error",
            message=f"Redirect target '{target}' is not allowed",
        )

    parsed = urlsplit(target)
    if parsed.scheme not in ("http", "https"):
        raise APIException(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="validation_error",
            message=f"Redirect target '{target}' is not allowed",
        )

    target_origin = f"{parsed.scheme}://{parsed.netloc}"
    for allowed in allowlist:
        if allowed.startswith("http://") or allowed.startswith("https://"):
            allowed_parsed = urlsplit(allowed)
            if target_origin == f"{allowed_parsed.scheme}://{allowed_parsed.netloc}":
                return target

    raise APIException(
        status_code=status.HTTP_400_BAD_REQUEST,
        code="validation_error",
        message=f"Redirect target '{target}' is not allowed",
    )


@router.get("/{provider}/start")
def start_oauth(
    provider: str,
    next: str | None = None,
    settings: Annotated[Settings, Depends(get_settings)] = None,
):
    provider_instance = get_provider(provider)
    if provider_instance is None:
        raise APIException(
            status_code=status.HTTP_404_NOT_FOUND,
            code="not_found",
            message=f"OAuth provider '{provider}' is not configured",
        )

    validated_next = validate_redirect_target(next, settings)
    verifier, challenge = generate_pkce_pair()
    state = secrets.token_urlsafe(32)

    cookie_payload = {
        "state": state,
        "verifier": verifier,
        "provider": provider,
        "next": validated_next,
    }
    cookie_value = sign_state_cookie(cookie_payload, settings.auth_secret_key)

    auth_url = provider_instance.authorize_url(state=state, code_challenge=challenge)
    response = RedirectResponse(url=auth_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    response.set_cookie(
        key="oauth_flow",
        value=cookie_value,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        path="/api/auth",
        max_age=600,
    )
    return response


@router.get("/{provider}/callback")
def oauth_callback(
    provider: str,
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    settings: Annotated[Settings, Depends(get_settings)] = None,
):
    provider_instance = get_provider(provider)
    if provider_instance is None:
        raise APIException(
            status_code=status.HTTP_404_NOT_FOUND,
            code="not_found",
            message=f"OAuth provider '{provider}' is not configured",
        )

    cookie_val = request.cookies.get("oauth_flow")
    cookie_payload = (
        verify_state_cookie(cookie_val, settings.auth_secret_key) if cookie_val else None
    )
    if not cookie_payload:
        raise APIException(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="validation_error",
            message="Missing, invalid, or expired OAuth state cookie",
        )

    if cookie_payload.get("provider") != provider:
        raise APIException(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="validation_error",
            message=(
                f"OAuth provider mismatch: expected '{cookie_payload.get('provider')}', "
                f"got '{provider}'"
            ),
        )

    expected_state = cookie_payload.get("state")
    if not state or not expected_state or not hmac.compare_digest(state, expected_state):
        raise APIException(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="validation_error",
            message="Missing or mismatched OAuth state parameter",
        )

    target = cookie_payload.get("next") or "http://localhost:5173"

    # Trapping provider-side cancellation or failure before code exchange
    if error:
        err_param = quote(error)
        sep = "&" if "?" in target else "?"
        response = RedirectResponse(
            url=f"{target}{sep}error={err_param}",
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
        )
        response.delete_cookie(key="oauth_flow", path="/api/auth")
        return response

    verifier = cookie_payload.get("verifier")
    if not code or not verifier:
        raise APIException(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="validation_error",
            message="Missing authorization code or verifier",
        )

    try:
        tokens = provider_instance.exchange_code(code=code, code_verifier=verifier)
        profile = provider_instance.fetch_profile(tokens)
        get_on_profile_hook()(profile)
    except Exception as exc:
        sep = "&" if "?" in target else "?"
        reason = quote(str(exc) or "provider_error")
        response = RedirectResponse(
            url=f"{target}{sep}error={reason}",
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
        )
        response.delete_cookie(key="oauth_flow", path="/api/auth")
        return response

    response = RedirectResponse(url=target, status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    response.delete_cookie(key="oauth_flow", path="/api/auth")
    return response
