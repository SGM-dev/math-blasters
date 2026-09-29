"""Auth routes: OAuth code flow, current account, and logout."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
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

logger = logging.getLogger("api.auth")
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


# Profile hook stub; wire issue #117 points this to resolve_account from #85.
def on_profile(profile: ProviderProfile) -> None:
    pass


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

    padding = (-len(payload_b64)) % 4
    padded_b64 = payload_b64 + ("=" * padding)

    try:
        data = json.loads(base64.urlsafe_b64decode(padded_b64.encode("ascii")).decode("utf-8"))
    except Exception as exc:
        logger.debug("Failed to decode state cookie: %s", exc, exc_info=True)
        return None

    if not isinstance(data, dict):
        logger.debug("State cookie payload is not a dictionary")
        return None

    if time.time() > data.get("exp", 0):
        logger.debug("State cookie expired")
        return None

    return data


def get_default_redirect_target(settings: Settings) -> str:
    """Return the primary allowed redirect destination, defaulting to root if none."""
    allowlist = settings.allowed_post_login_redirect_list
    return allowlist[0] if allowlist else "/"


CLEAR_COOKIE_HEADERS = {"Set-Cookie": 'oauth_flow=""; Path=/api/auth; Max-Age=0; SameSite=lax'}


def _redirect_clearing_cookie(target: str, error: str | None = None) -> RedirectResponse:
    url = f"{target}{'&' if '?' in target else '?'}error={quote(error)}" if error else target
    response = RedirectResponse(url=url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    response.delete_cookie(key="oauth_flow", path="/api/auth")
    return response


def validate_redirect_target(target: str | None, settings: Settings) -> str:
    """Validate that target matches the allowed post-login redirect allowlist."""
    allowlist = settings.allowed_post_login_redirect_list
    if not target:
        return get_default_redirect_target(settings)

    if not target.startswith(("//", "/\\", "\\")):
        if target.startswith("/"):
            if "/" in allowlist or any(
                target.startswith(p) for p in allowlist if p.startswith("/")
            ):
                return target
        else:
            parsed = urlsplit(target)
            if parsed.scheme in ("http", "https") and "@" not in parsed.netloc:
                target_origin = f"{parsed.scheme}://{parsed.netloc}"
                for allowed in allowlist:
                    if allowed.startswith(("http://", "https://")):
                        allowed_parsed = urlsplit(allowed)
                        if target_origin == f"{allowed_parsed.scheme}://{allowed_parsed.netloc}":
                            allowed_path = allowed_parsed.path.rstrip("/")
                            if not allowed_path or parsed.path.startswith(allowed_path):
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
            headers=CLEAR_COOKIE_HEADERS,
        )

    if cookie_payload.get("provider") != provider:
        raise APIException(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="validation_error",
            message=(
                f"OAuth provider mismatch: expected '{cookie_payload.get('provider')}', "
                f"got '{provider}'"
            ),
            headers=CLEAR_COOKIE_HEADERS,
        )

    expected_state = cookie_payload.get("state")
    if not state or not expected_state or not hmac.compare_digest(state, expected_state):
        raise APIException(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="validation_error",
            message="Missing or mismatched OAuth state parameter",
            headers=CLEAR_COOKIE_HEADERS,
        )

    target = cookie_payload.get("next") or get_default_redirect_target(settings)

    # Trapping provider-side cancellation or failure before code exchange
    if error:
        return _redirect_clearing_cookie(target, error=error)

    verifier = cookie_payload.get("verifier")
    if not code or not verifier:
        raise APIException(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="validation_error",
            message="Missing authorization code or verifier",
            headers=CLEAR_COOKIE_HEADERS,
        )

    try:
        tokens = provider_instance.exchange_code(code=code, code_verifier=verifier)
        profile = provider_instance.fetch_profile(tokens)
    except Exception:
        logger.exception("OAuth code exchange or profile fetch failed for provider '%s'", provider)
        return _redirect_clearing_cookie(target, error="provider_error")

    response = _redirect_clearing_cookie(target)

    try:
        on_profile(profile)
    except Exception as exc:
        logger.exception("Error processing authenticated profile in on_profile hook")
        cookie_hdr = response.headers.get("set-cookie")
        headers = {"Set-Cookie": cookie_hdr} if cookie_hdr else CLEAR_COOKIE_HEADERS
        raise APIException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            code="internal",
            message="Internal error processing authenticated profile",
            headers=headers,
        ) from exc

    return response
