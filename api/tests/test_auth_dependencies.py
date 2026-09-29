import pytest
from fastapi import APIRouter
from sqlalchemy import func, select

from app.auth import CurrentAccountDep, OptionalCurrentAccountDep
from app.learner import LEARNER_COOKIE_NAME
from app.models import Account, Learner


@pytest.fixture
def account_dependency_client(client):
    router = APIRouter()

    @router.get("/api/test/current-account/optional")
    def optional_account(account: OptionalCurrentAccountDep):
        return {"email": account.email} if account is not None else None

    @router.get("/api/test/current-account/required")
    def required_account(account: CurrentAccountDep):
        return {"email": account.email}

    client.app.include_router(router)
    return client


def attach_identity_cookie(client, session, account: Account | None, token: str) -> None:
    session.add(Learner(token=token, account=account))
    session.flush()
    client.cookies.set(LEARNER_COOKIE_NAME, token)


def learner_count(session) -> int:
    return session.scalar(select(func.count()).select_from(Learner))


def test_optional_dependency_resolves_account(account_dependency_client, session):
    account = Account(email="example1@example.com")
    session.add(account)
    session.flush()
    attach_identity_cookie(account_dependency_client, session, account, "a" * 43)

    response = account_dependency_client.get("/api/test/current-account/optional")

    assert response.status_code == 200
    assert response.json() == {"email": "example1@example.com"}


def test_optional_dependency_returns_none_without_cookie(
    account_dependency_client,
):
    response = account_dependency_client.get("/api/test/current-account/optional")

    assert response.status_code == 200
    assert response.json() is None


@pytest.mark.parametrize("token", ["malformed", "x" * 43])
def test_optional_dependency_returns_none_for_invalid_or_unknown_cookie(
    account_dependency_client, session, token
):
    account_dependency_client.cookies.set(LEARNER_COOKIE_NAME, token)
    response = account_dependency_client.get("/api/test/current-account/optional")

    assert response.status_code == 200
    assert response.json() is None
    assert learner_count(session) == 0


def test_optional_dependency_returns_none_for_anonymous_learner(account_dependency_client, session):
    attach_identity_cookie(
        account_dependency_client,
        session,
        account=None,
        token="t" * 43,
    )

    response = account_dependency_client.get("/api/test/current-account/optional")

    assert response.status_code == 200
    assert response.json() is None


def test_required_dependency_returns_account(account_dependency_client, session):
    account = Account(email="example2@example.com")
    session.add(account)
    session.flush()
    attach_identity_cookie(account_dependency_client, session, account, "b" * 43)

    response = account_dependency_client.get("/api/test/current-account/required")

    assert response.status_code == 200
    assert response.json() == {"email": "example2@example.com"}


def test_required_dependency_returns_unauthorized_envelope(
    account_dependency_client,
):
    response = account_dependency_client.get("/api/test/current-account/required")

    assert response.status_code == 401
    assert response.json() == {
        "error": {
            "code": "unauthorized",
            "message": "Not authenticated",
            "details": None,
        }
    }


def test_me_returns_null_when_signed_out(client):
    response = client.get("/api/auth/me")

    assert response.status_code == 200
    assert response.json() is None
