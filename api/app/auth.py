from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select

from app.db import SessionDep
from app.learner import LEARNER_COOKIE_NAME, LEARNER_TOKEN_PATTERN
from app.models import Account, Learner


def get_optional_current_account(request: Request, session: SessionDep) -> Account | None:
    token = request.cookies.get(LEARNER_COOKIE_NAME)
    if token is None or not LEARNER_TOKEN_PATTERN.fullmatch(token):
        return None

    return session.scalar(
        select(Account)
        .join(Learner, Learner.account_id == Account.id)
        .where(Learner.token == token)
    )


OptionalCurrentAccountDep = Annotated[Account | None, Depends(get_optional_current_account)]


def get_current_account(account: OptionalCurrentAccountDep) -> Account:
    if account is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return account


CurrentAccountDep = Annotated[Account, Depends(get_current_account)]
