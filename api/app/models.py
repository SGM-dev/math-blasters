"""SQLAlchemy models.

Content lives in the repository and does not enter the database. Future models
for learner progress, accounts, or state will inherit from Base here.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
