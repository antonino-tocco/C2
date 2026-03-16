import uuid

from sqlmodel import SQLModel, Field


class User(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    username: str = Field(max_length=50, unique=True, index=True)
    password_hash: str = Field(default="")
    role: str = Field(default="admin")
