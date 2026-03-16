from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional
import uuid

from sqlalchemy import Column, Text
from sqlmodel import SQLModel, Field, Relationship

if TYPE_CHECKING:
    from backend.models.target import Target


class Command(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    target_id: str = Field(foreign_key="target.id", index=True)
    command: str = Field(default="", sa_column=Column(Text))
    original_command: str = Field(default="", sa_column=Column(Text))
    output: str = Field(default="", sa_column=Column(Text))
    module_name: str = Field(default="")
    status: str = Field(default="pending")
    obfuscate: bool = Field(default=False)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    target: Optional["Target"] = Relationship(back_populates="commands")
