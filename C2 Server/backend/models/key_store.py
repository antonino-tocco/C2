from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional
import uuid

from sqlmodel import SQLModel, Field, Relationship

if TYPE_CHECKING:
    from backend.models.target import Target


class KeyStore(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    target_id: str = Field(foreign_key="target.id", index=True)
    public_key_pem: str = Field(default="")
    private_key_pem: str = Field(default="")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    target: Optional["Target"] = Relationship(back_populates="key_stores")
