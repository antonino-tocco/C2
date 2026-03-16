from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional
import uuid

from sqlmodel import SQLModel, Field, Relationship

if TYPE_CHECKING:
    from backend.models.command import Command
    from backend.models.key_store import KeyStore


class Target(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    hostname: str = Field(default="")
    ip_address: str = Field(default="")
    mac_address: str = Field(default="")
    os: str = Field(default="")
    status: str = Field(default="active")
    communication_channel: str = Field(default="http")  # "http" | "dns"
    beacon_interval: int = Field(default=60)    # seconds between check-ins
    beacon_jitter: float = Field(default=0.3)   # ±fraction applied to interval
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    commands: list["Command"] = Relationship(back_populates="target")
    key_stores: list["KeyStore"] = Relationship(back_populates="target")
