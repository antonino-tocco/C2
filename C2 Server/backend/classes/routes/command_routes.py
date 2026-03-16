from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlmodel import Session, select

from backend.classes.database import get_session
from backend.classes.auth import get_current_user
from backend.classes.command_processor import CommandProcessor
from backend.models.target import Target
from backend.models.command import Command
from backend.models.user import User

router = APIRouter(prefix="/commands", tags=["commands"])


class BulkCommandRequest(BaseModel):
    command: str
    target_ids: list[str]
    obfuscate: bool = False


class BulkModuleCommandRequest(BaseModel):
    module_name: str
    target_ids: list[str]
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


def _resolve_targets(session: Session, target_ids: list[str]) -> dict[str, Target]:
    if not target_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="target_ids must not be empty",
        )
    targets = session.exec(
        select(Target).where(Target.id.in_(target_ids))  # type: ignore[attr-defined]
    ).all()
    by_id = {t.id: t for t in targets}
    missing = set(target_ids) - by_id.keys()
    if missing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Targets not found: {', '.join(missing)}",
        )
    return by_id


@router.post("", response_model=list[CommandResultResponse])
def send_bulk_command(
    body: BulkCommandRequest,
    session: Session = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    targets = _resolve_targets(session, body.target_ids)

    commands = []
    for tid in body.target_ids:
        cmd = CommandProcessor.process_raw(session, targets[tid], body.command, body.obfuscate)
        commands.append(cmd)

    session.commit()
    for cmd in commands:
        session.refresh(cmd)

    return commands


@router.post("/module", response_model=list[CommandResultResponse])
def send_bulk_module_command(
    body: BulkModuleCommandRequest,
    session: Session = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    targets = _resolve_targets(session, body.target_ids)

    commands = []
    for tid in body.target_ids:
        try:
            cmd = CommandProcessor.process(
                session, targets[tid], body.module_name, body.obfuscate, **body.params
            )
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        commands.append(cmd)

    session.commit()
    for cmd in commands:
        session.refresh(cmd)

    return commands
