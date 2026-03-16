from sqlmodel import Session

from backend.classes.modules import get_module
from backend.classes.modules.encoder_module import Encoder
from backend.models.command import Command
from backend.models.target import Target


class CommandProcessor:
    @staticmethod
    def process(
        session: Session,
        target: Target,
        module_name: str,
        obfuscate: bool = False,
        **params,
    ) -> Command:
        module = get_module(module_name)
        if module is None:
            raise ValueError(f"Unknown module: {module_name}")

        payload = module.generate_payload(
            target_os=target.os,
            session=session,
            target_id=target.id,
            **params,
        )

        original = payload
        if obfuscate:
            payload = Encoder.encode(payload, target.os)

        cmd = Command(
            target_id=target.id,
            command=payload,
            original_command=original,
            module_name=module_name,
            obfuscate=obfuscate,
        )
        session.add(cmd)
        session.flush()
        return cmd

    @staticmethod
    def process_raw(
        session: Session,
        target: Target,
        raw_command: str,
        obfuscate: bool = False,
    ) -> Command:
        payload = raw_command
        original = payload
        if obfuscate:
            payload = Encoder.encode(payload, target.os)

        cmd = Command(
            target_id=target.id,
            command=payload,
            original_command=original,
            obfuscate=obfuscate,
        )
        session.add(cmd)
        session.flush()
        return cmd
