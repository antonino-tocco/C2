import os
import threading
from datetime import datetime, timezone
from time import sleep

from dotenv import load_dotenv

load_dotenv()

from backend.classes.database import init_db, engine
from backend.classes.helpers.seed import seed_admin
from backend.classes.servers.http_server import HttpServer
from backend.classes.servers.dns_server import DNSServer

from sqlmodel import Session, select
from backend.models.target import Target

# How often the reaper checks for stale targets (seconds).
_REAPER_INTERVAL = int(os.getenv("REAPER_INTERVAL", "30"))


def _reaper_loop() -> None:
    """Background thread: mark targets as inactive when they exceed their beacon_timeout."""
    while True:
        sleep(_REAPER_INTERVAL)
        try:
            now = datetime.now(timezone.utc)
            with Session(engine) as session:
                targets = session.exec(
                    select(Target).where(
                        Target.status == "active",
                        Target.beacon_timeout > 0,
                    )
                ).all()

                for t in targets:
                    elapsed = (now - t.last_seen).total_seconds()
                    if elapsed > t.beacon_timeout:
                        print(f"[reaper] Target {t.id} ({t.hostname}) inactive — "
                              f"last seen {int(elapsed)}s ago (timeout {t.beacon_timeout}s)")
                        t.status = "inactive"
                        session.add(t)

                session.commit()
        except Exception as e:
            print(f"[reaper] Error: {e}")


def main():
    init_db()
    seed_admin()

    http_server = HttpServer()

    # Start DNS server only when explicitly enabled via env var.
    # Set ENABLE_DNS_SERVER=true and optionally C2_DNS_DOMAIN / DNS_PORT.
    enable_dns = os.getenv("ENABLE_DNS_SERVER", "false").lower() == "true"
    dns_port = int(os.getenv("DNS_PORT", "15353"))
    print(f"[*] DNS server enabled: {enable_dns}, port: {dns_port}")
    dns_server = DNSServer(port=dns_port) if enable_dns else None

    # Start the beacon-timeout reaper
    reaper = threading.Thread(target=_reaper_loop, daemon=True)
    reaper.start()
    print(f"[*] Beacon reaper started (interval={_REAPER_INTERVAL}s)")

    try:
        http_server.start()
        if dns_server:
            dns_server.start()

        while True:
            pass

    except KeyboardInterrupt:
        if dns_server:
            dns_server.stop()
        http_server.stop()


if __name__ == "__main__":
    main()
