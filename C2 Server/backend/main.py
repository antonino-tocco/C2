import os

from dotenv import load_dotenv

load_dotenv()

from backend.classes.database import init_db
from backend.classes.helpers.seed import seed_admin
from backend.classes.servers.http_server import HttpServer
from backend.classes.servers.dns_server import DNSServer


def main():
    init_db()
    seed_admin()

    http_server = HttpServer()

    # Start DNS server only when explicitly enabled via env var.
    # Set ENABLE_DNS_SERVER=true and optionally C2_DNS_DOMAIN / DNS_PORT.
    enable_dns = os.getenv("ENABLE_DNS_SERVER", "false").lower() == "true"
    dns_port = int(os.getenv("DNS_PORT", "5353"))
    dns_server = DNSServer(port=dns_port) if enable_dns else None

    try:
        http_server.start()
        if dns_server:
            dns_server.start()

        while True:
            pass

    except KeyboardInterrupt:
        http_server.stop()
        if dns_server:
            dns_server.stop()


if __name__ == "__main__":
    main()
