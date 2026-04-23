#!/usr/bin/env python3
"""
Async TCP port scanner with banner grabbing.
Usage: python port_scanner.py --host <target> --ports 1-1024 --threads 500
"""

import asyncio
import socket
import argparse
from datetime import datetime
from typing import List, Optional, Tuple
from colorama import Fore, Style, init

init(autoreset=True)

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


async def scan_port(host: str, port: int, timeout: float = 1.0) -> Tuple[int, bool, Optional[str]]:
    """Attempt TCP connection to host:port. Returns (port, is_open, banner)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        banner = None
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=0.5)
            banner = data.decode("utf-8", errors="ignore").strip()[:80]
        except asyncio.TimeoutError:
            pass
        writer.close()
        await writer.wait_closed()
        return port, True, banner
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return port, False, None


async def scan_range(host: str, ports: List[int], concurrency: int = 500) -> List[dict]:
    """Scan all ports in list concurrently."""
    sem = asyncio.Semaphore(concurrency)
    open_ports = []

    async def bounded_scan(port: int):
        async with sem:
            port_num, is_open, banner = await scan_port(host, port)
            if is_open:
                service = COMMON_PORTS.get(port_num, "unknown")
                result = {"port": port_num, "service": service, "banner": banner}
                open_ports.append(result)
                banner_str = f"  [{banner}]" if banner else ""
                print(f"  {Fore.GREEN}checkmark{Style.RESET_ALL}  {port_num:<6} {service:<15}{banner_str}")

    tasks = [bounded_scan(p) for p in ports]
    await asyncio.gather(*tasks)
    return sorted(open_ports, key=lambda x: x["port"])


def parse_ports(port_str: str) -> List[int]:
    """Parse port range string like '1-1024' or '80,443,8080'."""
    ports = []
    for part in port_str.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


def main():
    parser = argparse.ArgumentParser(description="Async TCP Port Scanner")
    parser.add_argument("--host", required=True, help="Target host or IP")
    parser.add_argument("--ports", default="1-1024", help="Port range (e.g. 1-1024 or 80,443)")
    parser.add_argument("--threads", type=int, default=500, help="Max concurrent connections")
    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"{Fore.RED}Error: Cannot resolve {args.host}{Style.RESET_ALL}")
        return

    ports = parse_ports(args.ports)
    print(f"\n{Fore.CYAN}[+] Scanning {args.host} ({target_ip}) -- {len(ports)} ports{Style.RESET_ALL}")
    print(f"[+] Started at {datetime.now().strftime('%H:%M:%S')}\n")

    open_ports = asyncio.run(scan_range(target_ip, ports, args.threads))

    print(f"\n{Fore.CYAN}[+] Scan complete -- {len(open_ports)} open port(s){Style.RESET_ALL}")


if __name__ == "__main__":
    main()
