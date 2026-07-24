#!/usr/bin/env python3
"""
ServerWatch — Interactive Website Health & Security Monitor
============================================================
User enters server details via keyboard input.

Features:
  • ASCII Banner                • Rich Terminal UI
  • Dark Theme                  • Progress Bars
  • DNS Resolution              • SSL/TLS Expiry
  • HTTP Security Headers       • Response Times
  • Port Scanning               • JSON / CSV Export
  • Interactive Input           • Concurrent Scanning
  • Continuous Monitoring

Dependencies: pip install requests rich
"""

# ═══════════════════════════════════════════════════════════
# IMPORTS
# ═══════════════════════════════════════════════════════════

import argparse
import csv
import json
import ssl
import socket
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed, wait
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("Missing 'requests' library. Install: pip install requests")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    )
    from rich.panel import Panel
    from rich import box
    from rich.prompt import Prompt, Confirm, IntPrompt
except ImportError:
    print("Missing 'rich' library. Install: pip install rich")
    sys.exit(1)


# ═══════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════

VERSION = "3.0.0"

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                 993, 995, 1433, 1521, 2049, 3306, 3389, 5432,
                 5900, 6379, 8080, 8443, 9090, 27017]

WELL_KNOWN_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    2049: "NFS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9090: "HTTP-Alt2", 27017: "MongoDB",
}

SECURITY_HEADERS = [
    ("Strict-Transport-Security",   "HSTS"),
    ("Content-Security-Policy",     "CSP"),
    ("X-Content-Type-Options",      "XCTO"),
    ("X-Frame-Options",             "XFO"),
    ("X-XSS-Protection",            "XXSS"),
    ("Referrer-Policy",             "Referrer"),
    ("Permissions-Policy",          "Permissions"),
    ("Access-Control-Allow-Origin", "CORS"),
]

CONSOLE = Console()


# ═══════════════════════════════════════════════════════════
# BANNER
# ═══════════════════════════════════════════════════════════

def print_banner() -> None:
    """Display the ServerWatch ASCII banner."""
    banner = f"""\
╔══════════════════════════════════════════════════════════╗
║               ███████╗███████╗██████╗ ██╗   ██╗         ║
║               ██╔════╝██╔════╝██╔══██╗██║   ██║         ║
║               ███████╗█████╗  ██████╔╝██║   ██║         ║
║               ╚════██║██╔══╝  ██╔══██╗██║   ██║         ║
║               ███████║███████╗██║  ██║╚██████╔╝         ║
║               ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝          ║
║                   W A T C H  —  v{VERSION}                  ║
║            Website Health & Security Monitor             ║
╚══════════════════════════════════════════════════════════╝"""
    CONSOLE.print(banner, style="bold cyan", justify="center")


# ═══════════════════════════════════════════════════════════
# INTERACTIVE USER INPUT
# ═══════════════════════════════════════════════════════════

def get_servers_from_user() -> list[dict]:
    """Prompt user interactively for server details. Returns list of server dicts."""
    servers: list[dict] = []

    CONSOLE.print("\n[bold yellow]┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓[/]")
    CONSOLE.print("[bold yellow]┃      ENTER YOUR SERVERS TO MONITOR      ┃[/]")
    CONSOLE.print("[bold yellow]┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛[/]\n")

    while True:
        CONSOLE.print("─" * 50, style="dim")
        CONSOLE.print(f"[bold cyan]Server #{len(servers) + 1}[/]")

        name   = Prompt.ask("[bold white]Server name[/]",
                            default=f"Server {len(servers) + 1}")
        host   = Prompt.ask("[bold white]Hostname or IP[/]")
        port   = IntPrompt.ask("[bold white]Main web port[/]", default=443)
        ssl_en = Confirm.ask("[bold white]Use HTTPS/SSL?[/]",
                             default=(port == 443))

        CONSOLE.print("[dim]Which checks to run? (press Enter for all)[/]")
        check_dns     = Confirm.ask("  [bold]✓[/] DNS resolution check?",      default=True)
        check_ssl     = Confirm.ask("  [bold]✓[/] SSL certificate check?",     default=ssl_en)
        check_headers = Confirm.ask("  [bold]✓[/] Security headers check?",    default=True)
        check_avail   = Confirm.ask("  [bold]✓[/] Availability check?",        default=True)

        # ── Port scan prompt ──
        check_ports = Confirm.ask(
            "  [bold]✓[/] Port scan (check for open ports)?", default=False
        )
        custom_ports = None
        if check_ports:
            port_input = Prompt.ask(
                "  [dim]Ports to scan (comma-separated, or Enter for default set)[/]",
                default=""
            )
            if port_input.strip():
                try:
                    custom_ports = [int(p.strip()) for p in port_input.split(",")]
                except ValueError:
                    CONSOLE.print("  [red]Invalid port list. Using defaults.[/]")
                    custom_ports = None

        timeout = IntPrompt.ask("[bold white]Timeout (seconds)[/]", default=10)

        servers.append({
            "name":          name,
            "host":          host,
            "port":          port,
            "use_ssl":       ssl_en,
            "check_dns":     check_dns,
            "check_ssl":     check_ssl,
            "check_headers": check_headers,
            "check_avail":   check_avail,
            "check_ports":   check_ports,
            "custom_ports":  custom_ports,
            "timeout":       timeout,
        })

        CONSOLE.print(f"\n[green]✔ Added [bold]{name}[/] ([dim]{host}:{port}[/])[/]")

        if not Confirm.ask("\n[bold yellow]Add another server?[/]", default=False):
            break

    return servers


# ═══════════════════════════════════════════════════════════
# NETWORK CHECKS
# ═══════════════════════════════════════════════════════════

def check_dns(hostname: str, timeout: int = 5) -> dict:
    """Resolve hostname to IP addresses."""
    start = time.perf_counter()
    try:
        infos = socket.getaddrinfo(hostname, None,
                                   socket.AF_UNSPEC, socket.SOCK_STREAM)
        elapsed = round((time.perf_counter() - start) * 1000, 2)
        ips = sorted(set(info[4][0] for info in infos))
        return {"status": "OK", "ips": ips, "elapsed_ms": elapsed}
    except socket.gaierror as exc:
        elapsed = round((time.perf_counter() - start) * 1000, 2)
        return {"status": "FAIL", "error": str(exc), "elapsed_ms": elapsed}


def check_ssl(hostname: str, port: int = 443, timeout: int = 10) -> dict:
    """Retrieve SSL certificate and calculate days until expiry."""
    start = time.perf_counter()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                cert = tls.getpeercert()

        elapsed = round((time.perf_counter() - start) * 1000, 2)

        not_after = datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days

        return {
            "status": "OK",
            "issuer":    dict(cert.get("issuer", [])[0]) if cert.get("issuer") else {},
            "not_after": cert["notAfter"],
            "days_left": days_left,
            "elapsed_ms": elapsed,
        }
    except Exception as exc:
        elapsed = round((time.perf_counter() - start) * 1000, 2)
        return {"status": "FAIL", "error": str(exc), "elapsed_ms": elapsed}


def check_headers(url: str, timeout: int = 10) -> dict:
    """Check presence of security-related HTTP response headers."""
    start = time.perf_counter()
    try:
        resp = requests.head(url, timeout=timeout, allow_redirects=True)
        elapsed = round((time.perf_counter() - start) * 1000, 2)

        headers = dict(resp.headers)
        security = {}
        for hdr, short in SECURITY_HEADERS:
            val = headers.get(hdr) or headers.get(hdr.lower())
            security[short] = val if val else "⚠ MISSING"

        return {
            "status": "OK",
            "status_code": resp.status_code,
            "headers": security,
            "elapsed_ms": elapsed,
        }
    except Exception as exc:
        elapsed = round((time.perf_counter() - start) * 1000, 2)
        return {"status": "FAIL", "error": str(exc), "elapsed_ms": elapsed}


def check_availability(url: str, timeout: int = 10) -> dict:
    """Fetch the URL and measure response time / status."""
    start = time.perf_counter()
    try:
        session = requests.Session()
        retries = Retry(total=2, backoff_factor=0.3,
                        status_forcelist=[500, 502, 503, 504])
        session.mount("http://",  HTTPAdapter(max_retries=retries))
        session.mount("https://", HTTPAdapter(max_retries=retries))

        resp = session.get(url, timeout=timeout)
        elapsed = round((time.perf_counter() - start) * 1000, 2)

        return {
            "status":           "OK" if resp.status_code < 400 else "WARN",
            "status_code":       resp.status_code,
            "response_time_ms": elapsed,
            "content_length":    len(resp.content),
        }
    except Exception as exc:
        elapsed = round((time.perf_counter() - start) * 1000, 2)
        return {"status": "FAIL", "error": str(exc), "elapsed_ms": elapsed}


# ═══════════════════════════════════════════════════════════
# PORT SCANNER
# ═══════════════════════════════════════════════════════════

def _scan_single_port(host: str, port: int, timeout: float) -> tuple[int, bool, str]:
    """Attempt TCP connection to a single port. Returns (port, is_open, service)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        is_open = (result == 0)
        service = WELL_KNOWN_PORTS.get(port, "Unknown")
        return (port, is_open, service)
    except Exception:
        return (port, False, "Unknown")


def check_ports(host: str, port_list: list[int] | None = None,
                timeout: int = 10) -> dict:
    """
    Scan a host for open TCP ports.
    If port_list is None, uses DEFAULT_PORTS.
    Returns dict with open ports, closed count, and timing.
    """
    if port_list is None:
        port_list = DEFAULT_PORTS

    start = time.perf_counter()
    scan_timeout = max(0.5, timeout / max(len(port_list), 1) * 2)

    open_ports: list[dict] = []
    total = len(port_list)

    with ThreadPoolExecutor(max_workers=min(50, total)) as pool:
        futures = {pool.submit(_scan_single_port, host, p, scan_timeout): p
                   for p in port_list}
        for future in as_completed(futures):
            port, is_open, service = future.result()
            if is_open:
                open_ports.append({"port": port, "service": service})

    elapsed = round((time.perf_counter() - start) * 1000, 2)
    open_ports.sort(key=lambda x: x["port"])

    return {
        "status":       "OK",
        "open_ports":   open_ports,
        "open_count":   len(open_ports),
        "scanned":      total,
        "elapsed_ms":   elapsed,
    }


# ═══════════════════════════════════════════════════════════
# SCAN ORCHESTRATION
# ═══════════════════════════════════════════════════════════

def scan_server(server: dict) -> dict:
    """Run all enabled checks against a single server configuration."""
    name    = server["name"]
    host    = server["host"]
    port    = server["port"]
    ssl_en  = server["use_ssl"]
    timeout = server["timeout"]

    scheme   = "https" if ssl_en else "http"
    base_url = f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"

    results = {
        "server_name": name,
        "host":        host,
        "port":        port,
        "timestamp":   datetime.utcnow().isoformat(),
    }

    if server["check_dns"]:
        results["dns"] = check_dns(host, timeout)
    if server["check_ssl"] and ssl_en:
        results["ssl"] = check_ssl(host, port, timeout)
    if server["check_headers"]:
        results["headers"] = check_headers(base_url, timeout)
    if server["check_avail"]:
        results["availability"] = check_availability(base_url, timeout)
    if server["check_ports"]:
        results["ports"] = check_ports(host, server.get("custom_ports"), timeout)

    return results


# ═══════════════════════════════════════════════════════════
# EXPORT
# ═══════════════════════════════════════════════════════════

def export_json(all_results: list[dict], export_dir: str = "reports") -> Path:
    """Export full results to a timestamped JSON file."""
    Path(export_dir).mkdir(parents=True, exist_ok=True)
    ts   = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = Path(export_dir) / f"serverwatch_{ts}.json"
    with open(path, "w") as fh:
        json.dump(all_results, fh, indent=2)
    return path


def export_csv(all_results: list[dict], export_dir: str = "reports") -> Path:
    """Flatten results to a timestamped CSV (one row per check per server)."""
    Path(export_dir).mkdir(parents=True, exist_ok=True)
    ts   = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = Path(export_dir) / f"serverwatch_{ts}.csv"

    rows: list[dict] = []
    for entry in all_results:
        base = {
            "timestamp": entry["timestamp"],
            "server":    entry["server_name"],
            "host":      entry["host"],
            "port":      entry["port"],
        }
        for check_type in ("dns", "ssl", "headers", "availability", "ports"):
            data = entry.get(check_type)
            if not data:
                continue
            row = {**base, "check": check_type, "status": data.get("status", "?")}
            if data.get("elapsed_ms") is not None:
                row["elapsed_ms"] = data["elapsed_ms"]
            if data.get("error"):
                row["error"] = data["error"]
            if data.get("ips"):
                row["ips"] = ", ".join(data["ips"])
            if data.get("days_left") is not None:
                row["days_left"] = data["days_left"]
            if data.get("status_code"):
                row["status_code"] = data["status_code"]
            if data.get("response_time_ms") is not None:
                row["response_time_ms"] = data["response_time_ms"]
            if check_type == "ports":
                open_ports = data.get("open_ports", [])
                row["open_ports"] = ", ".join(
                    f"{p['port']}/{p['service']}" for p in open_ports
                ) if open_ports else "None"
                row["open_count"] = data.get("open_count", 0)
                row["scanned"]    = data.get("scanned", 0)
            rows.append(row)

    with open(path, "w", newline="") as fh:
        if rows:
            writer = csv.DictWriter(fh, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)

    return path


# ═══════════════════════════════════════════════════════════
# RICH DISPLAY
# ═══════════════════════════════════════════════════════════

def build_results_table(all_results: list[dict]) -> Table:
    """Construct a Rich Table summarising all scan results."""
    table = Table(
        title="📊 Scan Results",
        box=box.ROUNDED,
        border_style="bright_blue",
        header_style="bold cyan",
    )
    table.add_column("Server",        style="bold white")
    table.add_column("DNS",           justify="center")
    table.add_column("SSL Expiry",    justify="center")
    table.add_column("Headers",       justify="center")
    table.add_column("HTTP Status",   justify="center")
    table.add_column("Response Time", justify="right")
    table.add_column("Open Ports",    justify="center")

    for entry in all_results:
        # ── Server column ──
        name_cell = f"[bold]{entry['server_name']}[/]\n[dim]{entry['host']}[/]"

        # ── DNS column ──
        dns_data = entry.get("dns", {})
        if dns_data.get("status") == "OK":
            dns_cell = "[green]✓ OK[/]"
            if dns_data.get("ips"):
                dns_cell += f"\n[dim]{', '.join(dns_data['ips'][:2])}[/]"
        else:
            dns_cell = "[red]✗ FAIL[/]"

        # ── SSL column ──
        ssl_data = entry.get("ssl")
        if ssl_data and ssl_data["status"] == "OK":
            days = ssl_data["days_left"]
            color = "green" if days > 30 else ("yellow" if days > 7 else "red")
            ssl_cell = f"[{color}]{days} days[/]"
        elif ssl_data:
            ssl_cell = f"[red]✗ {ssl_data.get('error', '')[:20]}[/]"
        else:
            ssl_cell = "[dim]—[/]"

        # ── Headers column ──
        hdr_data = entry.get("headers")
        if hdr_data and hdr_data["status"] == "OK":
            hdrs     = hdr_data.get("headers", {})
            missing  = sum(1 for v in hdrs.values() if "MISSING" in str(v))
            total    = len(hdrs)
            color    = "green" if missing == 0 else "yellow"
            hdr_cell = f"[{color}]{total - missing}/{total}[/]"
        else:
            hdr_cell = "[dim]—[/]"

        # ── Status & Response Time columns ──
        avail_data = entry.get("availability")
        if avail_data:
            sc = avail_data.get("status_code", "?")
            if avail_data["status"] == "OK":
                sc_cell = f"[green]{sc}[/]"
            elif avail_data["status"] == "WARN":
                sc_cell = f"[yellow]{sc}[/]"
            else:
                sc_cell = "[red]✗[/]"

            rt = avail_data.get("response_time_ms")
            if rt is not None:
                rt_color = "green" if rt < 500 else ("yellow" if rt < 2000 else "red")
                rt_cell  = f"[{rt_color}]{rt:.0f} ms[/]"
            else:
                rt_cell = "[dim]—[/]"
        else:
            sc_cell = "[dim]—[/]"
            rt_cell = "[dim]—[/]"

        # ── Ports column ──
        port_data = entry.get("ports")
        if port_data and port_data["status"] == "OK":
            open_list = port_data.get("open_ports", [])
            scanned   = port_data.get("scanned", 0)
            if open_list:
                # Show first 3 ports, then "+N more" if needed
                summaries = [f"{p['port']}" for p in open_list[:3]]
                port_str = ", ".join(summaries)
                if len(open_list) > 3:
                    port_str += f"\n[dim]+{len(open_list)-3} more[/]"
                port_cell = f"[green]{port_str}[/]"
                # Color by risk: common high-risk open ports
                high_risk = {21, 23, 445, 3389, 5900}
                risk_ports = [p["port"] for p in open_list if p["port"] in high_risk]
                if risk_ports:
                    port_cell += f"\n[red]⚠ {', '.join(str(p) for p in risk_ports)}[/]"
            else:
                port_cell = f"[dim]None of {scanned}[/]"
        elif port_data:
            port_cell = f"[red]✗ {port_data.get('error', 'FAIL')[:15]}[/]"
        else:
            port_cell = "[dim]—[/]"

        table.add_row(name_cell, dns_cell, ssl_cell, hdr_cell, sc_cell, rt_cell, port_cell)

    return table


def display_summary(all_results: list[dict]) -> None:
    """Print a summary panel with aggregate statistics."""
    total    = len(all_results)
    ok_cnt   = sum(1 for e in all_results
                   if e.get("availability", {}).get("status") == "OK")
    warn_cnt = sum(1 for e in all_results
                   if e.get("availability", {}).get("status") == "WARN")
    fail_cnt = sum(1 for e in all_results
                   if e.get("availability", {}).get("status") == "FAIL")

    # Count total open ports
    total_open_ports = sum(
        len(e.get("ports", {}).get("open_ports", []))
        for e in all_results if e.get("ports")
    )

    panel = Panel(
        f"[bold white]Total Servers:[/] [cyan]{total}[/]   "
        f"[bold green]✓ OK:[/] {ok_cnt}   "
        f"[bold yellow]⚠ WARN:[/] {warn_cnt}   "
        f"[bold red]✗ FAIL:[/] {fail_cnt}   "
        f"[bold white]Open Ports Found:[/] [magenta]{total_open_ports}[/]",
        border_style="bright_blue",
        box=box.ROUNDED,
    )
    CONSOLE.print(panel)


# ═══════════════════════════════════════════════════════════
# CORE LOOP
# ═══════════════════════════════════════════════════════════

def run_scan_cycle(servers: list[dict]) -> list[dict]:
    """Execute all checks concurrently and return sorted results."""
    all_results: list[dict] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=CONSOLE,
        transient=True,
    ) as progress:
        task = progress.add_task(
            f"[cyan]Scanning {len(servers)} server(s)...", total=len(servers)
        )
        with ThreadPoolExecutor(max_workers=min(10, len(servers))) as pool:
            futures = {pool.submit(scan_server, s): s for s in servers}
            for future in as_completed(futures):
                srv = futures[future]
                try:
                    all_results.append(future.result())
                except Exception as exc:
                    all_results.append({
                        "server_name": srv["name"],
                        "host":        srv["host"],
                        "port":        srv["port"],
                        "timestamp":   datetime.utcnow().isoformat(),
                        "error":       str(exc),
                    })
                progress.update(task, advance=1)

    all_results.sort(key=lambda x: x["server_name"])
    return all_results


def run_exports(all_results: list[dict], formats: list[str],
                export_dir: str) -> None:
    """Export results in requested formats (json / csv)."""
    if "both" in formats:
        formats = ["json", "csv"]
    for fmt in formats:
        try:
            if fmt == "json":
                path = export_json(all_results, export_dir)
                CONSOLE.print(f"  [green]✓[/] JSON → [bold]{path}[/]")
            elif fmt == "csv":
                path = export_csv(all_results, export_dir)
                CONSOLE.print(f"  [green]✓[/] CSV  → [bold]{path}[/]")
        except Exception as exc:
            CONSOLE.print(f"  [red]✗[/] {fmt.upper()} export failed: {exc}")


# ═══════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="ServerWatch — Interactive Website Health & Security Monitor"
    )
    parser.add_argument("--export", nargs="+", choices=["json", "csv", "both"],
                        default=["json", "csv"], help="Export format(s)")
    parser.add_argument("--export-dir", default="reports",
                        help="Export directory (default: reports/)")
    parser.add_argument("--interval", type=int, default=0,
                        help="Continuous monitor interval in seconds (0 = one-shot)")
    return parser.parse_args()


def main() -> None:
    """Application entry point."""
    args = parse_args()
    print_banner()

    # ── Collect targets from user ──
    servers = get_servers_from_user()
    if not servers:
        CONSOLE.print("[bold red]No servers entered. Exiting.[/]")
        return

    CONSOLE.print(
        f"\n[bold cyan]✔ Loaded [white]{len(servers)}[/] server(s) "
        f"from user input.[/]\n"
    )

    # ── Scan loop (one-shot or continuous) ──
    iteration = 0
    while True:
        iteration += 1
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        CONSOLE.rule(f"[bold cyan]Iteration #{iteration} — {now}")

        results = run_scan_cycle(servers)

        CONSOLE.print("\n")
        CONSOLE.print(build_results_table(results))
        display_summary(results)

        run_exports(results, args.export, args.export_dir)

        if args.interval <= 0:
            CONSOLE.print("\n[bold green]✔ Scan complete. Exiting.[/]")
            break

        CONSOLE.print(
            f"\n[dim]Next scan in {args.interval}s... (Ctrl+C to stop)[/]\n"
        )
        try:
            time.sleep(args.interval)
        except KeyboardInterrupt:
            CONSOLE.print("\n[bold yellow]Interrupted. Exiting.[/]")
            break


# ═══════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        CONSOLE.print("\n[bold yellow]Exited by user.[/]")
    except Exception:
        traceback.print_exc()
        sys.exit(1)
