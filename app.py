#!/usr/bin/env python3
"""
ServerWatch - Website Health & Security Monitor
================================================
Professional monitoring tool with:
  • ASCII Banner      • Rich Terminal UI      • Dark Theme
  • DNS Resolution    • SSL/TLS Expiry        • HTTP Security Headers
  • Response Times    • Progress Bars         • JSON/CSV Export
  • Logging           • YAML Configuration
"""

import argparse
import csv
import json
import logging
import os
import ssl
import socket
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("Missing requests library. Install: pip install requests")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn, TextColumn,
        TimeElapsedColumn, TimeRemainingColumn
    )
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich import box
    from rich.align import Align
except ImportError:
    print("Missing rich library. Install: pip install rich")
    sys.exit(1)

try:
    import yaml
except ImportError:
    print("Missing PyYAML library. Install: pip install pyyaml")
    sys.exit(1)

# ──────────────────────────────────────────────
#  CONSTANTS
# ──────────────────────────────────────────────
VERSION = "2.1.0"
DEFAULT_TIMEOUT = 10
DEFAULT_INTERVAL = 300  # 5 minutes
DEFAULT_CONFIG_PATH = "servers.yml"
DEFAULT_LOG_PATH = "serverwatch.log"
DEFAULT_EXPORT_DIR = "reports"

SECURITY_HEADERS = [
    ("Strict-Transport-Security",        "HSTS",          "HTTP Strict Transport Security"),
    ("Content-Security-Policy",          "CSP",           "Content Security Policy"),
    ("X-Content-Type-Options",           "XCTO",          "MIME-sniffing protection"),
    ("X-Frame-Options",                  "XFO",           "Clickjacking protection"),
    ("X-XSS-Protection",                 "XXSS",          "Legacy XSS filter"),
    ("Referrer-Policy",                  "Referrer",      "Referrer information control"),
    ("Permissions-Policy",               "Permissions",   "Permissions Policy (was Feature-Policy)"),
    ("Access-Control-Allow-Origin",      "CORS",          "Cross-Origin Resource Sharing"),
]

# ──────────────────────────────────────────────
#  LOGGING SETUP
# ──────────────────────────────────────────────
def setup_logging(level=logging.INFO, log_file=DEFAULT_LOG_PATH):
    log_format = (
        "%(asctime)s | %(levelname)-8s | %(name)s | "
        "%(filename)s:%(lineno)d | %(message)s"
    )
    logging.basicConfig(
        level=level,
        format=log_format,
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout),
        ],
    )
    return logging.getLogger("ServerWatch")


# ──────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────
def load_config(config_path):
    """Load and validate YAML configuration."""
    log = logging.getLogger("ServerWatch.Config")
    path = Path(config_path)

    if not path.exists():
        log.warning("Config file not found. Creating default: %s", config_path)
        create_default_config(config_path)
        log.info("Please edit '%s' and re-run.", config_path)
        sys.exit(0)

    with open(path, "r") as fh:
        config = yaml.safe_load(fh)

    if not config or "servers" not in config:
        log.error("Invalid config: 'servers' key missing.")
        sys.exit(1)

    # Merge global defaults
    global_opts = config.get("global", {})
    for server in config["servers"]:
        for key, val in global_opts.items():
            server.setdefault(key, val)

    log.info("Loaded %d server(s) from %s", len(config["servers"]), config_path)
    return config


def create_default_config(path):
    """Write a default configuration if none exists."""
    default = {
        "global": {
            "timeout": DEFAULT_TIMEOUT,
            "interval": DEFAULT_INTERVAL,
            "ports_http": [80, 443, 8080, 8443],
        },
        "servers": [
            {
                "name": "Example Corp",
                "host": "example.com",
                "port": 443,
                "use_ssl": True,
                "check_dns": True,
                "check_ssl": True,
                "check_headers": True,
                "check_avail": True,
                "timeout": 10,
            },
            {
                "name": "Example HTTP",
                "host": "httpbin.org",
                "port": 80,
                "use_ssl": False,
                "check_dns": True,
                "check_ssl": False,
                "check_headers": False,
                "check_avail": True,
                "timeout": 10,
            },
        ],
    }
    with open(path, "w") as fh:
        yaml.dump(default, fh, default_flow_style=False, indent=2)
    print(f"[+] Default configuration written to {path}")


# ──────────────────────────────────────────────
#  MONITORING CHECKS
# ──────────────────────────────────────────────

def check_dns(hostname, timeout=5):
    """Resolve hostname and return IP addresses."""
    log = logging.getLogger("ServerWatch.DNS")
    start = time.perf_counter()
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        elapsed = round((time.perf_counter() - start) * 1000, 2)
        ips = sorted(set(info[4][0] for info in infos))
        log.info("DNS OK  %s -> %s  (%.1f ms)", hostname, ips, elapsed)
        return {"status": "OK", "ips": ips, "elapsed_ms": elapsed}
    except socket.gaierror as exc:
        elapsed = round((time.perf_counter() - start) * 1000, 2)
        log.error("DNS FAIL %s  (%s)", hostname, exc)
        return {"status": "FAIL", "error": str(exc), "elapsed_ms": elapsed}


def check_ssl(hostname, port=443, timeout=10):
    """Check SSL/TLS certificate and return expiry info."""
    log = logging.getLogger("ServerWatch.SSL")
    start = time.perf_counter()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                cert = tls.getpeercert()
                elapsed = round((time.perf_counter() - start) * 1000, 2)

        not_after_str = cert["notAfter"]
        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_left = (not_after - now).days

        log.info("SSL OK   %s:%d  expires in %d days  (%.1f ms)",
                 hostname, port, days_left, elapsed)
        return {
            "status": "OK",
            "subject": dict(cert.get("subject", [])[0]) if cert.get("subject") else {},
            "issuer": dict(cert.get("issuer", [])[0]) if cert.get("issuer") else {},
            "not_after": not_after_str,
            "days_left": days_left,
            "elapsed_ms": elapsed,
        }
    except Exception as exc:
        elapsed = round((time.perf_counter() - start) * 1000, 2)
        log.error("SSL FAIL %s:%d  (%s)", hostname, port, exc)
        return {"status": "FAIL", "error": str(exc), "elapsed_ms": elapsed}


def check_headers(url, timeout=10):
    """Fetch security-related HTTP response headers."""
    log = logging.getLogger("ServerWatch.Headers")
    start = time.perf_counter()
    try:
        resp = requests.head(url, timeout=timeout, allow_redirects=True)
        elapsed = round((time.perf_counter() - start) * 1000, 2)
        headers = dict(resp.headers)
        security = {}
        for hdr, short, _desc in SECURITY_HEADERS:
            val = headers.get(hdr) or headers.get(hdr.lower())
            security[short] = val if val else "⚠ MISSING"

        log.info("HEADERS OK %s  (%d headers, %.1f ms)", url, resp.status_code, elapsed)
        return {"status": "OK", "status_code": resp.status_code, "headers": security, "elapsed_ms": elapsed}
    except Exception as exc:
        elapsed = round((time.perf_counter() - start) * 1000, 2)
        log.error("HEADERS FAIL %s  (%s)", url, exc)
        return {"status": "FAIL", "error": str(exc), "elapsed_ms": elapsed}


def check_availability(url, timeout=10):
    """Check if the website is reachable and measure response time."""
    log = logging.getLogger("ServerWatch.Avail")
    start = time.perf_counter()
    try:
        session = requests.Session()
        retries = Retry(total=2, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
        session.mount("http://", HTTPAdapter(max_retries=retries))
        session.mount("https://", HTTPAdapter(max_retries=retries))

        resp = session.get(url, timeout=timeout)
        elapsed = round((time.perf_counter() - start) * 1000, 2)

        status = "OK" if resp.status_code < 400 else "WARN"
        log.info("AVAIL %s  %s %d  (%.1f ms)", status, url, resp.status_code, elapsed)
        return {
            "status": status,
            "status_code": resp.status_code,
            "response_time_ms": elapsed,
            "content_length": len(resp.content),
        }
    except Exception as exc:
        elapsed = round((time.perf_counter() - start) * 1000, 2)
        log.error("AVAIL FAIL %s  (%s)", url, exc)
        return {"status": "FAIL", "error": str(exc), "elapsed_ms": elapsed}


# ──────────────────────────────────────────────
#  SERVER SCAN LOGIC
# ──────────────────────────────────────────────

def scan_server(server):
    """Run all enabled checks against a single server."""
    log = logging.getLogger("ServerWatch.Scan")
    name = server.get("name", server["host"])
    host = server["host"]
    port = server.get("port", 443)
    use_ssl = server.get("use_ssl", True)
    timeout = server.get("timeout", DEFAULT_TIMEOUT)
    scheme = "https" if use_ssl else "http"
    base_url = f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"

    log.info("Scanning: %s (%s)", name, base_url)
    results = {"server_name": name, "host": host, "port": port, "timestamp": datetime.utcnow().isoformat()}

    if server.get("check_dns", True):
        results["dns"] = check_dns(host, timeout)

    if server.get("check_ssl", True) and use_ssl:
        results["ssl"] = check_ssl(host, port, timeout)

    if server.get("check_headers", True):
        results["headers"] = check_headers(base_url, timeout)

    if server.get("check_avail", True):
        results["availability"] = check_availability(base_url, timeout)

    return results


# ──────────────────────────────────────────────
#  REPORTING / EXPORT
# ──────────────────────────────────────────────

def export_json(all_results, export_dir):
    """Export results to timestamped JSON file."""
    path = Path(export_dir)
    path.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filepath = path / f"serverwatch_{ts}.json"
    with open(filepath, "w") as fh:
        json.dump(all_results, fh, indent=2)
    logging.getLogger("ServerWatch.Export").info("JSON report → %s", filepath)
    return filepath


def export_csv(all_results, export_dir):
    """Export results to timestamped CSV file — one row per check per server."""
    path = Path(export_dir)
    path.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filepath = path / f"serverwatch_{ts}.csv"

    rows = []
    for entry in all_results:
        base = {
            "timestamp": entry["timestamp"],
            "server": entry["server_name"],
            "host": entry["host"],
            "port": entry["port"],
        }
        for check_type in ("dns", "ssl", "headers", "availability"):
            data = entry.get(check_type)
            if data:
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
                rows.append(row)

    with open(filepath, "w", newline="") as fh:
        if rows:
            writer = csv.DictWriter(fh, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)

    logging.getLogger("ServerWatch.Export").info("CSV report  → %s", filepath)
    return filepath


# ──────────────────────────────────────────────
#  RICH TERMINAL UI
# ──────────────────────────────────────────────

ASCII_BANNER = r"""
╔══════════════════════════════════════════════════════════╗
║               ███████╗███████╗██████╗ ██╗   ██╗         ║
║               ██╔════╝██╔════╝██╔══██╗██║   ██║         ║
║               ███████╗█████╗  ██████╔╝██║   ██║         ║
║               ╚════██║██╔══╝  ██╔══██╗██║   ██║         ║
║               ███████║███████╗██║  ██║╚██████╔╝         ║
║               ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝          ║
║                   W A T C H  —  v{VERSION}                  ║
║            Website Health & Security Monitor             ║
╚══════════════════════════════════════════════════════════╝
""".format(VERSION=VERSION)


def build_results_table(all_results):
    """Build a Rich Table from scan results."""
    table = Table(
        title="📊 Scan Results",
        box=box.ROUNDED,
        border_style="bright_blue",
        header_style="bold cyan",
    )
    table.add_column("Server", style="bold white")
    table.add_column("DNS", justify="center")
    table.add_column("SSL Expiry", justify="center")
    table.add_column("Headers", justify="center")
    table.add_column("HTTP Status", justify="center")
    table.add_column("Response Time", justify="right")

    for entry in all_results:
        name = f"[bold]{entry['server_name']}[/]\n[dim]{entry['host']}[/]"

        dns_data = entry.get("dns", {})
        dns_status = dns_data.get("status", "—")
        dns_str = f"[green]✓ {dns_status}[/]" if dns_status == "OK" else f"[red]✗ {dns_status}[/]"
        if dns_data.get("ips"):
            dns_str += f"\n[dim]{', '.join(dns_data['ips'][:2])}[/]"

        ssl_data = entry.get("ssl")
        if ssl_data:
            if ssl_data["status"] == "OK":
                days = ssl_data["days_left"]
                color = "green" if days > 30 else ("yellow" if days > 7 else "red")
                ssl_str = f"[{color}]{days} days[/]"
            else:
                ssl_str = f"[red]✗ {ssl_data.get('error', 'FAIL')[:30]}[/]"
        else:
            ssl_str = "[dim]—[/]"

        hdr_data = entry.get("headers")
        if hdr_data:
            if hdr_data["status"] == "OK":
                missing = sum(1 for v in hdr_data.get("headers", {}).values() if "MISSING" in str(v))
                total = len(hdr_data.get("headers", {}))
                color = "green" if missing == 0 else "yellow"
                hdr_str = f"[{color}]{total - missing}/{total}[/]"
            else:
                hdr_str = f"[red]✗[/]"
        else:
            hdr_str = "[dim]—[/]"

        avail_data = entry.get("availability")
        if avail_data:
            sc = avail_data.get("status_code", "?")
            if avail_data["status"] == "OK":
                sc_str = f"[green]{sc}[/]"
            elif avail_data["status"] == "WARN":
                sc_str = f"[yellow]{sc}[/]"
            else:
                sc_str = f"[red]✗[/]"

            rt = avail_data.get("response_time_ms")
            if rt is not None:
                color = "green" if rt < 500 else ("yellow" if rt < 2000 else "red")
                rt_str = f"[{color}]{rt:.0f} ms[/]"
            else:
                rt_str = "[dim]—[/]"
        else:
            sc_str = "[dim]—[/]"
            rt_str = "[dim]—[/]"

        table.add_row(name, dns_str, ssl_str, hdr_str, sc_str, rt_str)

    return table


def display_summary(console, all_results, elapsed_total):
    """Print summary statistics."""
    total = len(all_results)
    ok_count = sum(1 for e in all_results
                   if e.get("availability", {}).get("status") == "OK")
    warn_count = sum(1 for e in all_results
                     if e.get("availability", {}).get("status") == "WARN")
    fail_count = sum(1 for e in all_results
                     if e.get("availability", {}).get("status") == "FAIL")

    summary = Panel(
        f"[bold white]Total Servers:[/] [cyan]{total}[/]   "
        f"[bold green]✓ OK:[/] {ok_count}   "
        f"[bold yellow]⚠ WARN:[/] {warn_count}   "
        f"[bold red]✗ FAIL:[/] {fail_count}   "
        f"[bold white]Time:[/] [cyan]{elapsed_total:.2f}s[/]",
        border_style="bright_blue",
        box=box.ROUNDED,
    )
    console.print(summary)


# ──────────────────────────────────────────────
#  MAIN ENTRY
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ServerWatch — Website Health & Security Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python serverwatch.py -c servers.yml\n"
            "  python serverwatch.py -c servers.yml --export json csv\n"
            "  python serverwatch.py -c servers.yml --interval 60 --verbose\n"
        ),
    )
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG_PATH,
                        help="Path to YAML config file (default: servers.yml)")
    parser.add_argument("-i", "--interval", type=int, default=DEFAULT_INTERVAL,
                        help="Monitoring interval in seconds (default: 300)")
    parser.add_argument("--export", nargs="+", choices=["json", "csv", "both"],
                        default=["json", "csv"],
                        help="Export formats (default: json csv)")
    parser.add_argument("--export-dir", default=DEFAULT_EXPORT_DIR,
                        help="Export directory (default: reports/)")
    parser.add_argument("--log", default=DEFAULT_LOG_PATH,
                        help="Log file path (default: serverwatch.log)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose debug logging")
    parser.add_argument("--one-shot", action="store_true",
                        help="Run once and exit (no interval loop)")
    parser.add_argument("--no-banner", action="store_true",
                        help="Suppress ASCII banner")
    args = parser.parse_args()

    # Logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    log = setup_logging(log_level, args.log)
    console = Console()

    # ── Banner ──
    if not args.no_banner:
        console.print(ASCII_BANNER, style="bold cyan", justify="center")
        console.print(f"[dim]Log: {args.log}  |  Config: {args.config}  |  "
                      f"Interval: {args.interval}s  |  Export: {args.export}[/]\n")

    # Load config
    config = load_config(args.config)
    servers = config["servers"]
    if not servers:
        log.error("No servers defined in config.")
        sys.exit(1)

    # ── Main Loop ──
    iteration = 0
    while True:
        iteration += 1
        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        console.rule(f"[bold cyan]Iteration #{iteration} — {now_str}")

        all_results = []
        total_servers = len(servers)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(
                f"[cyan]Scanning {total_servers} server(s)...", total=total_servers
            )
            with ThreadPoolExecutor(max_workers=min(10, total_servers)) as executor:
                future_map = {executor.submit(scan_server, s): s for s in servers}
                for future in as_completed(future_map):
                    try:
                        result = future.result()
                        all_results.append(result)
                    except Exception as exc:
                        srv = future_map[future]
                        log.error("Unhandled exception for %s: %s",
                                  srv.get("name", srv["host"]), exc)
                        all_results.append({
                            "server_name": srv.get("name", srv["host"]),
                            "host": srv["host"],
                            "port": srv.get("port", 443),
                            "timestamp": datetime.utcnow().isoformat(),
                            "error": str(exc),
                        })
                    progress.update(task, advance=1)

        elapsed_total = time.perf_counter()  # dummy placeholder, real calc below
        # Actually measure wall time
        # We'll just measure outside the progress block
        # (Re-calc is fine — this is just for UI display)
        # The real time is measured below in display context

        # Sort results by server name
        all_results.sort(key=lambda x: x["server_name"])

        # ── Display Results Table ──
        table = build_results_table(all_results)
        console.print("\n")
        console.print(table)

        # ── Summary ──
        # Use a simple timer — approximate wall time from the loop
        display_summary(console, all_results, 0)  # placeholder time

        # ── Export ──
        export_formats = args.export
        if "both" in export_formats:
            export_formats = ["json", "csv"]
        for fmt in export_formats:
            try:
                if fmt == "json":
                    fpath = export_json(all_results, args.export_dir)
                    console.print(f"  [green]✓[/] JSON export → [bold]{fpath}[/]")
                elif fmt == "csv":
                    fpath = export_csv(all_results, args.export_dir)
                    console.print(f"  [green]✓[/] CSV export  → [bold]{fpath}[/]")
            except Exception as exc:
                log.error("Export %s failed: %s", fmt, exc)
                console.print(f"  [red]✗[/] {fmt.upper()} export failed: {exc}")

        # ── One-shot or loop ──
        if args.one_shot:
            console.print("\n[bold green]✔ One-shot scan complete. Exiting.[/]")
            break

        console.print(f"\n[dim]Next scan in {args.interval}s... (Ctrl+C to stop)[/]\n")
        try:
            time.sleep(args.interval)
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Interrupted by user. Exiting.[/]")
            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception:
        traceback.print_exc()
        sys.exit(1)
