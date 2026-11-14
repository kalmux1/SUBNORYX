#!/usr/bin/env python3
"""
SUBNORYX: Fast Async Passive Subdomain Enumerator & Recon Engine
Author: Kalmux
License: GPL-2.0
"""

import asyncio
import argparse
import itertools
import sys
import re
import socket
from pathlib import Path
from urllib.parse import urlparse
import httpx

# Optional high-speed async DNS library
try:
    import aiodns
    HAS_AIODNS = True
except ImportError:
    HAS_AIODNS = False

# Optional PyYAML support
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# ANSI Colors & Styles
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BLUE = "\033[94m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

DEFAULT_CONFIG_PATH = Path.home() / ".config" / "subnoryx" / "config.yaml"

DEFAULT_CONFIG_TEMPLATE = """# =====================================================================
# SUBNORYX Configuration File (v1.0.0)
# =====================================================================
# Leave API keys empty ("") to use keyless OSINT engines (crt.sh, HackerTarget, etc.)

api_keys:
  alienvault: ""
  bevigil: ""
  bufferover: ""
  builtwith: ""
  c99: ""
  censys: ""
  certspotter: ""
  chaos: ""
  chinaz: ""
  digitalyama: ""
  dnsdb: ""
  dnsdumpster: ""
  dnsrepo: ""
  domainsproject: ""
  driftnet: ""
  fofa: ""
  fullhunt: ""
  github: ""
  hackertarget: ""
  intelx: ""
  leakix: ""
  merklemap: ""
  netlas: ""
  onyphe: ""
  profundis: ""
  pugrecon: ""
  quake: ""
  reconeer: ""
  redhuntlabs: ""
  robtex: ""
  rsecloud: ""
  securitytrails: ""
  shodan: ""
  submd: ""
  threatbook: ""
  urlscan: ""
  virustotal: ""
  whoisxmlapi: ""
  windvane: ""
  zoomeyeapi: ""

headers:
  User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
"""


def print_banner():
    banner = f"""{CYAN}{BOLD}
   _____ __  ______  _   ______  ______  ___  __
  / ___// / / / __ )/ | / / __ \\/ __ \\ \\/ / |/ /
  \\__ \\/ / / / __  /  |/ / / / / /_/ /\\  /|   / 
 ___/ / /_/ / /_/ / /|  / /_/ / _, _/ / //   |  
/____/\\____/_____/_/ |_/\\____/_/ |_| /_//_/|_|  
{RESET}{MAGENTA}   # SUBNORYX v1.0.0 — Async Subdomain Recon Engine | By Kalmux{RESET}
"""
    print(banner)


def print_manual():
    print_banner()
    manual_text = f"""{BOLD}{CYAN}SUBNORYX MANIFEST & USER MANUAL{RESET}
{DIM}───────────────────────────────────────────────────────────────────────────────{RESET}

{BOLD}NAME{RESET}
    subnoryx - High-performance asynchronous passive subdomain enumeration engine

{BOLD}SYNOPSIS{RESET}
    {GREEN}subnoryx{RESET} [{BOLD}-d{RESET} DOMAIN] [{BOLD}-i{RESET} FILE] [{BOLD}-r{RESET}] [{BOLD}--probe{RESET}] [{BOLD}-t{RESET} THREADS] [{BOLD}-o{RESET} FILE] [{BOLD}-s{RESET}]

{BOLD}DESCRIPTION{RESET}
    SUBNORYX is an asynchronous OSINT recon framework designed for bug bounty hunters 
    and penetration testers. Unlike traditional scrapers that rely on fragile HTML 
    parsing or blocking multiprocessing models, SUBNORYX queries high-speed public 
    APIs, Certificate Transparency logs, and passive DNS repositories concurrently.

{BOLD}OPTIONS{RESET}
    {BOLD}-d, --domain{RESET} DOMAIN
        Specify a single target apex domain (e.g., {YELLOW}prismlife.com{RESET}).

    {BOLD}-i, --input{RESET} FILE
        Specify a scope file containing a list of target domains (one per line).

    {BOLD}-r, --resolve{RESET}
        Filter out dead subdomains ({RED}NXDOMAIN{RESET}) using asynchronous DNS resolution 
        ({CYAN}aiodns{RESET} / socket lookup).

    {BOLD}--probe{RESET}
        Probe verified live subdomains for active HTTP/HTTPS web services, HTTP status 
        codes, and HTML page titles.

    {BOLD}-t, --threads{RESET} THREADS
        Set concurrency limit for DNS resolution and HTTP probing (default: {YELLOW}100{RESET}).

    {BOLD}--resolvers{RESET} LIST
        Comma-separated list of custom DNS resolvers (default: {YELLOW}1.1.1.1,8.8.8.8,9.9.9.9{RESET}).

    {BOLD}-o, --output{RESET} FILE
        Save cleaned, unique subdomain list to the specified file path.

    {BOLD}-H, --header{RESET} KEY:VALUE
        Inject custom HTTP headers (e.g., {YELLOW}-H "X-Bug-Bounty: HackerOne-kalmux"{RESET}). 
        By default, no bug bounty headers are injected.

    {BOLD}-c, --config{RESET} PATH
        Path to YAML configuration file (default: {YELLOW}~/.config/subnoryx/config.yaml{RESET}).

    {BOLD}-s, --silent{RESET}
        Silent mode. Suppresses banners and logs, outputting only raw subdomains 
        for seamless terminal piping ({GREEN}subnoryx -d target.com -s | httpx{RESET}).

    {BOLD}--man{RESET}
        Display this comprehensive manual page and exit.

    {BOLD}-v, --verbose{RESET}
        Enable verbose output during enumeration.

    {BOLD}-V, --version{RESET}
        Display version information and exit.

{BOLD}CONFIGURATION & API KEYS{RESET}
    SUBNORYX supports over 40 API keys out of the box. Configure your keys in:
    {CYAN}~/.config/subnoryx/config.yaml{RESET}

{BOLD}AUTHOR{RESET}
    Created by Kalmux. Licensed under GPL-2.0.
{DIM}───────────────────────────────────────────────────────────────────────────────{RESET}
"""
    print(manual_text)


class Spinner:
    """Sleek terminal spinner animation for background tasks."""
    def __init__(self, message="Working..."):
        self.message = message
        self.spinner = itertools.cycle(["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
        self.running = False
        self.task = None

    async def _animate(self):
        while self.running:
            sys.stdout.write(f"\r{CYAN}{next(self.spinner)}{RESET} {self.message}")
            sys.stdout.flush()
            await asyncio.sleep(0.08)

    def start(self):
        self.running = True
        self.task = asyncio.create_task(self._animate())

    async def stop(self, success_msg=""):
        self.running = False
        if self.task:
            try:
                await self.task
            except Exception:
                pass
        sys.stdout.write("\r\033[K")  # Clear line
        if success_msg:
            print(f"{GREEN}[✓]{RESET} {success_msg}")


def init_or_load_config(config_path: Path) -> dict:
    config = {
        "api_keys": {
            "alienvault": "", "bevigil": "", "bufferover": "", "builtwith": "", "c99": "",
            "censys": "", "certspotter": "", "chaos": "", "chinaz": "", "digitalyama": "",
            "dnsdb": "", "dnsdumpster": "", "dnsrepo": "", "domainsproject": "", "driftnet": "",
            "fofa": "", "fullhunt": "", "github": "", "hackertarget": "", "intelx": "",
            "leakix": "", "merklemap": "", "netlas": "", "onyphe": "", "profundis": "",
            "pugrecon": "", "quake": "", "reconeer": "", "redhuntlabs": "", "robtex": "",
            "rsecloud": "", "securitytrails": "", "shodan": "", "submd": "", "threatbook": "",
            "urlscan": "", "virustotal": "", "whoisxmlapi": "", "windvane": "", "zoomeyeapi": ""
        },
        "headers": {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        },
    }

    if not config_path.exists():
        try:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text(DEFAULT_CONFIG_TEMPLATE, encoding="utf-8")
        except Exception:
            pass
        return config

    try:
        raw_text = config_path.read_text(encoding="utf-8")
        if HAS_YAML:
            loaded = yaml.safe_load(raw_text) or {}
            if "api_keys" in loaded and isinstance(loaded["api_keys"], dict):
                config["api_keys"].update({k: str(v or "") for k, v in loaded["api_keys"].items()})
            if "headers" in loaded and isinstance(loaded["headers"], dict):
                config["headers"].update({k: str(v) for k, v in loaded["headers"].items() if v})
        else:
            for line in raw_text.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or ":" not in line:
                    continue
                k, v = line.split(":", 1)
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k in config["api_keys"]:
                    config["api_keys"][k] = v
    except Exception as e:
        print(f"{YELLOW}[!] Warning: Could not parse {config_path}: {e}{RESET}")

    return config


def normalize_domain_input(raw: str) -> str:
    item = raw.strip().lower()
    if not item or item.startswith("#"):
        return ""
    if "://" in item:
        parsed = urlparse(item)
        item = parsed.hostname or ""
    else:
        item = item.split("/")[0].split(":")[0]
    item = item.lstrip("*.")
    return item


def clean_subdomain(sub: str, domain: str) -> str | None:
    if not sub:
        return None
    sub = sub.strip().lower().lstrip("*.")
    if sub.endswith(f".{domain}") or sub == domain:
        if re.match(r"^[a-z0-9._-]+$", sub):
            return sub
    return None


# =====================================================================
# PASSIVE OSINT SOURCES
# =====================================================================

async def fetch_crtsh(client: httpx.AsyncClient, domain: str) -> set[str]:
    subs = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        resp = await client.get(url, timeout=30.0)
        if resp.status_code == 200:
            for entry in resp.json():
                for name in entry.get("name_value", "").splitlines():
                    cleaned = clean_subdomain(name, domain)
                    if cleaned:
                        subs.add(cleaned)
    except Exception:
        pass
    return subs


async def fetch_hackertarget(client: httpx.AsyncClient, domain: str) -> set[str]:
    subs = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        resp = await client.get(url, timeout=20.0)
        if resp.status_code == 200 and "API count exceeded" not in resp.text:
            for line in resp.text.splitlines():
                host = line.split(",")[0]
                cleaned = clean_subdomain(host, domain)
                if cleaned:
                    subs.add(cleaned)
    except Exception:
        pass
    return subs


async def fetch_alienvault(client: httpx.AsyncClient, domain: str) -> set[str]:
    subs = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        resp = await client.get(url, timeout=25.0)
        if resp.status_code == 200:
            for record in resp.json().get("passive_dns", []):
                cleaned = clean_subdomain(record.get("hostname", ""), domain)
                if cleaned:
                    subs.add(cleaned)
    except Exception:
        pass
    return subs


async def fetch_anubis(client: httpx.AsyncClient, domain: str) -> set[str]:
    subs = set()
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    try:
        resp = await client.get(url, timeout=20.0)
        if resp.status_code == 200:
            for item in resp.json():
                cleaned = clean_subdomain(item, domain)
                if cleaned:
                    subs.add(cleaned)
    except Exception:
        pass
    return subs


async def fetch_wayback(client: httpx.AsyncClient, domain: str) -> set[str]:
    subs = set()
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    try:
        resp = await client.get(url, timeout=30.0)
        if resp.status_code == 200:
            data = resp.json()
            for row in data[1:]:
                if row:
                    parsed = urlparse(row[0])
                    cleaned = clean_subdomain(parsed.hostname or "", domain)
                    if cleaned:
                        subs.add(cleaned)
    except Exception:
        pass
    return subs


async def fetch_urlscan(client: httpx.AsyncClient, domain: str, api_key: str) -> set[str]:
    subs = set()
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000"
    headers = {"API-Key": api_key} if api_key else {}
    try:
        resp = await client.get(url, headers=headers, timeout=25.0)
        if resp.status_code == 200:
            for item in resp.json().get("results", []):
                page_domain = item.get("page", {}).get("domain", "")
                task_domain = item.get("task", {}).get("domain", "")
                for candidate in (page_domain, task_domain):
                    cleaned = clean_subdomain(candidate, domain)
                    if cleaned:
                        subs.add(cleaned)
    except Exception:
        pass
    return subs


async def fetch_virustotal(client: httpx.AsyncClient, domain: str, api_key: str) -> set[str]:
    subs = set()
    if not api_key:
        return subs
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    try:
        resp = await client.get(url, headers={"x-apikey": api_key}, timeout=20.0)
        if resp.status_code == 200:
            for item in resp.json().get("data", []):
                cleaned = clean_subdomain(item.get("id", ""), domain)
                if cleaned:
                    subs.add(cleaned)
    except Exception:
        pass
    return subs


async def fetch_certspotter(client: httpx.AsyncClient, domain: str, api_key: str) -> set[str]:
    subs = set()
    if not api_key:
        return subs
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    try:
        resp = await client.get(url, headers={"Authorization": f"Bearer {api_key}"}, timeout=20.0)
        if resp.status_code == 200:
            for entry in resp.json():
                for name in entry.get("dns_names", []):
                    cleaned = clean_subdomain(name, domain)
                    if cleaned:
                        subs.add(cleaned)
    except Exception:
        pass
    return subs


async def fetch_chaos(client: httpx.AsyncClient, domain: str, api_key: str) -> set[str]:
    subs = set()
    if not api_key:
        return subs
    url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
    try:
        resp = await client.get(url, headers={"Authorization": api_key}, timeout=20.0)
        if resp.status_code == 200:
            for sub in resp.json().get("subdomains", []):
                cleaned = clean_subdomain(f"{sub}.{domain}", domain)
                if cleaned:
                    subs.add(cleaned)
    except Exception:
        pass
    return subs


# =====================================================================
# DNS RESOLUTION & HTTP PROBING
# =====================================================================

async def resolve_single_host(
    sub: str,
    sem: asyncio.Semaphore,
    resolver: "aiodns.DNSResolver | None",
    loop: asyncio.AbstractEventLoop,
) -> tuple[str, list[str]]:
    async with sem:
        if resolver is not None:
            try:
                res = await resolver.query(sub, "A")
                ips = sorted({r.host for r in res})
                return (sub, ips)
            except Exception:
                return (sub, [])
        else:
            try:
                infos = await loop.getaddrinfo(sub, None, family=socket.AF_INET)
                ips = sorted({info[4][0] for info in infos if info[4]})
                return (sub, ips)
            except Exception:
                return (sub, [])


async def resolve_subdomains(
    subdomains: set[str], concurrency: int, nameservers: list[str], quiet: bool
) -> dict[str, list[str]]:
    if not subdomains:
        return {}

    spinner = Spinner(f"Resolving {len(subdomains)} subdomains via async DNS...")
    if not quiet:
        spinner.start()

    sem = asyncio.Semaphore(concurrency)
    loop = asyncio.get_running_loop()
    resolver = aiodns.DNSResolver(nameservers=nameservers, timeout=3.0, tries=2) if HAS_AIODNS else None

    tasks = [resolve_single_host(sub, sem, resolver, loop) for sub in sorted(subdomains)]
    results = await asyncio.gather(*tasks)

    live_map = {sub: ips for sub, ips in results if ips}
    if not quiet:
        await spinner.stop(f"DNS Resolution complete: {len(live_map)}/{len(subdomains)} live hosts verified.")
    return live_map


async def probe_single_host(
    client: httpx.AsyncClient, sub: str, sem: asyncio.Semaphore
) -> tuple[str, str]:
    async with sem:
        for scheme in ("https", "http"):
            url = f"{scheme}://{sub}"
            try:
                resp = await client.get(url, timeout=8.0)
                title_match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                title = title_match.group(1).strip().replace("\n", " ")[:60] if title_match else ""
                info = f"{url} [{resp.status_code}]" + (f" [{title}]" if title else "")
                return (sub, info)
            except Exception:
                continue
        return (sub, "")


async def probe_http_hosts(
    subdomains: list[str], headers: dict[str, str], concurrency: int, quiet: bool
) -> dict[str, str]:
    if not subdomains:
        return {}
    spinner = Spinner(f"Probing {len(subdomains)} hosts for active HTTP/HTTPS services...")
    if not quiet:
        spinner.start()

    sem = asyncio.Semaphore(min(concurrency, 50))
    async with httpx.AsyncClient(headers=headers, follow_redirects=True, verify=False) as client:
        tasks = [probe_single_host(client, sub, sem) for sub in subdomains]
        results = await asyncio.gather(*tasks)

    probed = {sub: info for sub, info in results if info}
    if not quiet:
        await spinner.stop(f"HTTP Probing complete: {len(probed)} active web servers responding.")
    return probed


# =====================================================================
# MAIN ORCHESTRATOR
# =====================================================================

async def enumerate_single_domain(
    client: httpx.AsyncClient, domain: str, api_keys: dict[str, str], quiet: bool
) -> set[str]:
    spinner = Spinner(f"Querying OSINT sources for {domain}...")
    if not quiet:
        spinner.start()

    tasks = [
        fetch_crtsh(client, domain),
        fetch_hackertarget(client, domain),
        fetch_alienvault(client, domain),
        fetch_anubis(client, domain),
        fetch_wayback(client, domain),
        fetch_urlscan(client, domain, api_keys.get("urlscan", "")),
        fetch_virustotal(client, domain, api_keys.get("virustotal", "")),
        fetch_certspotter(client, domain, api_keys.get("certspotter", "")),
        fetch_chaos(client, domain, api_keys.get("chaos", "")),
    ]
    results = await asyncio.gather(*tasks)
    merged = set().union(*results)
    
    if not quiet:
        await spinner.stop(f"Discovered {len(merged)} unique passive subdomains for {domain}")
    return merged


async def run_engine(args: argparse.Namespace):
    config = init_or_load_config(Path(args.config).expanduser())
    api_keys = config["api_keys"]
    headers = config["headers"]

    # Apply CLI custom headers if provided
    if args.header:
        for raw_h in args.header:
            if ":" in raw_h:
                k, v = raw_h.split(":", 1)
                headers[k.strip()] = v.strip()

    targets: list[str] = []
    if args.domain:
        d = normalize_domain_input(args.domain)
        if d:
            targets.append(d)

    if args.input:
        input_path = Path(args.input).expanduser()
        if not input_path.is_file():
            print(f"{RED}[!] Error: Input file not found: {input_path}{RESET}", file=sys.stderr)
            sys.exit(1)
        for line in input_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            d = normalize_domain_input(line)
            if d and d not in targets:
                targets.append(d)

    if not targets:
        print(f"{RED}[!] Error: No valid target domains provided. Use -d or -i.{RESET}", file=sys.stderr)
        sys.exit(1)

    if not args.silent:
        active_keys = [k for k, v in api_keys.items() if v]
        print(f"{CYAN}[i] Loaded Targets:{RESET}      {len(targets)} domain(s)")
        print(f"{CYAN}[i] Safe-Harbor Header:{RESET}  {headers.get('X-Bug-Bounty', 'None (Disabled by default)')}")
        print(
            f"{CYAN}[i] Active API Keys:{RESET}     "
            f"{', '.join(active_keys) if active_keys else 'None (Using free keyless OSINT engines)'}"
        )

    all_discovered: set[str] = set()
    async with httpx.AsyncClient(headers=headers, follow_redirects=True) as client:
        for domain in targets:
            subs = await enumerate_single_domain(client, domain, api_keys, args.silent)
            all_discovered.update(subs)

    if not args.silent:
        print(f"\n{GREEN}{BOLD}[✓] Total Unique Passive Subdomains Discovered: {len(all_discovered)}{RESET}")

    resolved_map: dict[str, list[str]] = {}
    if args.resolve and all_discovered:
        nameservers = [ns.strip() for ns in args.resolvers.split(",") if ns.strip()]
        resolved_map = await resolve_subdomains(all_discovered, args.threads, nameservers, args.silent)
        final_subs = sorted(resolved_map.keys())
    else:
        final_subs = sorted(all_discovered)

    probed_map: dict[str, str] = {}
    if args.probe and final_subs:
        probed_map = await probe_http_hosts(final_subs, headers, args.threads, args.silent)

    if final_subs and not args.silent:
        print(f"\n{CYAN}{BOLD}--- SUBNORYX Final Results ({len(final_subs)}) ---{RESET}")
    for sub in final_subs:
        if args.silent:
            print(sub)
        else:
            ip_str = f" {YELLOW}[{', '.join(resolved_map[sub])}]{RESET}" if sub in resolved_map else ""
            probe_str = f" -> {GREEN}{probed_map[sub]}{RESET}" if sub in probed_map else ""
            print(f"  {sub}{ip_str}{probe_str}")

    if args.output:
        out_path = Path(args.output).expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("\n".join(final_subs) + ("\n" if final_subs else ""), encoding="utf-8")
        if not args.silent:
            print(f"\n{GREEN}[✓] Saved {len(final_subs)} subdomains to: {out_path}{RESET}")


def parse_args() -> argparse.Namespace:
    if len(sys.argv) > 1 and sys.argv[1] in ("--man", "man"):
        print_manual()
        sys.exit(0)

    if "-s" not in sys.argv and "--silent" not in sys.argv:
        print_banner()

    parser = argparse.ArgumentParser(
        prog="subnoryx",
        description="SUBNORYX — Fast Async Subdomain Enumerator with Multi-Domain, DNS Resolution & Safe-Harbor Support",
    )
    target_group = parser.add_argument_group("Target Selection")
    target_group.add_argument("-d", "--domain", help="Single target domain (e.g., prismlife.com)")
    target_group.add_argument("-i", "--input", help="File containing list of domains (e.g., scope.txt)")

    recon_group = parser.add_argument_group("Resolution & Probing")
    recon_group.add_argument(
        "-r", "--resolve", action="store_true", help="Filter out dead subdomains via async DNS resolution (aiodns)"
    )
    recon_group.add_argument(
        "--probe", action="store_true", help="Probe discovered subdomains for live HTTP/HTTPS status & page titles"
    )
    recon_group.add_argument(
        "-t", "--threads", type=int, default=100, help="Concurrency limit for DNS resolution / probing (default: 100)"
    )
    recon_group.add_argument(
        "--resolvers", default="1.1.1.1,8.8.8.8,9.9.9.9", help="Comma-separated DNS resolvers (default: 1.1.1.1,8.8.8.8,9.9.9.9)"
    )

    config_group = parser.add_argument_group("Configuration & Output")
    config_group.add_argument("-o", "--output", help="Output file path to save clean subdomain list")
    config_group.add_argument(
        "-c", "--config", default=str(DEFAULT_CONFIG_PATH), help=f"Path to config.yaml (default: {DEFAULT_CONFIG_PATH})"
    )
    config_group.add_argument(
        "-H", "--header", action="append", help="Custom HTTP header (e.g., -H 'X-Bug-Bounty: HackerOne-kalmux')"
    )
    config_group.add_argument(
        "-s", "--silent", action="store_true", help="Silent mode (print only raw subdomains to stdout for piping)"
    )
    config_group.add_argument("-v", "--verbose", action="store_true", help="Enable verbose realtime output")
    parser.add_argument("-V", "--version", action="version", version="SUBNORYX v1.0.0 (By Kalmux)")

    args = parser.parse_args()
    if not args.domain and not args.input:
        parser.print_help()
        sys.exit(1)
    return args


if __name__ == "__main__":
    try:
        asyncio.run(run_engine(parse_args()))
    except KeyboardInterrupt:
        print(f"\n{RED}[!] SUBNORYX scan interrupted by user. Exiting.{RESET}")
        sys.exit(130)