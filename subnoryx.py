#!/usr/bin/env python3
"""
SUBNORYX: Fast Async Passive Subdomain Enumerator & Recon Engine
Author: Kalmux
License: GPL-2.0

Requires Python >= 3.9 (tested on 3.9, 3.10, 3.11, 3.12).
"""
from __future__ import annotations

import argparse
import asyncio
import inspect
import itertools
import json
import random
import re
import socket
import sys
import warnings
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

__version__ = "1.0.0"
LICENSE = "GPL-2.0"

# ----------------------------------------------------------------------
# ANSI Colors & Styles
# ----------------------------------------------------------------------
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

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

API_KEY_NAMES = [
    "alienvault", "bevigil", "bufferover", "builtwith", "c99", "censys",
    "certspotter", "chaos", "chinaz", "digitalyama", "dnsdb", "dnsdumpster",
    "dnsrepo", "domainsproject", "driftnet", "fofa", "fullhunt", "github",
    "hackertarget", "intelx", "leakix", "merklemap", "netlas", "onyphe",
    "profundis", "pugrecon", "quake", "reconeer", "redhuntlabs", "robtex",
    "rsecloud", "securitytrails", "shodan", "submd", "threatbook", "urlscan",
    "virustotal", "whoisxmlapi", "windvane", "zoomeyeapi",
]

DEFAULT_CONFIG_TEMPLATE = (
    "# =====================================================================\n"
    f"# SUBNORYX Configuration File (v{__version__})\n"
    "# =====================================================================\n"
    '# Leave API keys empty ("") to use keyless OSINT engines (crt.sh, HackerTarget, etc.)\n'
    "\n"
    "api_keys:\n"
    + "\n".join(f'  {k}: ""' for k in API_KEY_NAMES) + "\n"
    "\n"
    "headers:\n"
    f'  User-Agent: "{DEFAULT_HEADERS["User-Agent"]}"\n'
)

# Verbose mode is toggled at runtime from run_engine()
_VERBOSE = False


def vlog(msg: str) -> None:
    """Verbose log helper (writes to stderr so stdout piping stays clean)."""
    if _VERBOSE:
        print(f"{DIM}[v]{RESET} {msg}", file=sys.stderr)


# ----------------------------------------------------------------------
# Banner & Manual
# ----------------------------------------------------------------------
def print_banner() -> None:
    banner = (
        f"{CYAN}{BOLD}\n"
        r"   _____ __  ______  _   ______  ______  ___  __" "\n"
        r"  / ___// / / / __ )/ | / / __ \/ __ \ \/ / |/ /" "\n"
        r"  \__ \/ / / / __  /  |/ / / / / /_/ /\  /|   /"  "\n"
        r" ___/ / /_/ / /_/ / /|  / /_/ / _, _/ / //   |"   "\n"
        r"/____/\____/_____/_/ |_/\____/_/ |_| /_//_/|_|"   "\n"
        f"{RESET}{CYAN}SUBNORYX v{__version__} — Async Subdomain Recon Engine{RESET}\n"
        f"{MAGENTA}                 ~By Kalmux{RESET}\n"
    )
    print(banner)


def print_manual() -> None:
    print_banner()
    manual_text = f"""{BOLD}{CYAN}SUBNORYX MANIFEST & USER MANUAL{RESET}
{DIM}───────────────────────────────────────────────────────────────────────────────{RESET}

{BOLD}NAME{RESET}
    subnoryx - High-performance asynchronous passive subdomain enumeration engine

{BOLD}SYNOPSIS{RESET}
    {GREEN}subnoryx{RESET} [{BOLD}-d{RESET} DOMAIN] [{BOLD}-i{RESET} FILE] [{BOLD}-r{RESET}] [{BOLD}--probe{RESET}] [{BOLD}-t{RESET} THREADS] [{BOLD}-o{RESET} FILE] [{BOLD}--json{RESET} FILE] [{BOLD}-s{RESET}]

{BOLD}DESCRIPTION{RESET}
    SUBNORYX is an asynchronous OSINT recon framework designed for bug bounty hunters
    and penetration testers. Unlike traditional scrapers that rely on fragile HTML
    parsing or blocking multiprocessing models, SUBNORYX queries high-speed public
    APIs, Certificate Transparency logs, and passive DNS repositories concurrently.

{BOLD}OPTIONS{RESET}
    {BOLD}-d, --domain{RESET} DOMAIN
        Specify a single target apex domain (e.g., {YELLOW}example.com{RESET}).

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
        Requires {CYAN}aiodns{RESET} to take effect.

    {BOLD}-o, --output{RESET} FILE
        Save cleaned, unique subdomain list to the specified file path.

    {BOLD}--json{RESET} FILE
        Save full results (subdomains + resolved IPs + HTTP probe details) as JSON.

    {BOLD}-H, --header{RESET} KEY:VALUE
        Inject a custom HTTP header for {BOLD}probing requests only{RESET}
        (e.g., {YELLOW}-H "X-Bug-Bounty: HackerOne-kalmux"{RESET}).
        No headers are injected by default. To inject headers into passive API
        calls as well, edit the {CYAN}headers:{RESET} section of your config file.

    {BOLD}-c, --config{RESET} PATH
        Path to YAML configuration file (default: {YELLOW}~/.config/subnoryx/config.yaml{RESET}).

    {BOLD}--show-config{RESET}
        Print the resolved configuration (headers + masked API key status) and exit.

    {BOLD}-s, --silent{RESET}
        Silent mode. Suppresses banners and logs, outputting only raw subdomains
        for seamless terminal piping ({GREEN}subnoryx -d target.com -s | httpx{RESET}).

    {BOLD}--man{RESET}
        Display this comprehensive manual page and exit.

    {BOLD}-v, --verbose{RESET}
        Enable verbose output on stderr (per-source timing, retries, failures).

    {BOLD}-V, --version{RESET}
        Display version information and exit.

{BOLD}CONFIGURATION & API KEYS{RESET}
    SUBNORYX supports over 40 API keys out of the box. Configure your keys in:
    {CYAN}~/.config/subnoryx/config.yaml{RESET}

{BOLD}AUTHOR{RESET}
    Created by Kalmux. Licensed under {LICENSE}.
{DIM}───────────────────────────────────────────────────────────────────────────────{RESET}
"""
    print(manual_text)


# ----------------------------------------------------------------------
# Spinner
# ----------------------------------------------------------------------
class Spinner:
    """Sleek terminal spinner — automatically disabled when stdout isn't a TTY."""

    def __init__(self, message: str = "Working..."):
        self.message = message
        self.spinner = itertools.cycle(
            ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        )
        self.running = False
        self.task: asyncio.Task | None = None
        self.enabled = sys.stdout.isatty()

    async def _animate(self) -> None:
        while self.running:
            sys.stdout.write(f"\r{CYAN}{next(self.spinner)}{RESET} {self.message}")
            sys.stdout.flush()
            await asyncio.sleep(0.08)

    def start(self) -> None:
        if not self.enabled:
            sys.stdout.write(f"{CYAN}[…]{RESET} {self.message}\n")
            sys.stdout.flush()
            return
        self.running = True
        self.task = asyncio.create_task(self._animate())

    async def stop(self, success_msg: str = "") -> None:
        if self.enabled:
            self.running = False
            if self.task:
                try:
                    await self.task
                except Exception:
                    pass
            sys.stdout.write("\r\033[K")
        if success_msg:
            print(f"{GREEN}[✓]{RESET} {success_msg}")


# ----------------------------------------------------------------------
# Config loading
# ----------------------------------------------------------------------
def _parse_config_fallback(raw_text: str, config: dict) -> None:
    """Minimal YAML-ish parser for when PyYAML is not installed."""
    current_section: str | None = None
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Top-level section header, e.g. "api_keys:" / "headers:"
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\s*:", stripped):
            current_section = stripped[:-1].strip()
            continue
        if current_section is None or ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if current_section == "api_keys" and key in config["api_keys"]:
            config["api_keys"][key] = value
        elif current_section == "headers" and value:
            config["headers"][key] = value


def init_or_load_config(config_path: Path) -> dict:
    config = {
        "api_keys": {k: "" for k in API_KEY_NAMES},
        "headers": dict(DEFAULT_HEADERS),
    }

    if not config_path.exists():
        try:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text(DEFAULT_CONFIG_TEMPLATE, encoding="utf-8")
        except Exception as e:
            vlog(f"Could not create default config: {e}")
        return config

    try:
        raw_text = config_path.read_text(encoding="utf-8")
    except Exception as e:
        print(
            f"{YELLOW}[!] Warning: Could not read {config_path}: {e}{RESET}",
            file=sys.stderr,
        )
        return config

    if HAS_YAML:
        try:
            loaded = yaml.safe_load(raw_text) or {}
            if isinstance(loaded, dict):
                api = loaded.get("api_keys") or {}
                if isinstance(api, dict):
                    for k, v in api.items():
                        if k in config["api_keys"]:
                            config["api_keys"][k] = str(v or "")
                hdrs = loaded.get("headers") or {}
                if isinstance(hdrs, dict):
                    for k, v in hdrs.items():
                        if v:
                            config["headers"][str(k)] = str(v)
        except Exception as e:
            print(
                f"{YELLOW}[!] Warning: Could not parse YAML in {config_path}: {e}{RESET}",
                file=sys.stderr,
            )
    else:
        _parse_config_fallback(raw_text, config)

    return config


def mask_key(value: str) -> str:
    """Mask an API key for safe display: show first/last 4 chars."""
    if not value:
        return "(empty)"
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}…{value[-4:]}"


def print_config_summary(config: dict, config_path: Path) -> None:
    """Print a safe, masked summary of the loaded configuration."""
    print(f"\n{CYAN}{BOLD}SUBNORYX Configuration Summary{RESET}")
    print(f"{DIM}{'─' * 55}{RESET}")
    print(f"{BOLD}Config file :{RESET} {config_path}")
    print(
        f"{BOLD}Status      :{RESET} "
        f"{'exists' if config_path.exists() else 'missing — using defaults'}"
    )
    print()

    print(f"{BOLD}Headers{RESET} ({len(config['headers'])}):")
    for k, v in config["headers"].items():
        print(f"  {k}: {v}")
    print()

    print(f"{BOLD}API Keys{RESET}:")
    active = 0
    for k, v in config["api_keys"].items():
        if v:
            active += 1
            print(f"  {GREEN}✓{RESET} {k:<16} {mask_key(v)}")
    if active == 0:
        print(
            f"  {DIM}(none configured — using keyless OSINT engines: "
            f"crt.sh, HackerTarget, AlienVault, Wayback, Anubis){RESET}"
        )
    else:
        print(
            f"\n  {GREEN}{active}{RESET} active / "
            f"{len(config['api_keys'])} supported"
        )
    print()


# ----------------------------------------------------------------------
# Input normalisation
# ----------------------------------------------------------------------
_STAR_PREFIX = re.compile(r"^\*\.")
_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?$")


def normalize_domain_input(raw: str) -> str:
    item = raw.strip().lower()
    if not item or item.startswith("#"):
        return ""
    if "://" in item:
        parsed = urlparse(item)
        item = parsed.hostname or ""
    else:
        item = item.split("/")[0].split(":")[0]
    item = _STAR_PREFIX.sub("", item)
    return item.rstrip(".")


def clean_subdomain(sub: str, domain: str) -> str | None:
    """Validate and normalise a discovered subdomain. Returns None if invalid."""
    if not sub:
        return None
    sub = _STAR_PREFIX.sub("", sub.strip().lower()).rstrip(".")
    if sub != domain and not sub.endswith(f".{domain}"):
        return None
    if len(sub) > 253:
        return None
    labels = sub.split(".")
    if not all(_LABEL_RE.match(lbl) for lbl in labels if lbl):
        return None
    return sub


# ----------------------------------------------------------------------
# HTTP retry helper
# ----------------------------------------------------------------------
async def http_get_with_retry(
    client: httpx.AsyncClient,
    url: str,
    *,
    headers: dict | None = None,
    retries: int = 2,
    **kwargs,
) -> httpx.Response:
    """GET with retries on transient failures (429, 5xx, network errors)."""
    last_exc: Exception | None = None
    resp: httpx.Response | None = None
    for attempt in range(retries + 1):
        try:
            resp = await client.get(url, headers=headers, **kwargs)
            if resp.status_code in (429, 500, 502, 503, 504) and attempt < retries:
                backoff = (1.0 + attempt) + random.uniform(0, 0.5)
                vlog(f"Retry {url} in {backoff:.1f}s (HTTP {resp.status_code})")
                await asyncio.sleep(backoff)
                continue
            return resp
        except (httpx.RequestError, httpx.TimeoutException) as e:
            last_exc = e
            if attempt < retries:
                backoff = (1.0 + attempt) + random.uniform(0, 0.5)
                vlog(f"Retry {url} in {backoff:.1f}s ({type(e).__name__})")
                await asyncio.sleep(backoff)
                continue
            raise
    if last_exc:
        raise last_exc
    if resp is not None:
        return resp
    raise RuntimeError(f"http_get_with_retry exhausted for {url}")


# ======================================================================
# PASSIVE OSINT SOURCES
# ======================================================================
async def fetch_crtsh(client: httpx.AsyncClient, domain: str) -> set[str]:
    subs: set[str] = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = await http_get_with_retry(client, url, timeout=30.0)
        if resp.status_code == 200:
            for entry in resp.json():
                for name in str(entry.get("name_value", "")).splitlines():
                    cleaned = clean_subdomain(name, domain)
                    if cleaned:
                        subs.add(cleaned)
    except Exception as e:
        vlog(f"crt.sh failed for {domain}: {e}")
    return subs


async def fetch_hackertarget(client: httpx.AsyncClient, domain: str) -> set[str]:
    subs: set[str] = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        resp = await http_get_with_retry(client, url, timeout=20.0)
        if resp.status_code == 200 and "API count exceeded" not in resp.text:
            for line in resp.text.splitlines():
                host = line.split(",")[0]
                cleaned = clean_subdomain(host, domain)
                if cleaned:
                    subs.add(cleaned)
    except Exception as e:
        vlog(f"HackerTarget failed for {domain}: {e}")
    return subs


async def fetch_alienvault(client: httpx.AsyncClient, domain: str) -> set[str]:
    subs: set[str] = set()
    url = (
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    )
    try:
        resp = await http_get_with_retry(client, url, timeout=25.0)
        if resp.status_code == 200:
            for record in resp.json().get("passive_dns", []):
                cleaned = clean_subdomain(record.get("hostname", ""), domain)
                if cleaned:
                    subs.add(cleaned)
    except Exception as e:
        vlog(f"AlienVault failed for {domain}: {e}")
    return subs


async def fetch_anubis(client: httpx.AsyncClient, domain: str) -> set[str]:
    """Best-effort — jldc.me/anubis is intermittently unavailable."""
    subs: set[str] = set()
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    try:
        resp = await http_get_with_retry(client, url, timeout=15.0, retries=1)
        if resp.status_code == 200:
            for item in resp.json():
                cleaned = clean_subdomain(item, domain)
                if cleaned:
                    subs.add(cleaned)
    except Exception as e:
        vlog(f"Anubis failed for {domain} (best-effort): {e}")
    return subs


async def fetch_wayback(client: httpx.AsyncClient, domain: str) -> set[str]:
    subs: set[str] = set()
    url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    )
    try:
        resp = await http_get_with_retry(client, url, timeout=30.0)
        if resp.status_code == 200:
            data = resp.json()
            for row in data[1:]:
                if row:
                    parsed = urlparse(row[0])
                    cleaned = clean_subdomain(parsed.hostname or "", domain)
                    if cleaned:
                        subs.add(cleaned)
    except Exception as e:
        vlog(f"Wayback failed for {domain}: {e}")
    return subs


async def fetch_urlscan(
    client: httpx.AsyncClient, domain: str, api_key: str
) -> set[str]:
    subs: set[str] = set()
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000"
    headers = {"API-Key": api_key} if api_key else {}
    try:
        resp = await http_get_with_retry(client, url, headers=headers, timeout=25.0)
        if resp.status_code == 200:
            for item in resp.json().get("results", []):
                for candidate in (
                    item.get("page", {}).get("domain", ""),
                    item.get("task", {}).get("domain", ""),
                ):
                    cleaned = clean_subdomain(candidate, domain)
                    if cleaned:
                        subs.add(cleaned)
    except Exception as e:
        vlog(f"urlscan failed for {domain}: {e}")
    return subs


async def fetch_virustotal(
    client: httpx.AsyncClient, domain: str, api_key: str
) -> set[str]:
    subs: set[str] = set()
    if not api_key:
        return subs
    url = (
        f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    )
    try:
        resp = await http_get_with_retry(
            client, url, headers={"x-apikey": api_key}, timeout=20.0
        )
        if resp.status_code == 200:
            for item in resp.json().get("data", []):
                cleaned = clean_subdomain(item.get("id", ""), domain)
                if cleaned:
                    subs.add(cleaned)
    except Exception as e:
        vlog(f"VirusTotal failed for {domain}: {e}")
    return subs


async def fetch_certspotter(
    client: httpx.AsyncClient, domain: str, api_key: str
) -> set[str]:
    subs: set[str] = set()
    if not api_key:
        return subs
    url = (
        f"https://api.certspotter.com/v1/issuances"
        f"?domain={domain}&include_subdomains=true&expand=dns_names"
    )
    try:
        resp = await http_get_with_retry(
            client,
            url,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=20.0,
        )
        if resp.status_code == 200:
            for entry in resp.json():
                for name in entry.get("dns_names", []):
                    cleaned = clean_subdomain(name, domain)
                    if cleaned:
                        subs.add(cleaned)
    except Exception as e:
        vlog(f"CertSpotter failed for {domain}: {e}")
    return subs


async def fetch_chaos(
    client: httpx.AsyncClient, domain: str, api_key: str
) -> set[str]:
    subs: set[str] = set()
    if not api_key:
        return subs
    url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
    try:
        resp = await http_get_with_retry(
            client, url, headers={"Authorization": api_key}, timeout=20.0
        )
        if resp.status_code == 200:
            for sub in resp.json().get("subdomains", []):
                cleaned = clean_subdomain(f"{sub}.{domain}", domain)
                if cleaned:
                    subs.add(cleaned)
    except Exception as e:
        vlog(f"Chaos failed for {domain}: {e}")
    return subs


# ======================================================================
# DNS RESOLUTION
# ======================================================================
def build_resolver(
    nameservers: list[str],
) -> tuple["aiodns.DNSResolver | None", dict]:
    """Return (resolver, query_kwargs) tolerant of aiodns 2.x and 3.x APIs."""
    if not HAS_AIODNS:
        return None, {}

    # aiodns < 3.0: timeout / tries accepted by constructor
    try:
        resolver = aiodns.DNSResolver(
            nameservers=nameservers, timeout=3.0, tries=2
        )
        return resolver, {}
    except TypeError:
        pass

    # aiodns >= 3.0: constructor takes only nameservers
    try:
        resolver = aiodns.DNSResolver(nameservers=nameservers)
    except Exception as e:
        vlog(f"Failed to build aiodns resolver: {e}")
        return None, {}

    # Probe whether query() accepts a timeout kwarg (varies across 3.x)
    query_kwargs: dict = {}
    try:
        if "timeout" in inspect.signature(resolver.query).parameters:
            query_kwargs["timeout"] = 3.0
    except Exception:
        pass
    return resolver, query_kwargs


async def resolve_single_host(
    sub: str,
    sem: asyncio.Semaphore,
    resolver,
    query_kwargs: dict,
    loop: asyncio.AbstractEventLoop,
) -> tuple[str, list[str]]:
    async with sem:
        if resolver is not None:
            try:
                res = await resolver.query(sub, "A", **query_kwargs)
                ips = sorted({r.host for r in res})
                return (sub, ips)
            except Exception:
                return (sub, [])
        try:
            infos = await loop.getaddrinfo(sub, None, family=socket.AF_INET)
            ips = sorted({info[4][0] for info in infos if info[4]})
            return (sub, ips)
        except Exception:
            return (sub, [])


async def batch_gather(factory, items, batch_size: int = 2000) -> list:
    """Run `factory(item)` for each item in bounded batches to cap memory usage."""
    items = list(items)
    results: list = []
    for i in range(0, len(items), batch_size):
        batch = items[i:i + batch_size]
        batch_results = await asyncio.gather(*(factory(it) for it in batch))
        results.extend(batch_results)
    return results


async def resolve_subdomains(
    subdomains: set[str],
    concurrency: int,
    nameservers: list[str],
    quiet: bool,
) -> dict[str, list[str]]:
    if not subdomains:
        return {}

    spinner = Spinner(
        f"Resolving {len(subdomains)} subdomains via async DNS..."
    )
    if not quiet:
        spinner.start()

    sem = asyncio.Semaphore(concurrency)
    loop = asyncio.get_running_loop()
    resolver, query_kwargs = build_resolver(nameservers)
    if resolver is None and HAS_AIODNS:
        vlog("aiodns resolver init failed; falling back to socket.getaddrinfo")
    if resolver is None and not HAS_AIODNS:
        vlog("aiodns not installed; using socket.getaddrinfo (slower)")

    results = await batch_gather(
        lambda sub: resolve_single_host(sub, sem, resolver, query_kwargs, loop),
        sorted(subdomains),
        batch_size=2000,
    )

    live_map = {sub: ips for sub, ips in results if ips}
    if not quiet:
        await spinner.stop(
            f"DNS Resolution complete: "
            f"{len(live_map)}/{len(subdomains)} live hosts verified."
        )
    return live_map


# ======================================================================
# HTTP PROBING
# ======================================================================
async def probe_single_host(
    client: httpx.AsyncClient, sub: str, sem: asyncio.Semaphore
) -> tuple[str, dict | None]:
    async with sem:
        for scheme in ("https", "http"):
            url = f"{scheme}://{sub}"
            try:
                resp = await client.get(url, timeout=8.0)
                title_match = re.search(
                    r"<title[^>]*>(.*?)</title>", resp.text,
                    re.IGNORECASE | re.DOTALL,
                )
                title = (
                    title_match.group(1).strip().replace("\n", " ")[:60]
                    if title_match else ""
                )
                return (sub, {
                    "url": url,
                    "status": resp.status_code,
                    "title": title,
                })
            except Exception:
                continue
        return (sub, None)


async def probe_http_hosts(
    subdomains: list[str],
    headers: dict[str, str],
    concurrency: int,
    quiet: bool,
) -> dict[str, dict]:
    if not subdomains:
        return {}

    spinner = Spinner(
        f"Probing {len(subdomains)} hosts for active HTTP/HTTPS services..."
    )
    if not quiet:
        spinner.start()

    sem = asyncio.Semaphore(concurrency)
    limits = httpx.Limits(max_connections=200, max_keepalive_connections=50)

    # `verify=False` is intentional for recon; suppress any warnings it emits.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        async with httpx.AsyncClient(
            headers=headers,
            follow_redirects=True,
            verify=False,
            limits=limits,
        ) as client:
            results = await batch_gather(
                lambda sub: probe_single_host(client, sub, sem),
                subdomains,
                batch_size=2000,
            )

    probed = {sub: info for sub, info in results if info}
    if not quiet:
        await spinner.stop(
            f"HTTP Probing complete: "
            f"{len(probed)} active web servers responding."
        )
    return probed


# ======================================================================
# MAIN ORCHESTRATOR
# ======================================================================
async def enumerate_single_domain(
    client: httpx.AsyncClient,
    domain: str,
    api_keys: dict[str, str],
    quiet: bool,
) -> set[str]:
    spinner = Spinner(f"Querying OSINT sources for {domain}...")
    if not quiet:
        spinner.start()

    vlog(f"Launching OSINT queries for {domain}")
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
    merged: set[str] = set().union(*results)

    if not quiet:
        await spinner.stop(
            f"Discovered {len(merged)} unique passive subdomains for {domain}"
        )
    return merged


async def run_engine(args: argparse.Namespace) -> None:
    global _VERBOSE
    _VERBOSE = bool(args.verbose)

    config_path = Path(args.config).expanduser()
    config = init_or_load_config(config_path)

    # -------- --show-config short-circuit --------
    if args.show_config:
        print_config_summary(config, config_path)
        return
    # ---------------------------------------------

    api_keys = config["api_keys"]
    # Baseline headers (config) → used by both passive client and probe client
    config_headers = dict(config["headers"])

    # Probe-only headers: config + any CLI -H values
    probe_headers = dict(config_headers)
    if args.header:
        for raw_h in args.header:
            if ":" in raw_h:
                k, v = raw_h.split(":", 1)
                probe_headers[k.strip()] = v.strip()

    # ------------------------------------------------------------------
    # Resolve target list
    # ------------------------------------------------------------------
    targets: list[str] = []
    if args.domain:
        d = normalize_domain_input(args.domain)
        if d:
            targets.append(d)

    if args.input:
        input_path = Path(args.input).expanduser()
        if not input_path.is_file():
            print(
                f"{RED}[!] Error: Input file not found: {input_path}{RESET}",
                file=sys.stderr,
            )
            sys.exit(1)
        for line in input_path.read_text(
            encoding="utf-8", errors="ignore"
        ).splitlines():
            d = normalize_domain_input(line)
            if d and d not in targets:
                targets.append(d)

    if not targets:
        print(
            f"{RED}[!] Error: No valid target domains provided. "
            f"Use -d or -i.{RESET}",
            file=sys.stderr,
        )
        sys.exit(1)

    if not args.silent:
        active_keys = [k for k, v in api_keys.items() if v]
        print(f"{CYAN}[i] Loaded Targets:{RESET}      {len(targets)} domain(s)")
        print(
            f"{CYAN}[i] Probe Headers:{RESET}       "
            f"{', '.join(probe_headers.keys())}"
        )
        print(
            f"{CYAN}[i] Active API Keys:{RESET}     "
            f"{', '.join(active_keys) if active_keys else 'None (using free keyless OSINT engines)'}"
        )

    # ------------------------------------------------------------------
    # Passive discovery
    # ------------------------------------------------------------------
    all_discovered: set[str] = set()
    limits = httpx.Limits(max_connections=50, max_keepalive_connections=20)
    async with httpx.AsyncClient(
        headers=config_headers, follow_redirects=True, limits=limits
    ) as client:
        for domain in targets:
            subs = await enumerate_single_domain(
                client, domain, api_keys, args.silent
            )
            all_discovered.update(subs)

    if not args.silent:
        print(
            f"\n{GREEN}{BOLD}[✓] Total Unique Passive Subdomains Discovered: "
            f"{len(all_discovered)}{RESET}"
        )

    # ------------------------------------------------------------------
    # DNS resolution
    # ------------------------------------------------------------------
    resolved_map: dict[str, list[str]] = {}
    if args.resolve and all_discovered:
        nameservers = [
            ns.strip() for ns in args.resolvers.split(",") if ns.strip()
        ]
        if not HAS_AIODNS and args.resolvers != "1.1.1.1,8.8.8.8,9.9.9.9":
            print(
                f"{YELLOW}[!] Warning: --resolvers requires aiodns; "
                f"custom resolver list will be ignored.{RESET}",
                file=sys.stderr,
            )
        resolved_map = await resolve_subdomains(
            all_discovered, args.threads, nameservers, args.silent
        )
        final_subs = sorted(resolved_map.keys())
    else:
        final_subs = sorted(all_discovered)

    # ------------------------------------------------------------------
    # HTTP probing
    # ------------------------------------------------------------------
    probed_map: dict[str, dict] = {}
    if args.probe and final_subs:
        probed_map = await probe_http_hosts(
            final_subs, probe_headers, args.threads, args.silent
        )

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------
    if final_subs and not args.silent:
        print(
            f"\n{CYAN}{BOLD}--- SUBNORYX Final Results "
            f"({len(final_subs)}) ---{RESET}"
        )
    for sub in final_subs:
        if args.silent:
            print(sub)
            continue
        ip_str = (
            f" {YELLOW}[{', '.join(resolved_map[sub])}]{RESET}"
            if sub in resolved_map else ""
        )
        probe_str = ""
        if sub in probed_map:
            info = probed_map[sub]
            probe_str = f" -> {GREEN}{info['url']} [{info['status']}]"
            if info.get("title"):
                probe_str += f" [{info['title']}]"
            probe_str += RESET
        print(f"  {sub}{ip_str}{probe_str}")

    if args.output:
        out_path = Path(args.output).expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            "\n".join(final_subs) + ("\n" if final_subs else ""),
            encoding="utf-8",
        )
        if not args.silent:
            print(
                f"\n{GREEN}[✓] Saved {len(final_subs)} subdomains to: "
                f"{out_path}{RESET}"
            )

    if args.json:
        json_path = Path(args.json).expanduser()
        json_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": __version__,
            "license": LICENSE,
            "targets": targets,
            "discovered_count": len(all_discovered),
            "resolved_count": len(resolved_map),
            "probed_count": len(probed_map),
            "subdomains": final_subs,
            "resolved": resolved_map,
            "probed": probed_map,
        }
        json_path.write_text(
            json.dumps(payload, indent=2), encoding="utf-8"
        )
        if not args.silent:
            print(
                f"{GREEN}[✓] Saved full JSON results to: {json_path}{RESET}"
            )


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    # --man / `man` subcommand anywhere on the command line
    if "--man" in sys.argv[1:] or (
        len(sys.argv) > 1 and sys.argv[1] == "man"
    ):
        print_manual()
        sys.exit(0)

    # Suppress the banner only for silent mode (keep it for -h / --help)
    suppress_banner = any(flag in sys.argv[1:] for flag in ("-s", "--silent"))
    if not suppress_banner:
        print_banner()

    parser = argparse.ArgumentParser(
        prog="subnoryx",
        description=(
            "SUBNORYX — Fast Async Subdomain Enumerator with "
            "Multi-Domain, DNS Resolution & Safe-Harbor Support"
        ),
    )
    target_group = parser.add_argument_group("Target Selection")
    target_group.add_argument(
        "-d", "--domain", help="Single target domain (e.g., example.com)"
    )
    target_group.add_argument(
        "-i", "--input", help="File containing list of domains (e.g., scope.txt)"
    )

    recon_group = parser.add_argument_group("Resolution & Probing")
    recon_group.add_argument(
        "-r", "--resolve", action="store_true",
        help="Filter out dead subdomains via async DNS resolution (aiodns)",
    )
    recon_group.add_argument(
        "--probe", action="store_true",
        help="Probe discovered subdomains for live HTTP/HTTPS status & titles",
    )
    recon_group.add_argument(
        "-t", "--threads", type=int, default=100,
        help="Concurrency limit for DNS resolution / probing (default: 100)",
    )
    recon_group.add_argument(
        "--resolvers",
        default="1.1.1.1,8.8.8.8,9.9.9.9",
        help="Comma-separated DNS resolvers (requires aiodns)",
    )

    config_group = parser.add_argument_group("Configuration & Output")
    config_group.add_argument(
        "-o", "--output", help="Output file path to save clean subdomain list"
    )
    config_group.add_argument(
        "--json", metavar="FILE",
        help="Save full results (subdomains + IPs + HTTP probe info) as JSON",
    )
    config_group.add_argument(
        "-c", "--config", default=str(DEFAULT_CONFIG_PATH),
        help=f"Path to config.yaml (default: {DEFAULT_CONFIG_PATH})",
    )
    config_group.add_argument(
        "--show-config", action="store_true",
        help="Print resolved configuration (headers + API key status) and exit",
    )
    config_group.add_argument(
        "-H", "--header", action="append", metavar="KEY:VALUE",
        help=(
            "Custom HTTP header for PROBING requests only "
            "(e.g. -H 'X-Bug-Bounty: HackerOne-user'). "
            "API-call headers must be set in the config file."
        ),
    )
    config_group.add_argument(
        "-s", "--silent", action="store_true",
        help="Silent mode (print only raw subdomains to stdout for piping)",
    )
    config_group.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose output on stderr",
    )
    parser.add_argument(
        "-V", "--version", action="version",
        version=f"SUBNORYX v{__version__} (By Kalmux, {LICENSE})",
    )

    args = parser.parse_args()
    if not args.domain and not args.input and not args.show_config:
        parser.print_help()
        sys.exit(1)
    return args


if __name__ == "__main__":
    try:
        asyncio.run(run_engine(parse_args()))
    except KeyboardInterrupt:
        print(
            f"\n{RED}[!] SUBNORYX scan interrupted by user. Exiting.{RESET}"
        )
        sys.exit(130)