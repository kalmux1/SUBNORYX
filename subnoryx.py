#!/usr/bin/env python3
"""
SUBNORYX: Fast Async Passive Subdomain Enumerator & Recon Engine
Author: Kalmux
License: GPL-3.0

Requires Python >= 3.9 (tested on 3.9, 3.10, 3.11, 3.12).

ETHICAL USE NOTICE
------------------
This tool is intended for AUTHORIZED security testing, bug bounty programs,
and education. Only use it against systems you own or have explicit
permission to test.
"""
from __future__ import annotations

import argparse
import asyncio
import inspect
import itertools
import json
import os
import random
import re
import socket
import sys
import warnings
from pathlib import Path
from urllib.parse import urlparse

try:
    import httpx
except ImportError:
    print(
        "Error: 'httpx' is required but not installed.\n"
        "Install it with:  pip install --user httpx",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    import aiodns
    HAS_AIODNS = True
except ImportError:
    HAS_AIODNS = False

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

__version__ = "1.2.0"
LICENSE = "GPL-3.0"

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

if os.environ.get("NO_COLOR"):
    CYAN = GREEN = YELLOW = RED = MAGENTA = BLUE = BOLD = DIM = RESET = ""

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

KEYLESS_SOURCES = {
    "alienvault", "anubis", "crtsh", "hackertarget", "wayback",
}

ALL_SOURCES = KEYLESS_SOURCES | set(API_KEY_NAMES)

_DEFAULT_CONFIG_HEADER = (
    "# =====================================================================\n"
    f"# SUBNORYX Configuration File (v{__version__})\n"
    "# =====================================================================\n"
    '# Leave API keys empty ("") to disable a keyed source.\n'
    "#\n"
    "# Sources with an empty key are SKIPPED at runtime.\n"
    "# Sources with a key configured are QUERIED during enumeration.\n"
    "# =====================================================================\n"
)

DEFAULT_CONFIG_TEMPLATE = (
    _DEFAULT_CONFIG_HEADER
    + "\napi_keys:\n"
    + "\n".join(f'  {k}: ""' for k in API_KEY_NAMES)
    + "\n\nheaders:\n"
    + f'  User-Agent: "{DEFAULT_HEADERS["User-Agent"]}"\n'
)

_VERBOSE = False


def vlog(msg: str) -> None:
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
    subnoryx - Asynchronous passive subdomain enumeration & recon engine

{BOLD}SYNOPSIS{RESET}
    {GREEN}subnoryx{RESET} [{BOLD}-d{RESET} DOMAIN | {BOLD}-i{RESET} FILE] [{BOLD}-r{RESET}] [{BOLD}--probe{RESET}] [{BOLD}--probe-only{RESET}]
             [{BOLD}--match-codes{RESET} CODES] [{BOLD}--show-list{RESET}] [{BOLD}-t{RESET} THREADS]
             [{BOLD}--resolvers{RESET} LIST] [{BOLD}-o{RESET} FILE] [{BOLD}--json{RESET} FILE] [{BOLD}-H{RESET} KEY:VALUE]
             [{BOLD}-c{RESET} PATH] [{BOLD}--show-config{RESET}] [{BOLD}-s{RESET}] [{BOLD}-v{RESET}] [{BOLD}-V{RESET}] [{BOLD}--man{RESET}]

{BOLD}TWO-STAGE WORKFLOW{RESET}
    Stage 1 — Discovery:
        {GREEN}subnoryx -d example.com -r -o subnoryx.txt{RESET}
        Saves discovered subdomains to a file. List is NOT printed.

    Stage 2 — Probing:
        {GREEN}subnoryx -i subnoryx.txt --probe --match-codes 200,301,403 -o live.txt{RESET}
        Probes the previously discovered subdomains. No re-discovery.
        Filters to status codes 200, 301, 403 only.

    {BOLD}--probe-only{RESET} forces subdomain-input mode. Without it, SUBNORYX
    auto-detects: if all lines in the input file share a common apex
    suffix (e.g. every line ends with .example.com), the file is
    treated as a list of subdomains.

{BOLD}OUTPUT BEHAVIOR{RESET}
    By default, the full subdomain list is {BOLD}not{RESET} printed to terminal.
    Use one of these to inspect results:
      • {BOLD}-o FILE{RESET}         save plain list to file
      • {BOLD}--json FILE{RESET}     save structured JSON
      • {BOLD}-s{RESET}              silent mode (raw stdout for piping)
      • {BOLD}--show-list{RESET}     print formatted list to terminal

{BOLD}OPTIONS{RESET}
    {BOLD}-d, --domain{RESET} DOMAIN
        Single target. Apex domain by default; subdomain when used with --probe-only.

    {BOLD}-i, --input{RESET} FILE
        Input file: apex domains (enumerate) or subdomains (probe, with --probe).

    {BOLD}-r, --resolve{RESET}
        Filter dead subdomains via async DNS resolution (aiodns).

    {BOLD}--probe{RESET}
        Probe hosts for HTTP/HTTPS status codes and titles.
        Implies -r in apex mode; does NOT imply -r in probe-only mode.

    {BOLD}--probe-only{RESET}
        Skip discovery. Treat -d/-i inputs as subdomains to probe directly.
        Implies --probe. Use this when feeding a file of known subdomains.

    {BOLD}--match-codes{RESET} CODES
        Comma-separated HTTP status codes to keep (e.g. 200,301,403).
        Only meaningful with --probe. Filters -o and --json output.
        Without this flag, all responsive codes are kept.

    {BOLD}--show-list{RESET}
        Print the full subdomain list to terminal (default: suppressed).

    {BOLD}-t, --threads{RESET} THREADS
        Concurrency limit (default: 100, min: 1).

    {BOLD}--resolvers{RESET} LIST
        Comma-separated DNS resolvers (default: 1.1.1.1,8.8.8.8,9.9.9.9).
        Requires aiodns.

    {BOLD}-o, --output{RESET} FILE
        Save filtered subdomain list (plain text).

    {BOLD}--json{RESET} FILE
        Save full structured results (subdomains + IPs + probe details).

    {BOLD}-H, --header{RESET} KEY:VALUE
        Custom HTTP header for probing only. Repeatable.

    {BOLD}-c, --config{RESET} PATH
        Config file path (default: ~/.config/subnoryx/config.yaml).

    {BOLD}--show-config{RESET}
        Print masked config and exit.

    {BOLD}-s, --silent{RESET}
        Silent mode — raw subdomains on stdout, no banner/spinner.

    {BOLD}-v, --verbose{RESET}
        Verbose per-source logs on stderr.

    {BOLD}-V, --version{RESET}
        Print version and exit.

    {BOLD}--man{RESET}
        This manual.

{BOLD}ENVIRONMENT{RESET}
    {BOLD}NO_COLOR{RESET}   Disables ANSI colors.

{BOLD}AUTHOR{RESET}
    Created by Kalmux. Licensed under {LICENSE}.
{DIM}───────────────────────────────────────────────────────────────────────────────{RESET}
"""
    print(manual_text)


# ----------------------------------------------------------------------
# Spinner
# ----------------------------------------------------------------------
class Spinner:
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
    current_section: str | None = None
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
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


def init_or_load_config(config_path: Path, *, create: bool = True) -> dict:
    config = {
        "api_keys": {k: "" for k in API_KEY_NAMES},
        "headers": dict(DEFAULT_HEADERS),
    }

    if not config_path.exists():
        if create:
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
    if not value:
        return "(empty)"
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}…{value[-4:]}"


_SECRET_HEADER_RE = re.compile(
    r"auth|token|key|secret|cookie|pass|credential|session",
    re.IGNORECASE,
)


def mask_header(name: str, value: str) -> str:
    if _SECRET_HEADER_RE.search(name):
        return mask_key(value)
    return value


def print_config_summary(config: dict, config_path: Path) -> None:
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
        print(f"  {k}: {mask_header(k, v)}")
    print()

    print(f"{BOLD}API Keys{RESET}:")
    active = 0
    for k, v in config["api_keys"].items():
        if v:
            active += 1
            print(f"  {GREEN}✓{RESET} {k:<16} {mask_key(v)}")
    if active == 0:
        print(
            f"  {DIM}(none configured — keyless sources only: "
            f"{', '.join(sorted(KEYLESS_SOURCES))}){RESET}"
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
        if "@" in item:
            item = item.rsplit("@", 1)[1]
        item = item.split("/")[0].split(":")[0]
    item = _STAR_PREFIX.sub("", item)
    return item.rstrip(".")


def clean_subdomain(sub: str, domain: str) -> str | None:
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


def detect_input_mode(lines: list[str]) -> str:
    """
    Heuristic: distinguish a subdomain list from an apex-domain list.

    Returns "subdomains" only when a strong signal is present:
      - ≥2 non-comment lines
      - all lines share a common suffix of ≥2 labels
      - every line has MORE labels than that shared suffix
        (i.e. every line is a strict subdomain of the common apex)

    Single-line files, mixed files, and files with differing TLDs are
    treated as "apex" (safer default; user can force with --probe-only).
    """
    clean = [l for l in lines if l and not l.startswith("#")]
    if len(clean) < 2:
        return "apex"

    parsed = [l.split(".") for l in clean]
    shortest = min(parsed, key=len)

    suffix_len = 0
    for i in range(1, len(shortest) + 1):
        candidate = shortest[-i:]
        if all(l[-i:] == candidate for l in parsed if len(l) >= i):
            suffix_len = i
        else:
            break

    # Strict subdomain signal: shared apex of ≥2 labels AND every line
    # extends it with at least one extra label.
    if suffix_len >= 2 and all(len(l) > suffix_len for l in parsed):
        return "subdomains"
    return "apex"


# ----------------------------------------------------------------------
# HTTP helper
# ----------------------------------------------------------------------
async def http_get_with_retry(
    client: httpx.AsyncClient,
    url: str,
    *,
    headers: dict | None = None,
    retries: int = 2,
    **kwargs,
) -> httpx.Response:
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
            if attempt < retries:
                backoff = (1.0 + attempt) + random.uniform(0, 0.5)
                vlog(f"Retry {url} in {backoff:.1f}s ({type(e).__name__})")
                await asyncio.sleep(backoff)
                continue
            raise
    raise RuntimeError(f"http_get_with_retry exhausted for {url}")


# ======================================================================
# FETCH FUNCTIONS (unchanged from v1.1.0 — all 40 sources)
# ======================================================================
async def fetch_crtsh(client, domain, key=""):
    subs = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = await http_get_with_retry(client, url, timeout=30.0)
        if resp.status_code == 200:
            for entry in resp.json():
                for name in str(entry.get("name_value", "")).splitlines():
                    c = clean_subdomain(name, domain)
                    if c:
                        subs.add(c)
    except Exception as e:
        vlog(f"crt.sh failed for {domain}: {e}")
    return subs


async def fetch_hackertarget(client, domain, key=""):
    subs = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        resp = await http_get_with_retry(client, url, timeout=20.0)
        if resp.status_code == 200 and "API count exceeded" not in resp.text:
            for line in resp.text.splitlines():
                c = clean_subdomain(line.split(",")[0], domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"HackerTarget failed for {domain}: {e}")
    return subs


async def fetch_alienvault(client, domain, key=""):
    subs = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    headers = {"X-OTX-API-KEY": key} if key else {}
    try:
        resp = await http_get_with_retry(client, url, headers=headers, timeout=25.0)
        if resp.status_code == 200:
            for r in resp.json().get("passive_dns", []):
                c = clean_subdomain(r.get("hostname", ""), domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"AlienVault failed for {domain}: {e}")
    return subs


async def fetch_anubis(client, domain, key=""):
    subs = set()
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    try:
        resp = await http_get_with_retry(client, url, timeout=15.0, retries=1)
        if resp.status_code == 200:
            for item in resp.json():
                c = clean_subdomain(item, domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"Anubis failed for {domain}: {e}")
    return subs


async def fetch_wayback(client, domain, key=""):
    subs = set()
    url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    )
    try:
        resp = await http_get_with_retry(client, url, timeout=30.0)
        if resp.status_code == 200:
            for row in resp.json()[1:]:
                if row:
                    c = clean_subdomain(urlparse(row[0]).hostname or "", domain)
                    if c:
                        subs.add(c)
    except Exception as e:
        vlog(f"Wayback failed for {domain}: {e}")
    return subs


async def fetch_bevigil(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://osint.bevigil.com/api/{domain}/subdomains/"
    try:
        resp = await http_get_with_retry(
            client, url, headers={"X-Access-Token": key}, timeout=20.0
        )
        if resp.status_code == 200:
            for item in resp.json().get("subdomains", []):
                c = clean_subdomain(item, domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"BeVigil failed for {domain}: {e}")
    return subs


async def fetch_bufferover(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://dns.bufferover.run/dns?q=.{domain}"
    try:
        resp = await http_get_with_retry(
            client, url, headers={"x-api-key": key}, timeout=20.0
        )
        if resp.status_code == 200:
            data = resp.json()
            for row in (data.get("FDNS_A") or []) + (data.get("RDNS") or []):
                parts = row.split(",")
                if len(parts) >= 2:
                    c = clean_subdomain(parts[1], domain)
                    if c:
                        subs.add(c)
    except Exception as e:
        vlog(f"BufferOver failed for {domain}: {e}")
    return subs


async def fetch_builtwith(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://api.builtwith.com/v21/api.json?KEY={key}&LOOKUP={domain}&SUB=1"
    try:
        resp = await http_get_with_retry(client, url, timeout=25.0)
        if resp.status_code == 200:
            for result in resp.json().get("Results", []):
                for path in result.get("Result", {}).get("Paths", []):
                    c = clean_subdomain(path.get("Domain", ""), domain)
                    if c:
                        subs.add(c)
                for sub in result.get("Result", {}).get("SubDomains", []):
                    c = clean_subdomain(sub, domain)
                    if c:
                        subs.add(c)
    except Exception as e:
        vlog(f"BuiltWith failed for {domain}: {e}")
    return subs


async def fetch_c99(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://api.c99.nl/subdomainfinder?key={key}&domain={domain}&json"
    try:
        resp = await http_get_with_retry(client, url, timeout=30.0)
        if resp.status_code == 200:
            for item in resp.json().get("subdomains", []) or []:
                c = clean_subdomain(item, domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"C99 failed for {domain}: {e}")
    return subs


async def fetch_censys(client, domain, key):
    subs = set()
    if not key or ":" not in key:
        vlog("Censys requires 'API_ID:API_SECRET' format")
        return subs
    api_id, api_secret = key.split(":", 1)
    url = f"https://search.censys.io/api/v2/hosts/search?q=names:{domain}&per_page=100"
    try:
        resp = await http_get_with_retry(
            client, url, auth=(api_id, api_secret), timeout=25.0
        )
        if resp.status_code == 200:
            for hit in resp.json().get("result", {}).get("hits", []):
                for name in hit.get("names", []):
                    c = clean_subdomain(name, domain)
                    if c:
                        subs.add(c)
    except Exception as e:
        vlog(f"Censys failed for {domain}: {e}")
    return subs


async def fetch_certspotter(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = (
        f"https://api.certspotter.com/v1/issuances"
        f"?domain={domain}&include_subdomains=true&expand=dns_names"
    )
    try:
        resp = await http_get_with_retry(
            client, url, headers={"Authorization": f"Bearer {key}"}, timeout=20.0
        )
        if resp.status_code == 200:
            for entry in resp.json():
                for name in entry.get("dns_names", []):
                    c = clean_subdomain(name, domain)
                    if c:
                        subs.add(c)
    except Exception as e:
        vlog(f"CertSpotter failed for {domain}: {e}")
    return subs


async def fetch_chaos(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
    try:
        resp = await http_get_with_retry(
            client, url, headers={"Authorization": key}, timeout=20.0
        )
        if resp.status_code == 200:
            for sub in resp.json().get("subdomains", []):
                c = clean_subdomain(f"{sub}.{domain}", domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"Chaos failed for {domain}: {e}")
    return subs


async def fetch_chinaz(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://apidatav2.chinaz.com/single/subdomain/{domain}?key={key}"
    try:
        resp = await http_get_with_retry(client, url, timeout=25.0)
        if resp.status_code == 200:
            for item in resp.json().get("Result", []) or []:
                c = clean_subdomain(item.get("SubDomain", ""), domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"Chinaz failed for {domain}: {e}")
    return subs


async def fetch_digitalyama(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://api.digitalyama.com/subdomain_finder?domain={domain}&key={key}"
    try:
        resp = await http_get_with_retry(client, url, timeout=25.0)
        if resp.status_code == 200:
            for item in resp.json().get("subdomains", []) or []:
                c = clean_subdomain(item, domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"DigitalYama failed for {domain}: {e}")
    return subs


async def fetch_dnsdb(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://api.dnsdb.info/lookup/rrset/name/*.{domain}/A?limit=1000"
    try:
        resp = await http_get_with_retry(
            client, url, headers={"X-API-Key": key}, timeout=25.0
        )
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                try:
                    obj = json.loads(line)
                    c = clean_subdomain(obj.get("rrname", "").rstrip("."), domain)
                    if c:
                        subs.add(c)
                except Exception:
                    continue
    except Exception as e:
        vlog(f"DNSDB failed for {domain}: {e}")
    return subs


async def fetch_dnsdumpster(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://api.dnsdumpster.com/domain/{domain}"
    try:
        resp = await http_get_with_retry(
            client, url, headers={"X-API-Key": key}, timeout=25.0
        )
        if resp.status_code == 200:
            data = resp.json()
            for section in ("a", "cname"):
                for record in data.get(section, []) or []:
                    c = clean_subdomain(record.get("host", ""), domain)
                    if c:
                        subs.add(c)
    except Exception as e:
        vlog(f"DNSDumpster failed for {domain}: {e}")
    return subs


async def fetch_dnsrepo(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://dnsrepo.nou-parrain.com/api/subdomains/{domain}?key={key}"
    try:
        resp = await http_get_with_retry(client, url, timeout=25.0)
        if resp.status_code == 200:
            for item in resp.json().get("subdomains", []) or []:
                c = clean_subdomain(item, domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"DNSRepo failed for {domain}: {e}")
    return subs


async def fetch_domainsproject(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://api.domainsproject.org/v1/subdomains/{domain}?key={key}"
    try:
        resp = await http_get_with_retry(client, url, timeout=25.0)
        if resp.status_code == 200:
            for item in resp.json().get("subdomains", []) or []:
                c = clean_subdomain(item, domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"DomainsProject failed for {domain}: {e}")
    return subs


async def fetch_driftnet(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://api.driftnet.io/v1/subdomains?domain={domain}&key={key}"
    try:
        resp = await http_get_with_retry(client, url, timeout=25.0)
        if resp.status_code == 200:
            for item in resp.json().get("subdomains", []) or []:
                c = clean_subdomain(item, domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"Driftnet failed for {domain}: {e}")
    return subs


async def fetch_fofa(client, domain, key):
    subs = set()
    if not key or ":" not in key:
        vlog("FOFA requires 'email:api_key' format")
        return subs
    import base64
    email, api_key = key.split(":", 1)
    query = f'domain="{domain}"'
    qbase64 = base64.b64encode(query.encode()).decode()
    url = f"https://fofa.info/api/v1/search/all?email={email}&key={api_key}&qbase64={qbase64}&size=1000&fields=host"
    try:
        resp = await http_get_with_retry(client, url, timeout=25.0)
        if resp.status_code == 200:
            for row in resp.json().get("results", []) or []:
                host = row[0] if isinstance(row, list) else row
                c = clean_subdomain(urlparse(f"http://{host}").hostname or "", domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"FOFA failed for {domain}: {e}")
    return subs


async def fetch_fullhunt(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://fullhunt.io/api/v1/domain/{domain}/subdomains"
    try:
        resp = await http_get_with_retry(
            client, url, headers={"X-API-KEY": key}, timeout=25.0
        )
        if resp.status_code == 200:
            for item in resp.json().get("hosts", []) or []:
                c = clean_subdomain(item, domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"FullHunt failed for {domain}: {e}")
    return subs


async def fetch_github(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://api.github.com/search/code?q={domain}+in:file&per_page=100"
    headers = {
        "Authorization": f"token {key}",
        "Accept": "application/vnd.github.v3+json",
    }
    try:
        resp = await http_get_with_retry(client, url, headers=headers, timeout=25.0)
        if resp.status_code == 200:
            for item in resp.json().get("items", []):
                text = f"{item.get('name', '')} {item.get('path', '')}"
                for match in re.findall(
                    rf"([a-zA-Z0-9_-]+\.{re.escape(domain)})", text
                ):
                    c = clean_subdomain(match, domain)
                    if c:
                        subs.add(c)
    except Exception as e:
        vlog(f"GitHub failed for {domain}: {e}")
    return subs


async def fetch_intelx(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = "https://2.intelx.io/phonebook/search"
    payload = {
        "term": domain, "maxresults": 1000, "media": 0,
        "target": 1, "timeout": 20,
    }
    headers = {"x-key": key, "Content-Type": "application/json"}
    try:
        resp = await client.post(url, json=payload, headers=headers, timeout=25.0)
        if resp.status_code == 200:
            for item in resp.json().get("selectors", []) or []:
                c = clean_subdomain(item.get("selectorvalue", ""), domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"IntelX failed for {domain}: {e}")
    return subs


async def fetch_leakix(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://leakix.net/api/subdomains/{domain}"
    try:
        resp = await http_get_with_retry(
            client, url, headers={"api-key": key, "accept": "application/json"},
            timeout=25.0,
        )
        if resp.status_code == 200:
            for item in resp.json() or []:
                c = clean_subdomain(item.get("subdomain", ""), domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"LeakIX failed for {domain}: {e}")
    return subs


async def fetch_merklemap(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://api.merklemap.com/search?query=*.{domain}&key={key}"
    try:
        resp = await http_get_with_retry(client, url, timeout=25.0)
        if resp.status_code == 200:
            for item in resp.json().get("results", []) or []:
                c = clean_subdomain(item.get("domain", ""), domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"MerkleMap failed for {domain}: {e}")
    return subs


async def fetch_netlas(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = (
        f"https://app.netlas.io/api/domains/?q=domain:*.{domain}"
        f"&source_type=include&start=0&fields=domain"
    )
    try:
        resp = await http_get_with_retry(
            client, url, headers={"X-API-Key": key}, timeout=25.0
        )
        if resp.status_code == 200:
            for item in resp.json().get("items", []) or []:
                c = clean_subdomain(item.get("data", {}).get("domain", ""), domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"Netlas failed for {domain}: {e}")
    return subs


async def fetch_onyphe(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://www.onyphe.io/api/v1/summary/domain:{domain}?size=1000"
    try:
        resp = await http_get_with_retry(
            client, url, headers={"Authorization": f"Bearer {key}"}, timeout=25.0
        )
        if resp.status_code == 200:
            for item in resp.json().get("results", []) or []:
                c = clean_subdomain(item.get("hostname", ""), domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"Onyphe failed for {domain}: {e}")
    return subs


async def fetch_profundis(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://api.profundis.io/v1/subdomains/{domain}?key={key}"
    try:
        resp = await http_get_with_retry(client, url, timeout=25.0)
        if resp.status_code == 200:
            for item in resp.json().get("subdomains", []) or []:
                c = clean_subdomain(item, domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"Profundis failed for {domain}: {e}")
    return subs


async def fetch_pugrecon(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://api.pugrecon.com/v1/subdomains?domain={domain}&key={key}"
    try:
        resp = await http_get_with_retry(client, url, timeout=25.0)
        if resp.status_code == 200:
            for item in resp.json().get("subdomains", []) or []:
                c = clean_subdomain(item, domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"PugRecon failed for {domain}: {e}")
    return subs


async def fetch_quake(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = "https://quake.360.net/api/v3/search/quake_service"
    headers = {"X-QuakeToken": key, "Content-Type": "application/json"}
    payload = {"query": f'domain:"{domain}"', "size": 500}
    try:
        resp = await client.post(url, json=payload, headers=headers, timeout=25.0)
        if resp.status_code == 200:
            for item in resp.json().get("data", []) or []:
                hostnames = (
                    item.get("service", {}).get("http", {}).get("hostname", "")
                )
                for name in hostnames.split(","):
                    c = clean_subdomain(name, domain)
                    if c:
                        subs.add(c)
    except Exception as e:
        vlog(f"Quake failed for {domain}: {e}")
    return subs


async def fetch_reconeeer(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://api.reconeer.com/v1/subdomains/{domain}?key={key}"
    try:
        resp = await http_get_with_retry(client, url, timeout=25.0)
        if resp.status_code == 200:
            for item in resp.json().get("subdomains", []) or []:
                c = clean_subdomain(item, domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"Reconeer failed for {domain}: {e}")
    return subs


async def fetch_redhuntlabs(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = (
        f"https://reconapi.redhuntlabs.com/community/v1/domains/subdomains"
        f"?domain={domain}&page_size=1000"
    )
    try:
        resp = await http_get_with_retry(
            client, url, headers={"X-BLOBR-KEY": key}, timeout=25.0
        )
        if resp.status_code == 200:
            for item in resp.json().get("subdomains", []) or []:
                c = clean_subdomain(item, domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"RedHuntLabs failed for {domain}: {e}")
    return subs


async def fetch_robtex(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://freeapi.robtex.com/pdns/forward/{domain}?key={key}"
    try:
        resp = await http_get_with_retry(client, url, timeout=25.0)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                try:
                    obj = json.loads(line)
                    c = clean_subdomain(obj.get("rrname", "").rstrip("."), domain)
                    if c:
                        subs.add(c)
                except Exception:
                    continue
    except Exception as e:
        vlog(f"Robtex failed for {domain}: {e}")
    return subs


async def fetch_rsecloud(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://api.rsecloud.com/v1/subdomains/{domain}?key={key}"
    try:
        resp = await http_get_with_retry(client, url, timeout=25.0)
        if resp.status_code == 200:
            for item in resp.json().get("subdomains", []) or []:
                c = clean_subdomain(item, domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"RSECloud failed for {domain}: {e}")
    return subs


async def fetch_securitytrails(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    try:
        resp = await http_get_with_retry(
            client, url, headers={"APIKEY": key}, timeout=25.0
        )
        if resp.status_code == 200:
            for item in resp.json().get("subdomains", []) or []:
                c = clean_subdomain(f"{item}.{domain}", domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"SecurityTrails failed for {domain}: {e}")
    return subs


async def fetch_shodan(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = (
        f"https://api.shodan.io/shodan/host/search"
        f"?query=hostname:{domain}&key={key}&page=1"
    )
    try:
        resp = await http_get_with_retry(client, url, timeout=25.0)
        if resp.status_code == 200:
            for m in resp.json().get("matches", []) or []:
                for name in m.get("hostnames", []) or []:
                    c = clean_subdomain(name, domain)
                    if c:
                        subs.add(c)
    except Exception as e:
        vlog(f"Shodan failed for {domain}: {e}")
    return subs


async def fetch_submd(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://api.submd.com/v1/subdomains/{domain}?key={key}"
    try:
        resp = await http_get_with_retry(client, url, timeout=25.0)
        if resp.status_code == 200:
            for item in resp.json().get("subdomains", []) or []:
                c = clean_subdomain(item, domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"SubMD failed for {domain}: {e}")
    return subs


async def fetch_threatbook(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = (
        f"https://api.threatbook.cn/v3/domain/sub_domains"
        f"?apikey={key}&resource={domain}"
    )
    try:
        resp = await http_get_with_retry(client, url, timeout=25.0)
        if resp.status_code == 200:
            for item in resp.json().get("data", {}).get(domain, []) or []:
                c = clean_subdomain(item, domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"ThreatBook failed for {domain}: {e}")
    return subs


async def fetch_urlscan(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000"
    try:
        resp = await http_get_with_retry(
            client, url, headers={"API-Key": key}, timeout=25.0
        )
        if resp.status_code == 200:
            for item in resp.json().get("results", []) or []:
                for cand in (
                    item.get("page", {}).get("domain", ""),
                    item.get("task", {}).get("domain", ""),
                ):
                    c = clean_subdomain(cand, domain)
                    if c:
                        subs.add(c)
    except Exception as e:
        vlog(f"urlscan failed for {domain}: {e}")
    return subs


async def fetch_virustotal(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    try:
        resp = await http_get_with_retry(
            client, url, headers={"x-apikey": key}, timeout=20.0
        )
        if resp.status_code == 200:
            for item in resp.json().get("data", []):
                c = clean_subdomain(item.get("id", ""), domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"VirusTotal failed for {domain}: {e}")
    return subs


async def fetch_whoisxmlapi(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://subdomains.whoisxmlapi.com/api/v1?apiKey={key}&domainName={domain}"
    try:
        resp = await http_get_with_retry(client, url, timeout=25.0)
        if resp.status_code == 200:
            for item in resp.json().get("result", {}).get("domains", []) or []:
                c = clean_subdomain(item.get("domain", ""), domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"WhoisXMLAPI failed for {domain}: {e}")
    return subs


async def fetch_windvane(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://api.windvane.com/v1/subdomains/{domain}?key={key}"
    try:
        resp = await http_get_with_retry(client, url, timeout=25.0)
        if resp.status_code == 200:
            for item in resp.json().get("subdomains", []) or []:
                c = clean_subdomain(item, domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"Windvane failed for {domain}: {e}")
    return subs


async def fetch_zoomeyeapi(client, domain, key):
    subs = set()
    if not key:
        return subs
    url = f"https://api.zoomeye.org/domain/search?q={domain}&type=0&page=1"
    try:
        resp = await http_get_with_retry(
            client, url, headers={"API-KEY": key}, timeout=25.0
        )
        if resp.status_code == 200:
            for item in resp.json().get("list", []) or []:
                c = clean_subdomain(item.get("name", ""), domain)
                if c:
                    subs.add(c)
    except Exception as e:
        vlog(f"ZoomEye failed for {domain}: {e}")
    return subs


# ======================================================================
# SOURCE DISPATCH
# ======================================================================
SOURCE_DISPATCH: dict[str, tuple] = {
    "alienvault": (fetch_alienvault, False),
    "anubis": (fetch_anubis, False),
    "crtsh": (fetch_crtsh, False),
    "hackertarget": (fetch_hackertarget, False),
    "wayback": (fetch_wayback, False),
    "bevigil": (fetch_bevigil, True),
    "bufferover": (fetch_bufferover, True),
    "builtwith": (fetch_builtwith, True),
    "c99": (fetch_c99, True),
    "censys": (fetch_censys, True),
    "certspotter": (fetch_certspotter, True),
    "chaos": (fetch_chaos, True),
    "chinaz": (fetch_chinaz, True),
    "digitalyama": (fetch_digitalyama, True),
    "dnsdb": (fetch_dnsdb, True),
    "dnsdumpster": (fetch_dnsdumpster, True),
    "dnsrepo": (fetch_dnsrepo, True),
    "domainsproject": (fetch_domainsproject, True),
    "driftnet": (fetch_driftnet, True),
    "fofa": (fetch_fofa, True),
    "fullhunt": (fetch_fullhunt, True),
    "github": (fetch_github, True),
    "intelx": (fetch_intelx, True),
    "leakix": (fetch_leakix, True),
    "merklemap": (fetch_merklemap, True),
    "netlas": (fetch_netlas, True),
    "onyphe": (fetch_onyphe, True),
    "profundis": (fetch_profundis, True),
    "pugrecon": (fetch_pugrecon, True),
    "quake": (fetch_quake, True),
    "reconeeer": (fetch_reconeeer, True),
    "redhuntlabs": (fetch_redhuntlabs, True),
    "robtex": (fetch_robtex, True),
    "rsecloud": (fetch_rsecloud, True),
    "securitytrails": (fetch_securitytrails, True),
    "shodan": (fetch_shodan, True),
    "submd": (fetch_submd, True),
    "threatbook": (fetch_threatbook, True),
    "urlscan": (fetch_urlscan, True),
    "virustotal": (fetch_virustotal, True),
    "whoisxmlapi": (fetch_whoisxmlapi, True),
    "windvane": (fetch_windvane, True),
    "zoomeyeapi": (fetch_zoomeyeapi, True),
}


def get_active_sources(api_keys: dict[str, str]) -> list[tuple[str, object]]:
    active = []
    for source_name, (fetch_fn, requires_key) in SOURCE_DISPATCH.items():
        if requires_key:
            if not api_keys.get(source_name, ""):
                vlog(f"Skipping {source_name} (no API key configured)")
                continue
        active.append((source_name, fetch_fn))
    return active


# ======================================================================
# DNS RESOLUTION
# ======================================================================
def build_resolver(nameservers: list[str]):
    if not HAS_AIODNS:
        return None, {}
    try:
        return aiodns.DNSResolver(
            nameservers=nameservers, timeout=3.0, tries=2
        ), {}
    except TypeError:
        pass
    try:
        resolver = aiodns.DNSResolver(nameservers=nameservers)
    except Exception as e:
        vlog(f"Failed to build aiodns resolver: {e}")
        return None, {}
    query_kwargs: dict = {}
    try:
        if "timeout" in inspect.signature(resolver.query).parameters:
            query_kwargs["timeout"] = 3.0
    except Exception:
        pass
    return resolver, query_kwargs


async def resolve_single_host(sub, sem, resolver, query_kwargs, loop):
    async with sem:
        if resolver is not None:
            try:
                res = await resolver.query(sub, "A", **query_kwargs)
                return (sub, sorted({r.host for r in res}))
            except Exception:
                return (sub, [])
        try:
            infos = await loop.getaddrinfo(sub, None, family=socket.AF_INET)
            return (sub, sorted({i[4][0] for i in infos if i[4]}))
        except Exception:
            return (sub, [])


async def batch_gather(factory, items, batch_size=2000):
    items = list(items)
    results = []
    for i in range(0, len(items), batch_size):
        batch = items[i:i + batch_size]
        results.extend(await asyncio.gather(*(factory(it) for it in batch)))
    return results


async def resolve_subdomains(subdomains, concurrency, nameservers, quiet):
    if not subdomains:
        return {}
    spinner = Spinner(f"Resolving {len(subdomains)} subdomains via async DNS...")
    if not quiet:
        spinner.start()
    try:
        sem = asyncio.Semaphore(concurrency)
        loop = asyncio.get_running_loop()
        resolver, qk = build_resolver(nameservers)
        if resolver is None:
            vlog("Using socket.getaddrinfo fallback for DNS resolution")
        results = await batch_gather(
            lambda s: resolve_single_host(s, sem, resolver, qk, loop),
            sorted(subdomains),
            batch_size=2000,
        )
        live_map = {s: ips for s, ips in results if ips}
    finally:
        if not quiet:
            await spinner.stop(
                f"DNS Resolution complete: "
                f"{len(locals().get('live_map', {}))}/{len(subdomains)} live hosts verified."
            )
    return live_map


# ======================================================================
# HTTP PROBING
# ======================================================================
async def probe_single_host(client, sub, sem):
    async with sem:
        for scheme in ("https", "http"):
            url = f"{scheme}://{sub}"
            try:
                resp = await client.get(url, timeout=8.0)
                body = resp.text[:100_000]
                m = re.search(
                    r"<title[^>]*>(.*?)</title>", body,
                    re.IGNORECASE | re.DOTALL,
                )
                title = (
                    m.group(1).strip().replace("\n", " ")[:60]
                    if m else ""
                )
                return (sub, {
                    "url": str(resp.url),
                    "status": resp.status_code,
                    "title": title,
                })
            except Exception:
                continue
        return (sub, None)


async def probe_http_hosts(subdomains, headers, concurrency, quiet):
    if not subdomains:
        return {}
    spinner = Spinner(
        f"Probing {len(subdomains)} hosts for active HTTP/HTTPS services..."
    )
    if not quiet:
        spinner.start()
    try:
        sem = asyncio.Semaphore(concurrency)
        limits = httpx.Limits(max_connections=200, max_keepalive_connections=50)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            async with httpx.AsyncClient(
                headers=headers, follow_redirects=True, verify=False, limits=limits,
            ) as client:
                results = await batch_gather(
                    lambda s: probe_single_host(client, s, sem),
                    subdomains, batch_size=2000,
                )
        probed = {s: info for s, info in results if info}
    finally:
        if not quiet:
            await spinner.stop(
                f"HTTP Probing complete: "
                f"{len(locals().get('probed', {}))} active web servers responding."
            )
    return probed


# ======================================================================
# MAIN ORCHESTRATOR
# ======================================================================
async def enumerate_single_domain(client, domain, api_keys, quiet):
    active = get_active_sources(api_keys)
    if not active:
        return set()
    spinner = Spinner(f"Querying {len(active)} OSINT sources for {domain}...")
    if not quiet:
        spinner.start()
    try:
        tasks = [
            fn(client, domain, api_keys.get(name, ""))
            for name, fn in active
        ]
        results = await asyncio.gather(*tasks)
        merged = set().union(*results) if results else set()
    finally:
        if not quiet:
            await spinner.stop(
                f"Discovered {len(locals().get('merged', set()))} "
                f"unique passive subdomains for {domain}"
            )
    if not merged and not quiet:
        print(
            f"{YELLOW}[!] No subdomains discovered for {domain}. "
            f"Run with -v for per-source details.{RESET}",
            file=sys.stderr,
        )
    return merged


def _load_targets_from_file(path: Path) -> list[str]:
    raw = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    out = []
    for line in raw:
        d = normalize_domain_input(line)
        if d:
            out.append(d)
    return out


def _parse_match_codes(spec: str | None, probe_enabled: bool) -> set[int] | None:
    if not spec:
        return None
    if not probe_enabled:
        print(
            f"{YELLOW}[!] --match-codes ignored without --probe{RESET}",
            file=sys.stderr,
        )
        return None
    try:
        codes = {int(c.strip()) for c in spec.split(",") if c.strip()}
        if not codes:
            raise ValueError("empty")
        return codes
    except ValueError:
        print(
            f"{RED}[!] Error: --match-codes must be comma-separated integers "
            f"(e.g. 200,301,403){RESET}",
            file=sys.stderr,
        )
        sys.exit(1)


async def run_engine(args: argparse.Namespace) -> None:
    global _VERBOSE
    _VERBOSE = bool(args.verbose)

    config_path = Path(args.config).expanduser()
    config = init_or_load_config(config_path, create=not args.show_config)

    if args.show_config:
        print_config_summary(config, config_path)
        return

    api_keys = config["api_keys"]
    config_headers = dict(config["headers"])

    probe_headers = dict(config_headers)
    if args.header:
        for raw_h in args.header:
            if ":" in raw_h:
                k, v = raw_h.split(":", 1)
                probe_headers[k.strip()] = v.strip()

    # -------- Parse --match-codes --------
    match_codes = _parse_match_codes(args.match_codes, args.probe)

    # -------- Load targets & detect mode --------
    targets: list[str] = []
    if args.domain:
        d = normalize_domain_input(args.domain)
        if d:
            targets.append(d)

    input_is_subdomains = False
    if args.input:
        input_path = Path(args.input).expanduser()
        if not input_path.is_file():
            print(
                f"{RED}[!] Error: Input file not found: {input_path}{RESET}",
                file=sys.stderr,
            )
            sys.exit(1)
        file_targets = _load_targets_from_file(input_path)
        if not file_targets:
            print(
                f"{RED}[!] Error: No valid entries in {input_path}{RESET}",
                file=sys.stderr,
            )
            sys.exit(1)

        # Determine whether the input file is a subdomain list
        if args.probe_only:
            input_is_subdomains = True
        elif args.probe and not args.domain:
            if detect_input_mode(file_targets) == "subdomains":
                input_is_subdomains = True
                if not args.silent:
                    print(
                        f"{CYAN}[i] Input detected as subdomain list — "
                        f"probing directly (skipping discovery).{RESET}"
                    )
                    print(
                        f"{DIM}    Use --probe-only to force this mode, "
                        f"or pass -d <apex> to force discovery.{RESET}"
                    )

        for d in file_targets:
            if d not in targets:
                targets.append(d)

    if args.probe_only and args.domain and not args.input:
        input_is_subdomains = True

    if not targets:
        print(
            f"{RED}[!] Error: No valid target domains provided. "
            f"Use -d or -i.{RESET}",
            file=sys.stderr,
        )
        sys.exit(1)

    # In subdomain-input mode, do NOT auto-enable -r (hosts were likely
    # already resolved when the file was produced). In apex mode, keep the
    # legacy `--probe implies -r` optimization.
    if args.probe and not args.resolve and not input_is_subdomains:
        args.resolve = True
        args._probe_implied_resolve = True

    # -------- Info panel --------
    if not args.silent:
        keyed_active = [
            s for s, (_, req) in SOURCE_DISPATCH.items()
            if req and api_keys.get(s)
        ]
        keyless_active = [
            s for s, (_, req) in SOURCE_DISPATCH.items() if not req
        ]
        if input_is_subdomains:
            print(f"{CYAN}[i] Mode:{RESET}              direct (--probe-only)")
            print(f"{CYAN}[i] Input subdomains:{RESET}   {len(targets)}")
        else:
            print(f"{CYAN}[i] Mode:{RESET}              discover-then-process")
            print(f"{CYAN}[i] Loaded Targets:{RESET}     {len(targets)} domain(s)")
            print(
                f"{CYAN}[i] Active Sources:{RESET}     "
                f"{len(keyless_active)} keyless + {len(keyed_active)} keyed "
                f"({len(keyless_active) + len(keyed_active)} total)"
            )
        print(
            f"{CYAN}[i] Probe Headers:{RESET}      "
            f"{', '.join(probe_headers.keys())}"
        )
        if match_codes:
            print(
                f"{CYAN}[i] Match Codes:{RESET}        {sorted(match_codes)}"
            )

    # -------- Stage 1: Discovery (skipped in subdomain mode) --------
    all_discovered: set[str] = set()
    if input_is_subdomains:
        all_discovered = set(targets)
    else:
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
                f"\n{GREEN}{BOLD}[✓] Total Unique Passive Subdomains "
                f"Discovered: {len(all_discovered)}{RESET}"
            )

    # -------- Stage 2: DNS resolution --------
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

    # -------- Stage 3: HTTP probing + status filter --------
    probed_map: dict[str, dict] = {}
    if args.probe and final_subs:
        probed_map = await probe_http_hosts(
            final_subs, probe_headers, args.threads, args.silent
        )

        if match_codes:
            original = len(probed_map)
            probed_map = {
                s: i for s, i in probed_map.items()
                if i["status"] in match_codes
            }
            if not args.silent:
                print(
                    f"{GREEN}[✓] Status filter {sorted(match_codes)}: "
                    f"{len(probed_map)} matched / {original} responsive{RESET}"
                )

        # When probing, final_subs reflects only surviving (responsive or
        # matched) hosts.
        final_subs = sorted(probed_map.keys())

    # -------- Output: list suppressed by default --------
    if args.silent:
        # Silent mode preserves the original pipe-friendly contract:
        # raw one-per-line on stdout.
        for sub in final_subs:
            print(sub)
    else:
        # Human-facing summary block
        print(f"\n{CYAN}{BOLD}─── SUBNORYX Summary ───{RESET}")
        if input_is_subdomains:
            print(f"  {BOLD}Input subdomains:{RESET}  {len(targets)}")
        else:
            print(f"  {BOLD}Discovered:{RESET}        {len(all_discovered)}")
        if args.resolve:
            print(f"  {BOLD}Resolved:{RESET}          {len(resolved_map)}")
        if args.probe:
            print(f"  {BOLD}Responsive:{RESET}        {len(probed_map)}")
            if match_codes:
                print(
                    f"  {BOLD}Matched:{RESET}           {len(final_subs)} "
                    f"({sorted(match_codes)})"
                )
        elif not input_is_subdomains:
            print(f"  {BOLD}Final:{RESET}             {len(final_subs)}")

        # Optional formatted list
        if args.show_list and final_subs:
            print(
                f"\n{CYAN}{BOLD}─── Subdomain List "
                f"({len(final_subs)}) ───{RESET}"
            )
            for sub in final_subs:
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
        elif final_subs:
            print(
                f"\n  {DIM}(subdomain list suppressed — "
                f"use --show-list to print, -o FILE to save, "
                f"or -s for raw pipe output){RESET}"
            )

    # -------- Save files --------
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
            "input_mode": "subdomains" if input_is_subdomains else "apex",
            "targets": targets,
            "match_codes": sorted(match_codes) if match_codes else None,
            "discovered_count": len(all_discovered),
            "resolved_count": len(resolved_map),
            "responsive_count": len(probed_map),
            "final_count": len(final_subs),
            "subdomains": final_subs,
            "discovered": sorted(all_discovered),
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
    if "--man" in sys.argv[1:] or (
        len(sys.argv) > 1 and sys.argv[1] == "man"
    ):
        print_manual()
        sys.exit(0)

    suppress_banner = any(
        flag in sys.argv[1:]
        for flag in ("-s", "--silent", "-V", "--version")
    )
    if not suppress_banner:
        print_banner()

    parser = argparse.ArgumentParser(
        prog="subnoryx",
        description=(
            "SUBNORYX — Fast Async Subdomain Enumerator with "
            "Two-Stage Workflow & Status-Code Filtering"
        ),
    )
    target_group = parser.add_argument_group("Target Selection")
    target_group.add_argument(
        "-d", "--domain",
        help="Single target domain (apex by default; subdomain with --probe-only)",
    )
    target_group.add_argument(
        "-i", "--input",
        help="Scope file (apex domains to enumerate, or subdomains with --probe)",
    )

    recon_group = parser.add_argument_group("Resolution, Probing & Filtering")
    recon_group.add_argument(
        "-r", "--resolve", action="store_true",
        help="Filter dead subdomains via async DNS resolution (aiodns)",
    )
    recon_group.add_argument(
        "--probe", action="store_true",
        help="Probe hosts for HTTP/HTTPS status & titles",
    )
    recon_group.add_argument(
        "--probe-only", action="store_true",
        help="Skip discovery. Treat -d/-i as subdomains to probe directly. "
             "Implies --probe.",
    )
    recon_group.add_argument(
        "--match-codes", metavar="CODES",
        help="Comma-separated HTTP status codes to keep during probing "
             "(e.g. 200,301,403). Filters -o and --json output. "
             "Without this flag, all responsive codes are kept.",
    )
    recon_group.add_argument(
        "-t", "--threads", type=int, default=100,
        help="Concurrency limit (default: 100, min: 1)",
    )
    recon_group.add_argument(
        "--resolvers",
        default="1.1.1.1,8.8.8.8,9.9.9.9",
        help="Comma-separated DNS resolvers (requires aiodns)",
    )

    config_group = parser.add_argument_group("Configuration & Output")
    config_group.add_argument(
        "-o", "--output",
        help="Save filtered subdomain list (plain text)",
    )
    config_group.add_argument(
        "--json", metavar="FILE",
        help="Save full structured results (subdomains + IPs + probe details)",
    )
    config_group.add_argument(
        "--show-list", action="store_true",
        help="Print the full subdomain list to terminal (default: suppressed)",
    )
    config_group.add_argument(
        "-c", "--config", default=str(DEFAULT_CONFIG_PATH),
        help=f"Path to config.yaml (default: {DEFAULT_CONFIG_PATH})",
    )
    config_group.add_argument(
        "--show-config", action="store_true",
        help="Print resolved configuration (masked) and exit",
    )
    config_group.add_argument(
        "-H", "--header", action="append", metavar="KEY:VALUE",
        help="Custom HTTP header for probing only (repeatable)",
    )
    config_group.add_argument(
        "-s", "--silent", action="store_true",
        help="Silent mode (raw subdomains on stdout for piping)",
    )
    config_group.add_argument(
        "-v", "--verbose", action="store_true",
        help="Verbose per-source logs on stderr",
    )
    parser.add_argument(
        "-V", "--version", action="version",
        version=f"SUBNORYX v{__version__} (By Kalmux, {LICENSE})",
    )

    args = parser.parse_args()

    # Validation
    if args.threads < 1:
        parser.error("--threads must be >= 1")

    # --probe-only implies --probe
    if args.probe_only:
        args.probe = True

    # --probe implies -r ONLY in apex mode; the apex/subdomain decision is
    # made inside run_engine() once we can inspect the input file.
    if args.resolve:
        resolvers = [ns.strip() for ns in args.resolvers.split(",") if ns.strip()]
        if not resolvers:
            parser.error("--resolvers must contain at least one resolver IP")

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