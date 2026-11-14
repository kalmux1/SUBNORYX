<div align="center">

```
               _____ __  ______  _   ______  ______  ___  __
              / ___// / / / __ )/ | / / __ \/ __ \ \/ / |/ /
              \__ \/ / / / __  /  |/ / / / / /_/ /\  /|   /
             ___/ / /_/ / /_/ / /|  / /_/ / _, _/ / //   |
            /____/\____/_____/_/ |_/\____/_/ |_| /_//_/|_|
```

**SUBNORYX** — Fast Async Passive Subdomain Enumerator & Recon Engine

[![Python](https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-GPL--2.0-green)](./LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-cyan)]()
[![Async](https://img.shields.io/badge/asyncio-httpx%20%2B%20aiodns-magenta)]()

*~By Kalmux*

</div>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [CLI Reference](#cli-reference)
- [Configuration](#configuration)
- [OSINT Sources](#osint-sources)
- [Examples](#examples)
- [Output Formats](#output-formats)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)
- [Uninstall](#uninstall)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)

---

## Overview

**SUBNORYX** is an asynchronous OSINT recon framework for bug bounty hunters
and penetration testers. Unlike traditional scrapers that rely on fragile HTML
parsing or blocking multiprocessing models, SUBNORYX queries high-speed public
APIs, Certificate Transparency logs, and passive DNS repositories concurrently —
then optionally resolves and probes the results, all without leaving a Safe-Harbor
header behind unless you explicitly ask for one.

Built on `asyncio` + `httpx`, it is designed to be:

- **Fast** — concurrent queries to every OSINT source in parallel.
- **Quiet** — zero headers injected by default.
- **Composable** — pipe-friendly output for `httpx`, `nuclei`, `katana`, etc.
- **Extensible** — clean separation between discovery, resolution, and probing.

---

## Features

- ⚡ **Asynchronous engine** — `asyncio` + `httpx`, no thread-lock overhead.
- 🕵️ **Zero default footprint** — no Safe-Harbor header is injected unless you
  explicitly pass `-H`. Passive API calls use only your configured `User-Agent`.
- 🌐 **Multi-domain scope** — pass a single target with `-d` or a scope file
  with `-i scope.txt`.
- 🔍 **Async DNS resolution** — filter `NXDOMAIN` results with `aiodns`
  (automatic fallback to `socket.getaddrinfo` if missing).
- 🌐 **Active HTTP probing** — `--probe` returns live URLs, HTTP status codes,
  and HTML page titles.
- 🔑 **40+ API integrations** — Shodan, Censys, VirusTotal, SecurityTrails,
  FOFA, Chaos, urlscan, CertSpotter, and more (config template auto-generated).
- 🆓 **Keyless-by-default** — works out of the box with crt.sh, HackerTarget,
  AlienVault, Wayback, and Anubis — no API key required.
- 🔁 **Transient-failure retries** — 429/5xx and network errors are retried
  with jittered backoff.
- 🧾 **Multiple output sinks** — plain text (`-o`), JSON (`--json`), stdout
  piping (`-s`).
- ⚙️ **Config inspector** — `--show-config` prints the resolved configuration
  with API keys **masked** (`abcd…wxyz`), safe to paste anywhere.
- 🎨 **Polished CLI** — animated spinners (TTY-aware), colorized output,
  comprehensive `--man` page.

---

## Requirements

| Dependency | Version | Notes |
|---|---|---|
| **Python** | ≥ 3.9 | `from __future__ import annotations` allows 3.9 support |
| **httpx** | ≥ 0.23 | Required — async HTTP client |
| **aiodns** | ≥ 2.0 | Optional — high-speed async DNS; falls back to `socket` |
| **PyYAML** | ≥ 5.0 | Optional — proper YAML config parsing; falls back to naive parser |

`aiodns` and `PyYAML` are optional but **strongly recommended**.

---

## Installation

### Automated (recommended)

```bash
git clone https://github.com/kalmux1/SUBNORYX.git
cd SUBNORYX
chmod +x install.sh
./install.sh
source ~/.bashrc      # or ~/.zshrc
```

The installer:

1. Validates `python3` ≥ 3.9 and locates `subnoryx.py`.
2. Runs `chmod +x subnoryx.py`.
3. Offers to `pip install --user httpx aiodns pyyaml` if any are missing.
4. Detects your shell (`bash`/`zsh`) and appends an **idempotent alias block**
   to `~/.bashrc` or `~/.zshrc`:
   ```bash
   # >>> SUBNORYX alias >>>
   alias subnoryx='python3 "/home/user/SUBNORYX/subnoryx.py"'
   # <<< SUBNORYX alias <<<
   ```
5. Optionally creates a `/usr/local/bin/subnoryx` symlink (for scripts/CI
   where aliases don't expand).
6. Reloads the rc file automatically when run via `source ./install.sh`.

**Installer flags:**

```bash
./install.sh             # interactive install
./install.sh --no-deps   # skip pip dependency prompt
./install.sh --uninstall # remove alias block + symlink
./install.sh -h          # installer help
```

### Manual

```bash
git clone https://github.com/kalmux1/SUBNORYX.git
cd SUBNORYX
chmod +x subnoryx.py
pip install --user httpx aiodns pyyaml

# Option A — alias
echo "alias subnoryx='python3 $(pwd)/subnoryx.py'" >> ~/.bashrc
source ~/.bashrc

# Option B — symlink
sudo ln -sf "$(pwd)/subnoryx.py" /usr/local/bin/subnoryx

# Option C — run directly
python3 subnoryx.py --man
```

---

## Quick Start

```bash
# Inspect configuration (safe to paste — keys are masked)
subnoryx --show-config

# Full manual
subnoryx --man

# Minimal scan — keyless OSINT, no resolution
subnoryx -d example.com

# Discovery + DNS resolution + HTTP probing
subnoryx -d example.com -r --probe

# Multi-domain scope file, save everything
subnoryx -i scope.txt -r --probe -o subs.txt --json subs.json -v

# Pipe straight into httpx (silent mode)
subnoryx -d example.com -r -s | httpx -silent -title -tech-detect
```

---

## Usage

```
subnoryx [-h] [-d DOMAIN] [-i INPUT] [-r] [--probe] [-t THREADS]
         [--resolvers RESOLVERS] [-o OUTPUT] [--json FILE]
         [-c CONFIG] [--show-config] [-H KEY:VALUE] [-s] [-v] [-V]
         [--man]
```

### Example output

```
   _____ __  ______  _   ______  ______  ___  __
  / ___// / / / __ )/ | / / __ \/ __ \ \/ / |/ /
  \__ \/ / / / __  /  |/ / / / / /_/ /\  /|   /
 ___/ / /_/ / /_/ / /|  / /_/ / _, _/ / //   |
/____/\____/_____/_/ |_/\____/_/ |_| /_//_/|_|
SUBNORYX v1.0.0 — Async Subdomain Recon Engine
                 ~By Kalmux

[i] Loaded Targets:      1 domain(s)
[i] Probe Headers:       User-Agent
[i] Active API Keys:     None (using free keyless OSINT engines)

⠹ Querying OSINT sources for example.com...
[✓] Discovered 247 unique passive subdomains for example.com

[✓] Total Unique Passive Subdomains Discovered: 247
⠼ Resolving 247 subdomains via async DNS...
[✓] DNS Resolution complete: 182/247 live hosts verified.
⠴ Probing 182 hosts for active HTTP/HTTPS services...
[✓] HTTP Probing complete: 164 active web servers responding.

--- SUBNORYX Final Results (182) ---
  api.example.com [93.184.216.34] -> https://api.example.com [200] [API Gateway]
  mail.example.com [93.184.216.34] -> https://mail.example.com [200] [Webmail Login]
  vpn.example.com [93.184.216.34] -> https://vpn.example.com [403]
  ...
```

---

## CLI Reference

### Target Selection

| Flag | Description |
|---|---|
| `-d, --domain DOMAIN` | Single target apex domain (e.g., `example.com`) |
| `-i, --input FILE` | Scope file — one domain per line, `#` comments supported |

### Resolution & Probing

| Flag | Description |
|---|---|
| `-r, --resolve` | Filter dead subdomains via async DNS (`aiodns` / `socket`) |
| `--probe` | Probe live hosts for HTTP/HTTPS status codes and page titles |
| `-t, --threads N` | Concurrency limit for resolution/probing (default: `100`) |
| `--resolvers LIST` | Comma-separated DNS resolvers (default: `1.1.1.1,8.8.8.8,9.9.9.9`) — requires `aiodns` |

### Configuration & Output

| Flag | Description |
|---|---|
| `-o, --output FILE` | Save cleaned, unique subdomain list (plain text) |
| `--json FILE` | Save full results (subdomains + IPs + probe info) as JSON |
| `-c, --config PATH` | Path to `config.yaml` (default: `~/.config/subnoryx/config.yaml`) |
| `--show-config` | Print resolved config with **masked** API keys and exit |
| `-H, --header KEY:VALUE` | Custom HTTP header for **probing only** (e.g., `-H 'X-Bug-Bounty: HackerOne-user'`) |
| `-s, --silent` | Output only raw subdomains — perfect for piping |
| `-v, --verbose` | Verbose output on **stderr** (source timing, retries, failures) |
| `-V, --version` | Print version and exit |
| `--man` | Print the full built-in manual |

### Header Precedence

| Header set | Applies to | Override via |
|---|---|---|
| `headers:` in config | Passive API calls + probing | Edit `~/.config/subnoryx/config.yaml` |
| `-H KEY:VALUE` on CLI | **Probing only** | Repeated `-H` flags |

> **Why probing only?** Sending `X-Bug-Bounty` to `crt.sh` or VirusTotal is
> unusual and can leak your identity to third-party aggregators. If you want
> custom headers on API calls, put them in the config file's `headers:` block.

---

## Configuration

SUBNORYX auto-creates `~/.config/subnoryx/config.yaml` on first run:

```yaml
# SUBNORYX Configuration File (v1.0.0)
# Leave API keys empty ("") to use keyless OSINT engines

api_keys:
  alienvault: ""
  certspotter: ""
  chaos: ""
  censys: ""
  fofa: ""
  securitytrails: ""
  shodan: ""
  urlscan: ""
  virustotal: ""
  # ... 40 keys total

headers:
  User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ..."
```

### Inspecting your config

```bash
subnoryx --show-config
```

```
SUBNORYX Configuration Summary
───────────────────────────────────────────────────────
Config file : /home/kalmux/.config/subnoryx/config.yaml
Status      : exists

Headers (1):
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...

API Keys:
  ✓ virustotal       abcd…wxyz
  ✓ urlscan          1234…5678

  2 active / 40 supported
```

Full key values are **never** printed — masked to `first4…last4` for safe
sharing in screenshots and bug reports.

### Using a custom config path

```bash
subnoryx -c /path/to/engagement-keys.yaml -d example.com
```

---

## OSINT Sources

### Keyless (always active)

| Source | Type |
|---|---|
| **crt.sh** | Certificate Transparency logs |
| **HackerTarget** | Passive DNS / host search |
| **AlienVault OTX** | Passive DNS |
| **Wayback Machine** | Archived URLs (hostname extraction) |
| **Anubis** | Passive DNS *(best-effort; endpoint is intermittent)* |

### Keyed (activate via `api_keys:` in config)

| Source | Config key | Auth style |
|---|---|---|
| VirusTotal | `virustotal` | `x-apikey` header |
| urlscan.io | `urlscan` | `API-Key` header |
| CertSpotter | `certspotter` | `Authorization: Bearer <key>` |
| Chaos (ProjectDiscovery) | `chaos` | `Authorization: <key>` |

Plus 36 more keys are pre-registered in the config template — the
`fetch_*` implementations for those sources can be added incrementally
without touching the CLI or config loader.

---

## Examples

### 1. Quick passive recon

```bash
subnoryx -d example.com
```

### 2. Full pipeline — discovery → resolution → probing

```bash
subnoryx -d example.com -r --probe -t 200
```

### 3. Multi-domain scope from a file

```bash
cat > scope.txt <<EOF
# Bug bounty scope
example.com
api.example.com
https://staging.example.org/path
*.wildcard.example.net
EOF

subnoryx -i scope.txt -r --probe -o live.txt --json results.json
```

All four lines normalise correctly — URLs are reduced to hostnames and
`*.` prefixes are stripped.

### 4. Pipe into httpx

```bash
subnoryx -d example.com -r -s | httpx -silent -title -tech-detect -sc
```

`-s` suppresses banner/spinner, emitting one subdomain per line — perfect
for downstream tooling.

### 5. Add a Safe-Harbor header to probing only

```bash
subnoryx -d example.com --probe \
  -H "X-Bug-Bounty: HackerOne-kalmux" \
  -H "X-Contact: kalmux@example.com"
```

### 6. Verbose + custom resolvers

```bash
subnoryx -d example.com -r --resolvers 1.1.1.1,9.9.9.9 -v
```

### 7. Inspect config before scanning

```bash
subnoryx --show-config
```

---

## Output Formats

### Plain text (`-o subs.txt`)

One subdomain per line, sorted, deduplicated:

```
api.example.com
mail.example.com
vpn.example.com
```

### JSON (`--json results.json`)

Full structured output — subdomains, resolved IPs, and HTTP probe details:

```json
{
  "version": "1.0.0",
  "license": "GPL-2.0",
  "targets": ["example.com"],
  "discovered_count": 247,
  "resolved_count": 182,
  "probed_count": 164,
  "subdomains": ["api.example.com", "mail.example.com", "..."],
  "resolved": {
    "api.example.com": ["93.184.216.34"],
    "mail.example.com": ["93.184.216.34"]
  },
  "probed": {
    "api.example.com": {
      "url": "https://api.example.com",
      "status": 200,
      "title": "API Gateway"
    },
    "vpn.example.com": {
      "url": "https://vpn.example.com",
      "status": 403,
      "title": ""
    }
  }
}
```

### Silent stdout (`-s`)

One subdomain per line — designed for `| httpx`, `| nuclei`, `| katana`, etc.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                      subnoryx.py                         │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  ┌───────────────┐  ┌───────────────┐  ┌──────────────┐  │
│  │  Discovery    │  │  Resolution   │  │   Probing    │  │
│  │  (parallel    │→ │  (async DNS)  │→ │  (HTTP/HTTPS)│  │
│  │   9 fetchers) │  │               │  │              │  │
│  └───────────────┘  └───────────────┘  └──────────────┘  │
│         │                   │                  │         │
│         ▼                   ▼                  ▼         │
│   crt.sh               aiodns            httpx client    │
│   HackerTarget         (or socket)       (verify=False)  │
│   AlienVault                                             │
│   Anubis                                                 │
│   Wayback              Semaphore         Semaphore       │
│   urlscan              batch=2000        batch=2000      │
│   VirusTotal                                             │
│   CertSpotter          ┌──────────────────────────┐      │
│   Chaos                │  Final Output Sinks      │      │
│                        │  - stdout (human/pipe)   │      │
│                        │  - -o  (text)            │      │
│                        │  --json (full detail)    │      │
│                        └──────────────────────────┘      │
└──────────────────────────────────────────────────────────┘
```

**Key design decisions:**

- **Bounded `batch_gather()`** — resolutions/probes run in chunks of 2000 to
  prevent memory spikes on 100k-name scopes.
- **Retries with jitter** — `http_get_with_retry()` retries 429/5xx and
  network errors with `1s + attempt + random(0, 0.5)` backoff.
- **`aiodns` 2.x / 3.x compatibility** — `build_resolver()` auto-detects
  the installed version and adapts the API call signature.
- **RFC-1035-safe subdomain validation** — label length (63) and FQDN length
  (253) enforced in `clean_subdomain()`.
- **TTY-aware spinner** — non-interactive runs emit a single `[…] message`
  line instead of animating escape codes into your logs.

---

## Troubleshooting

### `subnoryx: command not found`

Your shell hasn't reloaded the alias:

```bash
source ~/.bashrc     # or ~/.zshrc
# or open a new terminal
```

If you're calling `subnoryx` from a **script** or **cron**, aliases don't
expand — use the `/usr/local/bin/subnoryx` symlink (offered by the installer)
or invoke directly:

```bash
python3 /path/to/SUBNORYX/subnoryx.py -d example.com
```

### `error: argument -c/--config: expected one argument`

`-c` requires a path. To inspect the **default** config, use:

```bash
subnoryx --show-config
# or
cat ~/.config/subnoryx/config.yaml
```

### `custom resolver list will be ignored`

`--resolvers` needs `aiodns`:

```bash
pip install --user aiodns
```

Without `aiodns`, SUBNORYX falls back to `socket.getaddrinfo` which uses the
system resolver — slower, but still functional.

### Empty results for a domain

Some possibilities:

1. The domain has no public subdomains in CT logs or passive DNS.
2. Keyless sources rate-limited you — wait 60s or add API keys.
3. `crt.sh` is intermittently slow — try `-v` to see per-source timing.

### `InsecureRequestWarning` during probing

Suppressed automatically in the probing client (`warnings.catch_warnings()`).
The `verify=False` setting is **intentional** — bug bounty recon needs to
probe self-signed / expired certs.

### DNS resolution is slow

- Install `aiodns`: `pip install --user aiodns`
- Increase concurrency: `-t 500`
- Use faster resolvers: `--resolvers 1.1.1.1,1.0.0.1`

---

## Uninstall

```bash
# From the SUBNORYX directory
./install.sh --uninstall
source ~/.bashrc    # or ~/.zshrc
```

This removes:

- The `# >>> SUBNORYX alias >>>` block from your rc file
- The `/usr/local/bin/subnoryx` symlink (if present)

Your `~/.config/subnoryx/config.yaml` is **not** touched — delete it manually
if you want a clean slate:

```bash
rm -rf ~/.config/subnoryx
```

---

## Contributing

Contributions are welcome! To add a new OSINT source:

1. Add its name to `API_KEY_NAMES` in `subnoryx.py`.
2. Implement `async def fetch_yoursource(client, domain, api_key)` that
   returns a `set[str]` of subdomains.
3. Register it in `enumerate_single_domain()`'s `tasks` list.
4. Add the source to the table in this README.

Please open an issue first for significant changes, and follow the existing
code style (async, bounded concurrency, retries via `http_get_with_retry`).

---

## License

Distributed under the **GNU General Public License v2.0**.

See [`LICENSE`](./LICENSE) for the full text.

```
SUBNORYX is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; version 2 of the License.

SUBNORYX is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
```

---

## Author

**Kalmux** — [@kalmux1](https://github.com/kalmux1)

- Repository: <https://github.com/kalmux1/SUBNORYX>
- Issues: <https://github.com/kalmux1/SUBNORYX/issues>

---

<div align="center">

**⚡ Happy hunting. Stay in scope. ⚡**

```
   _____ __  ______  _   ______  ______  ___  __
  / ___// / / / __ )/ | / / __ \/ __ \ \/ / |/ /
  \__ \/ / / / __  /  |/ / / / / /_/ /\  /|   /
 ___/ / /_/ / /_/ / /|  / /_/ / _, _/ / //   |
/____/\____/_____/_/ |_/\____/_/ |_| /_//_/|_|
```

</div>
