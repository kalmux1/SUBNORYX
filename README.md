<div align="center">
<pre>
   _____ __  ______  _   ______  ______  ___  __  
  / ___// / / / __ )/ | / / __ \/ __ \ \/ / |/ /  
  \__ \/ / / / __  /  |/ / / / / /_/ /\  /|   / 
 ___/ / /_/ / /_/ / /|  / /_/ / _, _/ / //   |
/____/\____/_____/_/ |_/\____/_/ |_| /_//_/|_|
</pre>

**SUBNORYX v1.2.1** — Fast Async Subdomain Enumerator & Recon Engine

[![Python](https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-GPL--3.0-green)](./LICENSE)
[![Version](https://img.shields.io/badge/version-1.2.1-cyan)]()
[![Async](https://img.shields.io/badge/asyncio-httpx%20%2B%20aiodns-magenta)]()

*~By Kalmux*
</div>

---

> ⚠️ **ETHICAL USE NOTICE**
> SUBNORYX is provided for **authorized security testing, bug bounty programs,
> and education only**. Only use it against systems you own or have explicit
> written permission to test. Unauthorized reconnaissance may violate laws such
> as the CFAA (US), CMA (UK), or equivalent legislation elsewhere. The author
> assumes no liability for misuse.

---

## Table of Contents

- [Overview](#overview)
- [What's New in v1.2.1](#whats-new-in-v121)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Two-Stage Workflow](#two-stage-workflow)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
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
and penetration testers. It queries high-speed public APIs, Certificate
Transparency logs, and passive DNS repositories concurrently, then optionally
resolves and probes the results.

Built on `asyncio` + `httpx`, it is designed to be:
- **Fast** — concurrent queries to every configured OSINT source.
- **Quiet** — zero headers injected by default.
- **Composable** — pipe-friendly output for `httpx`, `nuclei`, `katana`, etc.
- **Staged** — discovery and probing can be run as separate passes.

---

## What's New in v1.2.1

- 🛠️ **`--init-config` flag** — explicitly create the default config file  (`~/.config/subnoryx/config.yaml`) without running a scan. Idempotent.
- 📦 **Installer now initializes the config** — a fresh `./install.sh` run  creates the 40-key config template automatically. The installer delegates  to `subnoryx --init-config` so the template stays in one place.
- 💡 **Better empty-config hint** — `--show-config` on a missing config now  prints `Create the config file with: subnoryx --init-config` instead of  leaving you to guess.
- 🐛 **No behaviour change to `--show-config`** — it remains read-only, so  safe for scripts and CI.

### What's new in v1.2.0

- 🗂️ **Two-stage workflow** — split discovery and probing across  invocations. `-i subnoryx.txt --probe` auto-detects subdomain-list input.
- 🎯 **`--match-codes`** — filter probe results to specific HTTP status  codes (`--match-codes 200,301,403`). Applied to `-o` and `--json` output.
- 🔇 **Quiet by default** — the subdomain list is no longer printed to the  terminal; you get a concise summary instead. Use `--show-list` to opt in.
- 🧩 **`--probe-only`** — explicit subdomain-input mode. Skips discovery.
- 🌐 **Full source registry** — all 40 API-key slots now have fetch  implementations (plus 3 keyless-only sources). Keyed sources run only  when their key is configured.

---

## Features

- ⚡ **Asynchronous engine** — `asyncio` + `httpx`, no thread-lock overhead.
- 🕵️ **Zero default footprint** — no Safe-Harbor header unless you pass `-H`.
- 🌐 **Multi-domain scope** — single target (`-d`) or scope file (`-i`).
- 🔍 **Async DNS resolution** — `aiodns` with `socket.getaddrinfo` fallback.
- 🌐 **Active HTTP probing** — final URLs after redirects, status codes,  and HTML page titles.
- 🎯 **Status-code filtering** — keep only the codes you care about.
- 🔑 **40 keyed + 3 keyless sources** — conditional dispatch: keyed sources  run only when their key is present.
- 🔁 **Transient-failure retries** — 429/5xx and network errors retried with  jittered backoff.
- 🧾 **Multiple output sinks** — plain text (`-o`), JSON (`--json`), silent  stdout (`-s`), and formatted list (`--show-list`).
- ⚙️ **Config inspector + initializer** — `--show-config` masks secrets;  `--init-config` creates the template.
- 🎨 **Polished CLI** — TTY-aware spinners, `NO_COLOR` support,  comprehensive `--man` page.

---

## Requirements

| Dependency | Version | Notes |
|---|---|---|
| **Python** | ≥ 3.9 | `from __future__ import annotations` allows 3.9 support |
| **httpx** | ≥ 0.23 | **Required** |
| **aiodns** | ≥ 2.0 | Optional — faster async DNS; falls back to `socket` |
| **PyYAML** | ≥ 5.0 | Optional — proper YAML parsing; falls back to naive parser |

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
3. Offers to `pip install --user httpx aiodns pyyaml` if any are missing (detects PEP 668 externally-managed environments and suggests venv).
4. Creates `~/.config/subnoryx/config.yaml` with the full 40-key template (idempotent — never overwrites an existing config).
5. Appends an idempotent alias block to `~/.bashrc` or `~/.zshrc`.
6. Optionally creates `/usr/local/bin/subnoryx` symlink.
7. Reloads your rc file when run via `source ./install.sh`.

Installer flags:
```bash
./install.sh             # interactive install
./install.sh --no-deps   # skip pip dependency prompt
./install.sh --yes       # auto-confirm all prompts (CI-friendly)
./install.sh --uninstall # remove alias block + symlink
./install.sh -h          # installer help
```

### Manual

```bash
git clone https://github.com/kalmux1/SUBNORYX.git
cd SUBNORYX
chmod +x subnoryx.py
pip install --user httpx aiodns pyyaml

# Create config
python3 subnoryx.py --init-config

# Alias
echo "alias subnoryx='python3 $(pwd)/subnoryx.py'" >> ~/.bashrc
source ~/.bashrc

# Or symlink
sudo ln -sf "$(pwd)/subnoryx.py" /usr/local/bin/subnoryx
```

### Post-install verification
```bash
subnoryx --show-config
# Expected: Status      : exists
#           API Keys:    (none configured — keyless sources only: ...)
#                        Create the config file with: subnoryx --init-config   ← only if missing
```

## Configuration

SUBNORYX reads `~/.config/subnoryx/config.yaml`. To create it:

```bash
subnoryx --init-config
```

The installer does this for you automatically. The default template looks like:

```yaml
api_keys:
  certspotter: ""
  chaos: ""
  urlscan: ""
  virustotal: ""
  # ... 40 keys total; leave empty to disable

headers:
  User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ..."
```

Behaviour:
- Empty key → the corresponding keyed source is skipped at runtime.
- Populated key → the source is queried on every scan.
- Keyless sources (`crtsh`, `anubis`, `wayback`, plus `alienvault` and `hackertarget` which work with or without a key) always run.

### Composite keys
Some providers require two-part keys, colon-separated:

| Source | Format | Where to get it |
|---|---|---|
| Censys | `API_ID:API_SECRET` | https://search.censys.io/account/api |
| FOFA | `email:api_key` | https://fofa.info/personalData |

A single-value key for these sources is silently skipped with a vlog warning (visible under `-v`).

### Inspecting your config
```bash
subnoryx --show-config
```

```text
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

Masking rules:
- API keys masked to `first4…last4` (or `****` if ≤ 8 chars).
- Header values whose name matches `auth|token|key|secret|cookie|pass|credential|session` are masked.

### `--show-config` vs `--init-config`

| Flag | Reads | Creates | Exits |
|---|---|---|---|
| `--show-config` | ✅ | ❌ (read-only) | ✅ |
| `--init-config` | ✅ | ✅ (if missing) | ✅ |
| `--init-config --show-config` | ✅ | ✅ (if missing) | ✅ (prints) |
| `-d example.com` (real scan) | ✅ | ✅ (if missing) | — |

`--show-config` is deliberately read-only so it can be safely used in scripts and CI without side effects.

## Two-Stage Workflow

SUBNORYX supports splitting recon across two independent invocations.

### Stage 1 — Discovery only
```bash
subnoryx -d example.com -r -o subnoryx.txt
```
- Queries all configured OSINT sources.
- Resolves discovered hosts via async DNS (`-r`).
- Saves the live subdomains to `subnoryx.txt`.
- Prints only a summary (not the full list).

### Stage 2 — Probe only
```bash
subnoryx -i subnoryx.txt --probe --match-codes 200,301,403 -o live.txt
```
- Skips discovery entirely (auto-detected subdomain list input).
- Probes each host over HTTPS, then HTTP.
- Keeps only status codes 200, 301, 403.
- Saves the filtered list to `live.txt`.

### Input mode detection
When you run `-i FILE --probe`, SUBNORYX auto-detects the input mode:

| Input content | Detected as | Behaviour |
|---|---|---|
| `example.com`, `foo.org` (different apexes) | apex list | enumerates each |
| `api.example.com`, `mail.example.com` (shared suffix) | subdomain list | probes directly |
| `api.example.com` (single line) | apex list (conservative) | enumerate |
| Anything with `--probe-only` | subdomain list (forced) | probe directly |

## Quick Start

```bash
# Create config (usually done by installer)
subnoryx --init-config

# Inspect config (keys + sensitive headers masked)
subnoryx --show-config

# Full manual
subnoryx --man

# Minimal discovery (summary only)
subnoryx -d example.com

# Full one-shot pipeline (discovery + resolve + probe, summary only)
subnoryx -d example.com -r --probe

# Two-stage: save, then filter
subnoryx -d example.com -r -o subnoryx.txt
subnoryx -i subnoryx.txt --probe --match-codes 200,301,403 -o live.txt

# Show the list in-terminal
subnoryx -i subnoryx.txt --probe --show-list

# Pipe raw results (silent mode)
subnoryx -d example.com -r -s | httpx -silent -title -tech-detect
```

## CLI Reference

```text
subnoryx [-h] [-d DOMAIN] [-i INPUT] [-r] [--probe] [--probe-only]
         [--match-codes CODES] [-t THREADS] [--resolvers RESOLVERS]
         [-o OUTPUT] [--json FILE] [--show-list] [-c CONFIG]
         [--show-config] [--init-config] [-H KEY:VALUE] [-s] [-v] [-V] [--man]
```

### Target Selection
| Flag | Description |
|---|---|
| `-d, --domain DOMAIN` | Single target. Apex by default; subdomain with `--probe-only` |
| `-i, --input FILE` | Scope file (apex domains to enumerate, or subdomains with `--probe`) |

### Resolution, Probing & Filtering
| Flag | Description |
|---|---|
| `-r, --resolve` | Filter dead subdomains via async DNS |
| `--probe` | Probe hosts for HTTP/HTTPS status & titles |
| `--probe-only` | Skip discovery; treat `-d/-i` as subdomains to probe. Implies `--probe` |
| `--match-codes CODES` | Comma-separated HTTP codes to keep during probing (e.g. 200,301,403). Filters `-o` and `--json`. Without this flag, all responsive codes are kept |
| `-t, --threads N` | Concurrency limit for resolution/probing (default: 100, min: 1) |
| `--resolvers LIST` | Comma-separated DNS resolvers. Requires `aiodns` |

### Configuration & Output
| Flag | Description |
|---|---|
| `-o, --output FILE` | Save filtered subdomain list (plain text) |
| `--json FILE` | Save full structured results (subdomains + IPs + probe details) |
| `--show-list` | Print the full subdomain list to terminal (default: suppressed) |
| `-c, --config PATH` | Path to `config.yaml` (default: `~/.config/subnoryx/config.yaml`) |
| `--show-config` | Print resolved config with masked secrets and exit. Read-only |
| `--init-config` | Create the default config file if missing, then exit |
| `-H, --header KEY:VALUE` | Custom HTTP header for probing only. Repeatable |
| `-s, --silent` | Silent mode — raw subdomains on stdout for piping |
| `-v, --verbose` | Verbose per-source logs on stderr |
| `-V, --version` | Print version and exit |
| `--man` | Print full built-in manual |

### Environment
| Variable | Effect |
|---|---|
| `NO_COLOR` | Any non-empty value disables ANSI colour output |

## OSINT Sources
SUBNORYX registers 43 fetch implementations — 40 keyed providers plus 3 keyless-only sources. Keyless sources always run. Keyed sources run only when their key is configured.

### Keyless (5) — always active
| Source | Type |
|---|---|
| crt.sh | Certificate Transparency logs |
| HackerTarget | Passive DNS / host search |
| AlienVault OTX | Passive DNS (accepts a key for higher rate limit) |
| Wayback Machine | Archived URLs |
| Anubis | Passive DNS (best-effort) |

### Keyed (38) — active only when key is set
Alphabetical list of providers with implementations:

```text
bevigil      bufferover   builtwith    c99          censys
certspotter  chaos        chinaz       digitalyama  dnsdb
dnsdumpster  dnsrepo      domainsproject  driftnet  fofa
fullhunt     github       intelx       leakix       merklemap
netlas       onyphe       profundis    pugrecon     quake
reconeeer    redhuntlabs  robtex       rsecloud     securitytrails
shodan       submd        threatbook   urlscan      virustotal
whoisxmlapi  windvane     zoomeyeapi
```

⚠️ Reliability note. All 43 fetchers are structurally complete and wired into the dispatch registry. Provider APIs change frequently; some endpoints may be outdated, require paid tiers, or use response shapes that differ from the implementation. A broken source never crashes the scan — every fetcher is wrapped in `try/except` and returns an empty set on failure. Run with `-v` to see which sources succeed for your environment.

### Finding out which sources work
```bash
subnoryx -d example.com -v 2>&1 | grep -E "failed|Skipping"
```
Sources that do not appear in the failure log are working.

## Examples

**1. Discovery only — save results**
```bash
subnoryx -d example.com -r -o subnoryx.txt
```
Output is a summary; `subnoryx.txt` contains the live subdomains.

**2. Two-stage recon — filter for interesting codes**
```bash
# Stage 1
subnoryx -d example.com -r -o subnoryx.txt

# Stage 2 — keep only 200/301/403
subnoryx -i subnoryx.txt --probe --match-codes 200,301,403 -o live.txt
```

**3. Force subdomain-input mode**
```bash
subnoryx -d api.example.com --probe-only --match-codes 200
subnoryx -i scope.txt --probe-only --match-codes 200
```

**4. Multi-domain discovery**
```bash
cat > scope.txt <<EOF
# Bug bounty scope
example.com
api.example.com
https://staging.example.org/path
*.wildcard.example.net
EOF

subnoryx -i scope.txt -r -o results.txt
```

**5. Pipe into httpx**
```bash
subnoryx -d example.com -r -s | httpx -silent -title -tech-detect -sc
```

**6. Show the list in-terminal**
```bash
subnoryx -d example.com -r --probe --show-list
```

**7. Safe-Harbor headers on probing only**
```bash
subnoryx -d example.com --probe \
  -H "X-Bug-Bounty: HackerOne-kalmux" \
  -H "X-Contact: kalmux@example.com"
```

**8. Filter + JSON export**
```bash
subnoryx -i subnoryx.txt --probe --match-codes 200,403 --json results.json
```

## Output Formats

### Plain text (`-o subs.txt`)
One subdomain per line, sorted, deduplicated. When combined with `--probe`, only responsive hosts are written (and only `--match-codes` matches if set).
```text
api.example.com
mail.example.com
vpn.example.com
```

### JSON (`--json results.json`)
Structured output including discovery, resolution, probe, and filter state:
```json
{
  "version": "1.2.1",
  "license": "GPL-3.0",
  "input_mode": "subdomains",
  "targets": ["api.example.com", "mail.example.com"],
  "match_codes": [200, 301, 403],
  "discovered_count": 2,
  "resolved_count": 2,
  "responsive_count": 2,
  "final_count": 1,
  "subdomains": ["mail.example.com"],
  "discovered": ["api.example.com", "mail.example.com"],
  "resolved": {
    "api.example.com": ["93.184.216.34"],
    "mail.example.com": ["93.184.216.34"]
  },
  "probed": {
    "mail.example.com": {
      "url": "https://mail.example.com/",
      "status": 200,
      "title": "Webmail Login"
    }
  }
}
```

| Field | Meaning |
|---|---|
| `input_mode` | `"apex"` (enumerate) or `"subdomains"` (direct probe) |
| `match_codes` | `null` if no filter applied, else the code list |
| `discovered` | Everything discovered, unfiltered |
| `probed` | Responsive hosts after `--match-codes` filter |
| `subdomains` | Final filtered list (matches `-o` output) |

### Silent stdout (`-s`)
One subdomain per line on stdout, no banner/spinner/logs.

### Terminal formatted list (`--show-list`)
Adds a colourised block after the summary:
```text
─── Subdomain List (3) ───
  api.example.com [93.184.216.34] -> https://api.example.com [200] [API Gateway]
  mail.example.com [93.184.216.34] -> https://mail.example.com [200] [Webmail Login]
  vpn.example.com [93.184.216.34] -> https://vpn.example.com [403]
```

## Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│                        subnoryx.py                           │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌───────────────┐  ┌───────────────┐  ┌──────────────┐      │
│  │  Discovery    │  │  Resolution   │  │   Probing    │      │
│  │  (parallel    │→ │  (async DNS)  │→ │  (HTTP/HTTPS)│      │
│  │   N fetchers) │  │               │  │  + filter    │      │
│  └───────────────┘  └───────────────┘  └──────────────┘      │
│        │                    │                  │             │
│        ▼                    ▼                  ▼             │
│  40 keyed + 3           aiodns              httpx            │
│  keyless sources        (or socket)         (verify=False)   │
│                                                              │
│  Conditional dispatch:  Semaphore           Semaphore        │
│  keyed sources skip     batch=2000          batch=2000       │
│  when key not set                                            │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐    │
│  │ Output sinks                                         │    │
│  │  - summary (default)                                 │    │
│  │  - --show-list  (formatted)                          │    │
│  │  - -s           (raw pipe)                           │    │
│  │  - -o           (plain text)                         │    │
│  │  - --json       (full structured)                    │    │
│  └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

Key design decisions:
- Conditional source dispatch — `get_active_sources()` filters `SOURCE_DISPATCH` by key presence. Sources without keys are logged and skipped.
- Input-mode auto-detection — `detect_input_mode()` classifies files by shared suffix so the two-stage workflow "just works".
- Bounded `batch_gather()` — resolution/probing runs in chunks of 2000.
- Retries with jitter — `http_get_with_retry()` handles 429/5xx and network errors.
- aiodns 2.x / 3.x compatibility — `build_resolver()` auto-detects the API signature.
- RFC-1035-safe validation — label length (63) and FQDN length (253) enforced in `clean_subdomain()`.
- TTY-aware spinner — non-interactive runs emit one `[…]` message line.
- `NO_COLOR` compliance — all ANSI output disabled when the env var is set.
- `--show-config` is read-only; `--init-config` is the only explicit creator. The installer and any real scan also create the config on first run.

## Troubleshooting

**`subnoryx: command not found`**
```bash
source ~/.bashrc     # or ~/.zshrc
# or open a new terminal
```
For scripts/cron, use the `/usr/local/bin/subnoryx` symlink or invoke directly: `python3 /path/to/subnoryx.py`.

**`--show-config` didn't create my config file**
By design — `--show-config` is read-only so it can be safely used in scripts and CI without side effects. To create the config file explicitly:
```bash
subnoryx --init-config
```
The installer (`./install.sh`) runs this automatically, and any real scan (`subnoryx -d example.com`) also creates the template on first run. The file lives at `~/.config/subnoryx/config.yaml`.

**`--init-config` says "Failed to create config"**
Usually means `~/.config/subnoryx/` is not writable, or the parent path is broken. Check permissions:
```bash
ls -ld ~/.config ~/.config/subnoryx 2>/dev/null
mkdir -p ~/.config/subnoryx
subnoryx --init-config
```

**Discovery returned 0 subdomains**
1. Run with `-v` to see per-source failures.
2. Confirm network access to crt.sh, hackertarget.com, etc.
3. Try a well-known domain (example.com) as a baseline.

**`--match-codes` ignored without `--probe`**
`--match-codes` only applies to probe results. Add `--probe` (or `--probe-only`):
```bash
subnoryx -i subnoryx.txt --probe --match-codes 200
```

**Auto-detection picked the wrong mode**
Force either mode:
```bash
# Force subdomain-input mode
subnoryx -i scope.txt --probe-only --match-codes 200

# Force apex-enumeration mode
subnoryx -d example.com -r
```

**`--probe` re-runs DNS resolution in apex mode**
Intentional — probing unresolvable hosts wastes time. In two-stage mode with `--probe-only`, DNS is not re-run unless you explicitly pass `-r`.

**`error: --threads must be >= 1`**
Threads must be a positive integer. `asyncio.Semaphore` cannot be initialised with 0 (deadlock) or a negative value (exception).

**`--resolvers` requires aiodns**
```bash
pip install --user aiodns
```
Without `aiodns`, SUBNORYX falls back to `socket.getaddrinfo` — slower, but functional.

**`pip install` fails with externally-managed-environment**
PEP 668 on Debian/Ubuntu 23.04+, Fedora 38+, etc. Create a venv:
```bash
python3 -m venv ~/.venvs/subnoryx
source ~/.venvs/subnoryx/bin/activate
pip install httpx aiodns pyyaml
```

**Composite-key sources appear "active" but return nothing**
`censys` needs `API_ID:API_SECRET` and `fofa` needs `email:api_key`. Single-value keys are silently rejected. Check with `-v`.

**DNS resolution is slow**
- Install `aiodns`: `pip install --user aiodns`
- Increase concurrency: `-t 500`
- Use faster resolvers: `--resolvers 1.1.1.1,1.0.0.1`

## Uninstall

```bash
./install.sh --uninstall
source ~/.bashrc    # or ~/.zshrc
```
Removes:
- The `# >>> SUBNORYX alias >>>` block from your rc file
- The `/usr/local/bin/subnoryx` symlink (if present)

Your `~/.config/subnoryx/config.yaml` is not touched. To remove it:
```bash
rm -rf ~/.config/subnoryx
```

## Contributing

Contributions are welcome! To add a new OSINT source:
1. Add its name to `API_KEY_NAMES` in `subnoryx.py`.
2. If it's keyless, add it to `KEYLESS_SOURCES`; otherwise set `requires_key=True` in the dispatch entry.
3. Implement `async def fetch_yoursource(client, domain, key)` that returns a `set[str]` of subdomains.
4. Register it in `SOURCE_DISPATCH`.
5. Add the source to the tables in this README.

Please follow the existing code style: async, bounded concurrency, retries via `http_get_with_retry`, and defensive exception handling.

## License

Distributed under the GNU General Public License v3.0. See [LICENSE](./LICENSE) for the full text.

```text
SUBNORYX is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

SUBNORYX is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
```

## Author

**Kalmux** — @kalmux1
- Repository: https://github.com/kalmux1/SUBNORYX
- Issues: https://github.com/kalmux1/SUBNORYX/issues

<div align="center">
⚡ Happy hunting. Stay in scope. ⚡
</div>
