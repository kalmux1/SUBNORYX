# SUBNORYX 🚀

> High-performance asynchronous passive subdomain enumeration and recon engine built for bug bounty hunters and penetration testers.

[![License: GPL-3.0](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://github.com/kalmux1/subnoryx/blob/main/LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%--spec-green.svg)](https://www.python.org/)

---

## ⚡ Features

- **Asynchronous Engine:** Built on `asyncio` and `httpx` for maximum concurrency without multiprocessing thread-lock crashes.
- **Zero Default Footprint:** Safe-Harbor/Bug-Bounty headers are disabled (`None`) by default and only injected when explicitly requested (`-H`).
- **Multi-Domain Scope Support:** Pass a single domain (`-d`) or an entire scope file (`-i scope.txt`).
- **Async DNS Resolution:** Instantly filters out dead `NXDOMAIN` records via `aiodns` or native socket lookup (`-r`).
- **Active HTTP Probing:** Probes live subdomains for status codes and HTML page titles (`--probe`).
- **40+ API Integration Ready:** Native configuration mapping for Shodan, Censys, VirusTotal, SecurityTrails, FOFA, and 35+ more OSINT sources.
- **Terminal Animations:** Sleek interactive spinners and status updates.
- **Built-in Manual:** Access the full man page right from your terminal (`subnoryx --man`).

---

## 📦 Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/kalmux1/subnoryx.git](https://github.com/kalmux1/subnoryx.git)
   cd subnoryx