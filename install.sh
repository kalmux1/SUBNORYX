#!/usr/bin/env bash
# =====================================================================
# SUBNORYX Installer
# - Marks subnoryx.py executable
# - Registers `subnoryx` alias in ~/.bashrc / ~/.zshrc
# - Optionally creates /usr/local/bin symlink
# - Sources shell rc file (or prints the command to run)
#
# Usage:
#   ./install.sh             # interactive install
#   ./install.sh --uninstall # remove alias block & symlink
#   ./install.sh --no-deps   # skip pip dependency prompt
# =====================================================================
set -euo pipefail

# ---- Colors --------------------------------------------------------
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
CYAN="\033[0;36m"
BOLD="\033[1m"
RESET="\033[0m"

info()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()    { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
err()   { echo -e "${RED}[x]${RESET} $*" >&2; }
title() { echo -e "\n${BOLD}${CYAN}==> $*${RESET}"; }

# ---- Arg parsing ---------------------------------------------------
DO_UNINSTALL=0
SKIP_DEPS=0
for arg in "$@"; do
    case "$arg" in
        --uninstall|-u) DO_UNINSTALL=1 ;;
        --no-deps)      SKIP_DEPS=1 ;;
        -h|--help)
            echo "Usage: $0 [--uninstall] [--no-deps]"
            exit 0
            ;;
        *) err "Unknown argument: $arg"; exit 2 ;;
    esac
done

# ---- Locate script directory --------------------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd)"
SUBNORYX_PY="${SCRIPT_DIR}/subnoryx.py"
MARKER_START="# >>> SUBNORYX alias >>>"
MARKER_END="# <<< SUBNORYX alias <<<"

# ---- Detect shell rc file -----------------------------------------
detect_rc_file() {
    local sh
    sh="$(basename "${SHELL:-bash}")"
    case "$sh" in
        zsh)  echo "$HOME/.zshrc" ;;
        bash)
            if [[ -f "$HOME/.bashrc" ]]; then
                echo "$HOME/.bashrc"
            else
                echo "$HOME/.bash_profile"
            fi
            ;;
        fish) echo "$HOME/.config/fish/config.fish" ;;
        *)    echo "$HOME/.profile" ;;
    esac
}

RC_FILE="$(detect_rc_file)"

# ---- Remove alias block (idempotent helper) -----------------------
remove_alias_block() {
    local rc="$1"
    [[ -f "$rc" ]] || return 0
    python3 - "$rc" "$MARKER_START" "$MARKER_END" <<'PYEOF'
import re, sys
path, start, end = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    text = open(path, encoding="utf-8").read()
except FileNotFoundError:
    sys.exit(0)
pattern = re.compile(
    re.escape(start) + r".*?" + re.escape(end) + r"\n?",
    re.DOTALL,
)
new_text = pattern.sub("", text)
if new_text != text:
    open(path, "w", encoding="utf-8").write(new_text)
PYEOF
}

# =====================================================================
# UNINSTALL PATH
# =====================================================================
if [[ "$DO_UNINSTALL" -eq 1 ]]; then
    title "Uninstalling SUBNORYX"
    if [[ -f "$RC_FILE" ]] && grep -qF "$MARKER_START" "$RC_FILE"; then
        remove_alias_block "$RC_FILE"
        ok "Removed alias block from $RC_FILE"
    else
        info "No alias block found in $RC_FILE"
    fi
    if [[ -L /usr/local/bin/subnoryx ]]; then
        sudo rm -f /usr/local/bin/subnoryx && \
            ok "Removed symlink /usr/local/bin/subnoryx" || \
            warn "Could not remove symlink (permission?)"
    fi
    ok "Uninstall complete. Restart your shell or run: source $RC_FILE"
    exit 0
fi

# =====================================================================
# INSTALL PATH
# =====================================================================
echo -e "${BOLD}${CYAN}"
cat <<'EOF'
   _____ __  ______  _   ______  ______  ___  __
  / ___// / / / __ )/ | / / __ \/ __ \ \/ / |/ /
  \__ \/ / / / __  /  |/ / / / / /_/ /\  /|   /
 ___/ / /_/ / /_/ / /|  / /_/ / _, _/ / //   |
/____/\____/_____/_/ |_/\____/_/ |_| /_//_/|_|
EOF
echo -e "${RESET}${CYAN}              Installer${RESET}"

# ---- Sanity: subnoryx.py present ----------------------------------
title "Locating subnoryx.py"
if [[ ! -f "$SUBNORYX_PY" ]]; then
    err "subnoryx.py not found next to installer: $SCRIPT_DIR"
    exit 1
fi
ok "Found: $SUBNORYX_PY"

# ---- Python version check -----------------------------------------
title "Checking Python"
if ! command -v python3 >/dev/null 2>&1; then
    err "python3 not found in PATH — install Python 3.9+ first"
    exit 1
fi
PY_VER="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PY_MAJOR="${PY_VER%%.*}"
PY_MINOR="${PY_VER##*.}"
if (( PY_MAJOR < 3 || (PY_MAJOR == 3 && PY_MINOR < 9) )); then
    err "SUBNORYX requires Python >= 3.9 (found $PY_VER)"
    exit 1
fi
ok "Python $PY_VER detected"

# ---- Make executable + verify shebang -----------------------------
title "Setting executable permission"
if ! head -n1 "$SUBNORYX_PY" | grep -q '^#!.*python'; then
    warn "subnoryx.py has no python shebang — alias will use 'python3' explicitly"
fi
chmod +x "$SUBNORYX_PY"
ok "chmod +x $SUBNORYX_PY"

# ---- Dependencies --------------------------------------------------
if [[ "$SKIP_DEPS" -eq 0 ]]; then
    title "Checking Python dependencies"
    MISSING=()
    python3 -c "import httpx"   >/dev/null 2>&1 || MISSING+=("httpx")
    python3 -c "import aiodns"  >/dev/null 2>&1 || MISSING+=("aiodns")
    python3 -c "import yaml"    >/dev/null 2>&1 || MISSING+=("pyyaml")

    if [[ ${#MISSING[@]} -eq 0 ]]; then
        ok "httpx, aiodns, pyyaml — all present"
    else
        warn "Missing: ${MISSING[*]}"
        read -rp "Install them now with pip (--user)? [y/N] " ans
        if [[ "$ans" =~ ^[Yy]$ ]]; then
            if python3 -m pip install --user "${MISSING[@]}"; then
                ok "Dependencies installed"
            else
                warn "pip install failed — install manually: pip install ${MISSING[*]}"
            fi
        else
            warn "Skipped — 'httpx' is mandatory for SUBNORYX to run"
        fi
    fi
else
    info "Skipping dependency check (--no-deps)"
fi

# ---- Add alias to rc file -----------------------------------------
title "Registering alias in $RC_FILE"

case "$(basename "${SHELL:-bash}")" in
    fish)
        err "Fish shell is not supported by this installer (aliases differ)."
        info "Add this manually to $RC_FILE:"
        echo "    alias subnoryx 'python3 \"$SUBNORYX_PY\"'"
        exit 1
        ;;
esac

# Ensure rc file exists
if [[ ! -f "$RC_FILE" ]]; then
    touch "$RC_FILE"
    ok "Created $RC_FILE"
fi

# Remove any existing block first (idempotency)
if grep -qF "$MARKER_START" "$RC_FILE"; then
    remove_alias_block "$RC_FILE"
    info "Removed previous SUBNORYX alias block"
fi

# Append the fresh block
{
    echo ""
    echo "$MARKER_START"
    echo "# SUBNORYX — Async Subdomain Recon Engine (managed by install.sh)"
    echo "alias subnoryx='python3 \"${SUBNORYX_PY}\"'"
    echo "$MARKER_END"
} >> "$RC_FILE"
ok "Alias 'subnoryx' written to $RC_FILE"

# ---- Optional: /usr/local/bin symlink -----------------------------
title "Optional system-wide symlink"
if [[ -w /usr/local/bin ]]; then
    read -rp "Create symlink /usr/local/bin/subnoryx? [y/N] " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        ln -sf "$SUBNORYX_PY" /usr/local/bin/subnoryx
        ok "Symlink created: /usr/local/bin/subnoryx"
    fi
else
    read -rp "Create symlink /usr/local/bin/subnoryx (needs sudo)? [y/N] " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        if sudo ln -sf "$SUBNORYX_PY" /usr/local/bin/subnoryx; then
            ok "Symlink created: /usr/local/bin/subnoryx"
        else
            warn "Symlink creation failed"
        fi
    fi
fi

# ---- Reload current shell if we were sourced ----------------------
# If the user ran `. ./install.sh` or `source install.sh`, we can
# actually reload the rc file into their current interactive session.
if [[ "${BASH_SOURCE[0]:-}" != "${0}" ]]; then
    # Sourced mode
    info "Reloading $RC_FILE into current shell"
    # shellcheck disable=SC1090
    source "$RC_FILE" || warn "Could not source $RC_FILE"
    ok "Alias is active in this shell"
else
    # Executed mode — cannot affect parent shell
    info "Note: alias applies to NEW shells. Activate it in this shell with:"
    echo ""
    echo -e "    ${GREEN}source ${RC_FILE}${RESET}"
    echo ""
fi

# ---- Final summary ------------------------------------------------
echo ""
ok "Installation complete!"
echo ""
echo -e "  ${BOLD}Alias:${RESET}  subnoryx  →  python3 \"${SUBNORYX_PY}\""
echo -e "  ${BOLD}Rc file:${RESET} ${RC_FILE}"
echo ""
echo -e "  ${BOLD}Quick start:${RESET}"
echo "    subnoryx --man"
echo "    subnoryx -d example.com -r --probe"
echo "    subnoryx -i scope.txt -r --probe -o subs.txt --json subs.json -v"
echo ""
echo -e "  ${BOLD}Uninstall:${RESET}"
echo "    ./install.sh --uninstall"
echo ""