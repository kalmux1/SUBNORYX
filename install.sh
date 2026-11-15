#!/usr/bin/env bash
# =====================================================================
# SUBNORYX Installer (v1.2.0)
# - Marks subnoryx.py executable
# - Registers `subnoryx` alias in ~/.bashrc / ~/.zshrc
# - Optionally creates /usr/local/bin symlink
# - Sources shell rc file (or prints the command to run)
#
# Usage:
#   ./install.sh             # interactive install
#   ./install.sh --uninstall # remove alias block & symlink
#   ./install.sh --no-deps   # skip pip dependency prompt
#   ./install.sh --yes       # auto-confirm all prompts (CI-friendly)
# =====================================================================
set -euo pipefail

# ---- Colors --------------------------------------------------------
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
CYAN="\033[0;36m"
BOLD="\033[1m"
RESET="\033[0m"

# Honor NO_COLOR
if [[ -n "${NO_COLOR:-}" ]]; then
    GREEN=""; YELLOW=""; RED=""; CYAN=""; BOLD=""; RESET=""
fi

info()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()    { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
err()   { echo -e "${RED}[x]${RESET} $*" >&2; }
title() { echo -e "\n${BOLD}${CYAN}==> $*${RESET}"; }

# Safe prompt: returns default when stdin is not a TTY (CI/pipe-friendly).
ask() {
    local prompt="$1" default="${2:-n}" ans
    if [[ "${ASSUME_YES:-0}" -eq 1 ]]; then
        ans="y"
    elif [[ ! -t 0 ]]; then
        ans="$default"
    else
        read -rp "$prompt" ans || ans="$default"
    fi
    printf '%s' "$ans"
}

# ---- Arg parsing ---------------------------------------------------
DO_UNINSTALL=0
SKIP_DEPS=0
ASSUME_YES=0
for arg in "$@"; do
    case "$arg" in
        --uninstall|-u) DO_UNINSTALL=1 ;;
        --no-deps)      SKIP_DEPS=1 ;;
        --yes|-y)       ASSUME_YES=1 ;;
        -h|--help)
            echo "Usage: $0 [--uninstall] [--no-deps] [--yes]"
            exit 0
            ;;
        *) err "Unknown argument: $arg"; exit 2 ;;
    esac
done
export ASSUME_YES

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

# ---- Pre-flight: Python 3 must exist (used by install AND uninstall) ----
PYTHON_BIN=""
if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    if python -c 'import sys; sys.exit(0 if sys.version_info[0]>=3 else 1)' 2>/dev/null; then
        PYTHON_BIN="python"
    fi
fi

if [[ -z "$PYTHON_BIN" ]]; then
    if [[ "$DO_UNINSTALL" -eq 1 ]]; then
        err "python3 not found — cannot run uninstall helper."
        info "Remove the alias block manually from $RC_FILE and delete /usr/local/bin/subnoryx."
        exit 1
    fi
    err "python3 not found in PATH — install Python 3.9+ first"
    exit 1
fi

PY_VER="$($PYTHON_BIN -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PY_MAJOR="${PY_VER%%.*}"
PY_MINOR="${PY_VER##*.}"
if (( PY_MAJOR < 3 || (PY_MAJOR == 3 && PY_MINOR < 9) )); then
    if [[ "$DO_UNINSTALL" -eq 1 ]]; then
        warn "Python $PY_VER found, but >= 3.9 recommended. Uninstall will attempt anyway."
    else
        err "SUBNORYX requires Python >= 3.9 (found $PY_VER)"
        exit 1
    fi
fi

# ---- Remove alias block (idempotent helper) -----------------------
remove_alias_block() {
    local rc="$1"
    [[ -f "$rc" ]] || return 0
    "$PYTHON_BIN" - "$rc" "$MARKER_START" "$MARKER_END" <<'PYEOF'
import re, sys
path, start, end = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(path, encoding="utf-8") as f:
        text = f.read()
except FileNotFoundError:
    sys.exit(0)
pattern = re.compile(
    re.escape(start) + r".*?" + re.escape(end) + r"\n?",
    re.DOTALL,
)
new_text = pattern.sub("", text)
if new_text != text:
    with open(path, "w", encoding="utf-8") as f:
        f.write(new_text)
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
        if [[ -w /usr/local/bin ]]; then
            rm -f /usr/local/bin/subnoryx && \
                ok "Removed symlink /usr/local/bin/subnoryx" || \
                warn "Could not remove symlink"
        else
            sudo rm -f /usr/local/bin/subnoryx && \
                ok "Removed symlink /usr/local/bin/subnoryx" || \
                warn "Could not remove symlink (permission?)"
        fi
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
echo -e "${RESET}${CYAN}           Installer  (v1.2.0)${RESET}"

# ---- Sanity: subnoryx.py present ----------------------------------
title "Locating subnoryx.py"
if [[ ! -f "$SUBNORYX_PY" ]]; then
    err "subnoryx.py not found next to installer: $SCRIPT_DIR"
    exit 1
fi
ok "Found: $SUBNORYX_PY"
ok "Python $PY_VER detected ($PYTHON_BIN)"

# ---- Make executable + verify shebang -----------------------------
title "Setting executable permission"
if ! head -n1 "$SUBNORYX_PY" | grep -q '^#!.*python'; then
    warn "subnoryx.py has no python shebang — alias will use '$PYTHON_BIN' explicitly"
fi
chmod +x "$SUBNORYX_PY"
ok "chmod +x $SUBNORYX_PY"

# ---- Dependencies --------------------------------------------------
if [[ "$SKIP_DEPS" -eq 0 ]]; then
    title "Checking Python dependencies"
    MISSING=()
    "$PYTHON_BIN" -c "import httpx"  >/dev/null 2>&1 || MISSING+=("httpx")
    "$PYTHON_BIN" -c "import aiodns" >/dev/null 2>&1 || MISSING+=("aiodns")
    "$PYTHON_BIN" -c "import yaml"   >/dev/null 2>&1 || MISSING+=("pyyaml")

    if [[ ${#MISSING[@]} -eq 0 ]]; then
        ok "httpx, aiodns, pyyaml — all present"
    else
        warn "Missing: ${MISSING[*]}"
        ans="$(ask "Install them now with pip (--user)? [y/N] " n)"
        if [[ "$ans" =~ ^[Yy]$ ]]; then
            PIP_LOG="$(mktemp -t subnoryx-pip.XXXXXX)"
            if "$PYTHON_BIN" -m pip install --user "${MISSING[@]}" 2>&1 | tee "$PIP_LOG"; then
                ok "Dependencies installed"
            else
                warn "pip install failed — install manually: pip install --user ${MISSING[*]}"
                if grep -q "externally-managed-environment" "$PIP_LOG" 2>/dev/null; then
                    info "This system enforces PEP 668 (externally-managed env)."
                    info "Recommended:  $PYTHON_BIN -m venv ~/.venvs/subnoryx"
                    info "              source ~/.venvs/subnoryx/bin/activate"
                    info "              pip install ${MISSING[*]}"
                fi
            fi
            rm -f "$PIP_LOG"
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
        echo "    alias subnoryx '$PYTHON_BIN \"$SUBNORYX_PY\"'"
        exit 1
        ;;
esac

# Ensure rc file exists
if [[ ! -f "$RC_FILE" ]]; then
    mkdir -p "$(dirname "$RC_FILE")"
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
    echo "alias subnoryx='$PYTHON_BIN \"${SUBNORYX_PY}\"'"
    echo "$MARKER_END"
} >> "$RC_FILE"
ok "Alias 'subnoryx' written to $RC_FILE"

# ---- Optional: /usr/local/bin symlink -----------------------------
title "Optional system-wide symlink"
NEED_SUDO=0
[[ -w /usr/local/bin ]] || NEED_SUDO=1
if [[ "$NEED_SUDO" -eq 0 ]]; then
    ans="$(ask "Create symlink /usr/local/bin/subnoryx? [y/N] " n)"
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        ln -sf "$SUBNORYX_PY" /usr/local/bin/subnoryx && \
            ok "Symlink created: /usr/local/bin/subnoryx" || \
            warn "Symlink creation failed"
    fi
else
    ans="$(ask "Create symlink /usr/local/bin/subnoryx (needs sudo)? [y/N] " n)"
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        if sudo ln -sf "$SUBNORYX_PY" /usr/local/bin/subnoryx; then
            ok "Symlink created: /usr/local/bin/subnoryx"
        else
            warn "Symlink creation failed"
        fi
    fi
fi

# ---- Reload current shell if we were sourced ----------------------
if [[ "${BASH_SOURCE[0]:-}" != "${0}" ]]; then
    info "Reloading $RC_FILE into current shell"
    # shellcheck disable=SC1090
    source "$RC_FILE" 2>/dev/null || warn "Could not source $RC_FILE"
    ok "Alias is active in this shell"
else
    info "Note: alias applies to NEW shells. Activate it in this shell with:"
    echo ""
    echo -e "    ${GREEN}source ${RC_FILE}${RESET}"
    echo ""
fi

# ---- Final summary ------------------------------------------------
echo ""
ok "Installation complete!"
echo ""
echo -e "  ${BOLD}Alias:${RESET}  subnoryx  →  $PYTHON_BIN \"${SUBNORYX_PY}\""
echo -e "  ${BOLD}Rc file:${RESET} ${RC_FILE}"
echo ""
echo -e "  ${BOLD}Quick start:${RESET}"
echo "    subnoryx --man"
echo "    subnoryx --show-config"
echo ""
echo -e "  ${BOLD}Two-stage workflow:${RESET}"
echo "    # Stage 1 — discover and save"
echo "    subnoryx -d example.com -r -o subnoryx.txt"
echo ""
echo "    # Stage 2 — probe saved list, keep only 200/301/403"
echo "    subnoryx -i subnoryx.txt --probe --match-codes 200,301,403 -o live.txt"
echo ""
echo -e "  ${BOLD}Uninstall:${RESET}"
echo "    ./install.sh --uninstall"
echo ""