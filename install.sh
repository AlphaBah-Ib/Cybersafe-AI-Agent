#!/usr/bin/env bash
#
# Cybersafe-AI Agent — installation script
#
# Usage:
#   sudo ./install.sh
#
# What it does:
#   - Creates a dedicated 'cybersafe' system user (no shell, no home login)
#   - Creates required directories under /opt, /etc, /var
#   - Installs the Python agent into /opt/cybersafe-agent (with its own venv)
#   - Installs and enables the systemd service (does NOT start it)
#
# Idempotent: re-running the script is safe.

set -euo pipefail

# --- Configuration --------------------------------------------------------

AGENT_USER="cybersafe"
AGENT_GROUP="cybersafe"
AGENT_HOME="/opt/cybersafe-agent"
CONFIG_DIR="/etc/cybersafe"
STATE_DIR="/var/lib/cybersafe"
SPOOL_DIR="/var/spool/cybersafe"
SERVICE_NAME="cybersafe-agent"
SERVICE_FILE_SRC="packaging/linux/systemd/${SERVICE_NAME}.service"
SERVICE_FILE_DST="/etc/systemd/system/${SERVICE_NAME}.service"
PYTHON_MIN_VERSION="3.10"

# Path where the agent will write its own log file.
# Must be inside ReadWritePaths declared in the systemd unit.
AGENT_LOG_FILE="${STATE_DIR}/agent.log"

# Colors for output
C_RESET="\033[0m"
C_INFO="\033[1;34m"
C_OK="\033[1;32m"
C_WARN="\033[1;33m"
C_ERR="\033[1;31m"

log_info()  { echo -e "${C_INFO}[INFO]${C_RESET}  $*"; }
log_ok()    { echo -e "${C_OK}[ OK ]${C_RESET}  $*"; }
log_warn()  { echo -e "${C_WARN}[WARN]${C_RESET}  $*"; }
log_err()   { echo -e "${C_ERR}[ERR ]${C_RESET}  $*" >&2; }

# --- Pre-flight checks ----------------------------------------------------

if [[ "${EUID}" -ne 0 ]]; then
    log_err "This script must be run as root (use sudo)."
    exit 1
fi

if [[ "$(uname -s)" != "Linux" ]]; then
    log_err "This installer only supports Linux."
    exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
    log_err "systemd is required (systemctl not found)."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

if [[ ! -f "${SERVICE_FILE_SRC}" ]]; then
    log_err "Missing ${SERVICE_FILE_SRC}. Run this script from the agent repo root."
    exit 1
fi

if [[ ! -d "cybersafe_agent" ]]; then
    log_err "Missing cybersafe_agent/ directory. Run this script from the agent repo root."
    exit 1
fi

if [[ ! -f "requirements.txt" ]]; then
    log_err "Missing requirements.txt. Run this script from the agent repo root."
    exit 1
fi

# Find a usable python3 (>= 3.10)
PYTHON_BIN=""
for candidate in python3.12 python3.11 python3.10 python3; do
    if command -v "${candidate}" >/dev/null 2>&1; then
        version=$("${candidate}" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        if [[ "$(printf '%s\n%s\n' "${PYTHON_MIN_VERSION}" "${version}" | sort -V | head -n1)" == "${PYTHON_MIN_VERSION}" ]]; then
            PYTHON_BIN="$(command -v "${candidate}")"
            break
        fi
    fi
done

if [[ -z "${PYTHON_BIN}" ]]; then
    log_err "Python ${PYTHON_MIN_VERSION}+ is required but was not found."
    log_err "Install with: apt-get install -y python3 python3-venv"
    exit 1
fi

log_info "Using Python: ${PYTHON_BIN} ($(${PYTHON_BIN} --version))"

if ! "${PYTHON_BIN}" -c "import venv" >/dev/null 2>&1; then
    log_err "The 'venv' module is missing. On Debian/Ubuntu: apt-get install -y python3-venv"
    exit 1
fi

# --- 1. Create system user and group --------------------------------------

if ! getent group "${AGENT_GROUP}" >/dev/null; then
    log_info "Creating group '${AGENT_GROUP}'..."
    groupadd --system "${AGENT_GROUP}"
    log_ok "Group '${AGENT_GROUP}' created."
else
    log_ok "Group '${AGENT_GROUP}' already exists."
fi

if ! id -u "${AGENT_USER}" >/dev/null 2>&1; then
    log_info "Creating system user '${AGENT_USER}'..."
    useradd --system \
            --gid "${AGENT_GROUP}" \
            --home-dir "${AGENT_HOME}" \
            --no-create-home \
            --shell /usr/sbin/nologin \
            --comment "Cybersafe-AI Agent" \
            "${AGENT_USER}"
    log_ok "User '${AGENT_USER}' created."
else
    log_ok "User '${AGENT_USER}' already exists."
fi

# Add cybersafe to adm and syslog groups (read /var/log/auth.log etc.)
for grp in adm syslog; do
    if getent group "${grp}" >/dev/null; then
        if id -nG "${AGENT_USER}" | tr ' ' '\n' | grep -qx "${grp}"; then
            log_ok "User '${AGENT_USER}' already in group '${grp}'."
        else
            log_info "Adding '${AGENT_USER}' to group '${grp}'..."
            usermod -aG "${grp}" "${AGENT_USER}"
            log_ok "Added '${AGENT_USER}' to group '${grp}'."
        fi
    else
        log_warn "Group '${grp}' does not exist on this system, skipping."
    fi
done

# --- 2. Create directories ------------------------------------------------

log_info "Creating directories..."
install -d -o "${AGENT_USER}" -g "${AGENT_GROUP}" -m 0755 "${AGENT_HOME}"
install -d -o root            -g "${AGENT_GROUP}" -m 0750 "${CONFIG_DIR}"
install -d -o "${AGENT_USER}" -g "${AGENT_GROUP}" -m 0750 "${STATE_DIR}"
install -d -o "${AGENT_USER}" -g "${AGENT_GROUP}" -m 0750 "${SPOOL_DIR}"
log_ok "Directories ready."

# --- 3. Install agent code ------------------------------------------------

log_info "Copying agent code to ${AGENT_HOME}..."
if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete \
        --exclude '.git' \
        --exclude '__pycache__' \
        --exclude '*.pyc' \
        --exclude 'venv' \
        --exclude '.venv' \
        --exclude '*.bak' \
        --exclude '*.backup' \
        cybersafe_agent/ "${AGENT_HOME}/cybersafe_agent/"
    cp requirements.txt "${AGENT_HOME}/requirements.txt"
else
    rm -rf "${AGENT_HOME}/cybersafe_agent"
    cp -r cybersafe_agent "${AGENT_HOME}/cybersafe_agent"
    cp requirements.txt "${AGENT_HOME}/requirements.txt"
fi

chown -R "${AGENT_USER}:${AGENT_GROUP}" "${AGENT_HOME}"
log_ok "Agent code installed."

# --- 4. Create / update the virtualenv ------------------------------------

if [[ ! -d "${AGENT_HOME}/venv" ]]; then
    log_info "Creating Python virtualenv..."
    "${PYTHON_BIN}" -m venv "${AGENT_HOME}/venv"
    log_ok "Virtualenv created."
else
    log_ok "Virtualenv already exists."
fi

log_info "Installing Python dependencies..."
"${AGENT_HOME}/venv/bin/pip" install --quiet --upgrade pip
"${AGENT_HOME}/venv/bin/pip" install --quiet -r "${AGENT_HOME}/requirements.txt"
chown -R "${AGENT_USER}:${AGENT_GROUP}" "${AGENT_HOME}/venv"
log_ok "Dependencies installed."

# --- 5. Configuration files -----------------------------------------------

# config.yaml
if [[ ! -f "${CONFIG_DIR}/config.yaml" ]]; then
    if [[ -f "config.example.yaml" ]]; then
        log_info "Installing default config to ${CONFIG_DIR}/config.yaml..."
        install -o root -g "${AGENT_GROUP}" -m 0640 \
            config.example.yaml "${CONFIG_DIR}/config.yaml"

        # Rewrite log_file to a path that is writable under our systemd hardening.
        # /var/log is read-only because of ProtectSystem=strict; we redirect to /var/lib/cybersafe.
        log_info "Adjusting log_file path to ${AGENT_LOG_FILE} (writable under systemd hardening)..."
        sed -i "s|^log_file:.*|log_file: ${AGENT_LOG_FILE}|" "${CONFIG_DIR}/config.yaml"

        log_ok "Default config installed (review token before starting the service)."
    else
        log_warn "config.example.yaml not found; skipping config install."
        log_warn "You will need to create ${CONFIG_DIR}/config.yaml manually."
    fi
else
    log_ok "Existing config preserved at ${CONFIG_DIR}/config.yaml"
    # Safety: warn if existing config still points to /var/log/ (would fail at runtime)
    if grep -qE "^log_file:\s*/var/log/" "${CONFIG_DIR}/config.yaml"; then
        log_warn "Existing config has log_file under /var/log/ — this will fail with systemd hardening."
        log_warn "Recommended: change it to ${AGENT_LOG_FILE}"
    fi
fi

# agent.env (optional environment overrides loaded by systemd)
if [[ ! -f "${CONFIG_DIR}/agent.env" ]]; then
    log_info "Creating ${CONFIG_DIR}/agent.env (optional overrides)..."
    cat > "${CONFIG_DIR}/agent.env" <<'EOF'
# Cybersafe-AI Agent — environment file
# Loaded by systemd before starting the agent.
# All values are OPTIONAL. The token and main settings live in config.yaml.

# Override the path to the YAML config file
# CYBERSAFE_CONFIG=/etc/cybersafe/config.yaml
EOF
    chown root:"${AGENT_GROUP}" "${CONFIG_DIR}/agent.env"
    chmod 0640 "${CONFIG_DIR}/agent.env"
    log_ok "Created ${CONFIG_DIR}/agent.env (mode 0640, root:${AGENT_GROUP})."
else
    log_ok "Existing ${CONFIG_DIR}/agent.env preserved."
fi

# --- 6. Install and enable the systemd service ----------------------------

log_info "Installing systemd unit to ${SERVICE_FILE_DST}..."
install -o root -g root -m 0644 "${SERVICE_FILE_SRC}" "${SERVICE_FILE_DST}"
log_ok "Service file installed."

log_info "Reloading systemd..."
systemctl daemon-reload

log_info "Enabling ${SERVICE_NAME} (start on boot)..."
systemctl enable "${SERVICE_NAME}.service" >/dev/null
log_ok "Service enabled."

# --- Summary --------------------------------------------------------------

echo
echo -e "${C_OK}=========================================================${C_RESET}"
echo -e "${C_OK} Cybersafe-AI Agent installed successfully.${C_RESET}"
echo -e "${C_OK}=========================================================${C_RESET}"
echo
echo "Next steps:"
echo
echo "  1. Set your agent token in:"
echo "       sudo nano ${CONFIG_DIR}/config.yaml"
echo "     (replace 'csa_REMPLACE_PAR_TON_TOKEN_ICI' with your real token)"
echo
echo "  2. Start the agent:"
echo "       sudo systemctl start ${SERVICE_NAME}"
echo
echo "  3. Check status and logs:"
echo "       systemctl status ${SERVICE_NAME}"
echo "       journalctl -u ${SERVICE_NAME} -f"
echo "       sudo tail -f ${AGENT_LOG_FILE}"
echo
echo "To uninstall later:  sudo ./uninstall.sh"
echo
