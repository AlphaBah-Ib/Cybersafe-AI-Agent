#!/usr/bin/env bash
#
# Cybersafe-AI Agent — uninstall script
#
# Usage:
#   sudo ./uninstall.sh           # Interactive: asks before deleting data
#   sudo ./uninstall.sh --purge   # Non-interactive: deletes everything
#   sudo ./uninstall.sh --help
#
# What it always does (no prompt):
#   - Stops and disables the systemd service
#   - Removes the unit file from /etc/systemd/system/
#
# What it asks about (or removes if --purge):
#   - /opt/cybersafe-agent (code + venv)
#   - /etc/cybersafe       (config + agent token)
#   - /var/lib/cybersafe   (state, tail positions, log file)
#   - /var/spool/cybersafe (queued events)
#   - 'cybersafe' system user and group

set -euo pipefail

# --- Configuration --------------------------------------------------------

AGENT_USER="cybersafe"
AGENT_GROUP="cybersafe"
AGENT_HOME="/opt/cybersafe-agent"
CONFIG_DIR="/etc/cybersafe"
STATE_DIR="/var/lib/cybersafe"
SPOOL_DIR="/var/spool/cybersafe"
SERVICE_NAME="cybersafe-agent"
SERVICE_FILE_DST="/etc/systemd/system/${SERVICE_NAME}.service"

PURGE=false

C_RESET="\033[0m"
C_INFO="\033[1;34m"
C_OK="\033[1;32m"
C_WARN="\033[1;33m"
C_ERR="\033[1;31m"

log_info()  { echo -e "${C_INFO}[INFO]${C_RESET}  $*"; }
log_ok()    { echo -e "${C_OK}[ OK ]${C_RESET}  $*"; }
log_warn()  { echo -e "${C_WARN}[WARN]${C_RESET}  $*"; }
log_err()   { echo -e "${C_ERR}[ERR ]${C_RESET}  $*" >&2; }

# --- Args -----------------------------------------------------------------

show_help() {
    cat <<EOF
Usage: sudo $0 [OPTIONS]

Options:
  --purge     Remove everything without prompting (code, config, data, user).
  -h, --help  Show this help.

Without --purge, the script asks before deleting code/config/data and the user.
The systemd service is always stopped and disabled.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --purge) PURGE=true; shift ;;
        -h|--help) show_help; exit 0 ;;
        *) log_err "Unknown argument: $1"; show_help; exit 1 ;;
    esac
done

# --- Pre-flight -----------------------------------------------------------

if [[ "${EUID}" -ne 0 ]]; then
    log_err "This script must be run as root (use sudo)."
    exit 1
fi

# --- Helpers --------------------------------------------------------------

# confirm <prompt> -> returns 0 if yes, 1 otherwise.
# In --purge mode, always yes.
confirm() {
    local prompt="$1"
    if [[ "${PURGE}" == "true" ]]; then
        return 0
    fi
    local reply
    read -r -p "${prompt} [y/N] " reply
    [[ "${reply}" =~ ^[Yy]([Ee][Ss])?$ ]]
}

# --- 1. Stop and disable the service --------------------------------------

if systemctl list-unit-files | grep -q "^${SERVICE_NAME}.service"; then
    if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
        log_info "Stopping ${SERVICE_NAME}..."
        systemctl stop "${SERVICE_NAME}.service" || true
        log_ok "Service stopped."
    else
        log_ok "Service was not running."
    fi

    if systemctl is-enabled --quiet "${SERVICE_NAME}.service" 2>/dev/null; then
        log_info "Disabling ${SERVICE_NAME}..."
        systemctl disable "${SERVICE_NAME}.service" >/dev/null 2>&1 || true
        log_ok "Service disabled."
    else
        log_ok "Service was not enabled."
    fi
else
    log_ok "Service ${SERVICE_NAME} is not installed."
fi

# --- 2. Remove the unit file ----------------------------------------------

if [[ -f "${SERVICE_FILE_DST}" ]]; then
    log_info "Removing ${SERVICE_FILE_DST}..."
    rm -f "${SERVICE_FILE_DST}"
    systemctl daemon-reload
    systemctl reset-failed "${SERVICE_NAME}.service" 2>/dev/null || true
    log_ok "Unit file removed."
else
    log_ok "Unit file already absent."
fi

# --- 3. Optional removal: code (/opt) -------------------------------------

if [[ -d "${AGENT_HOME}" ]]; then
    if confirm "Remove agent code and venv at ${AGENT_HOME} ?"; then
        rm -rf "${AGENT_HOME}"
        log_ok "Removed ${AGENT_HOME}."
    else
        log_warn "Kept ${AGENT_HOME}."
    fi
else
    log_ok "${AGENT_HOME} already absent."
fi

# --- 4. Optional removal: config (/etc) -----------------------------------

if [[ -d "${CONFIG_DIR}" ]]; then
    if confirm "Remove configuration directory ${CONFIG_DIR} (contains your agent token) ?"; then
        rm -rf "${CONFIG_DIR}"
        log_ok "Removed ${CONFIG_DIR}."
    else
        log_warn "Kept ${CONFIG_DIR}."
    fi
else
    log_ok "${CONFIG_DIR} already absent."
fi

# --- 5. Optional removal: state / spool -----------------------------------

if [[ -d "${STATE_DIR}" ]]; then
    if confirm "Remove state directory ${STATE_DIR} (tail positions, agent log) ?"; then
        rm -rf "${STATE_DIR}"
        log_ok "Removed ${STATE_DIR}."
    else
        log_warn "Kept ${STATE_DIR}."
    fi
else
    log_ok "${STATE_DIR} already absent."
fi

if [[ -d "${SPOOL_DIR}" ]]; then
    if confirm "Remove spool directory ${SPOOL_DIR} (queued events) ?"; then
        rm -rf "${SPOOL_DIR}"
        log_ok "Removed ${SPOOL_DIR}."
    else
        log_warn "Kept ${SPOOL_DIR}."
    fi
else
    log_ok "${SPOOL_DIR} already absent."
fi

# --- 6. Optional removal: user / group ------------------------------------

if id -u "${AGENT_USER}" >/dev/null 2>&1; then
    if confirm "Remove system user '${AGENT_USER}' ?"; then
        userdel "${AGENT_USER}" 2>/dev/null || true
        log_ok "User '${AGENT_USER}' removed."
    else
        log_warn "Kept user '${AGENT_USER}'."
    fi
else
    log_ok "User '${AGENT_USER}' already absent."
fi

# Group is auto-removed by userdel on most distros if it has no other members.
# Best-effort cleanup if it still exists and is empty.
if getent group "${AGENT_GROUP}" >/dev/null; then
    if [[ -z "$(getent group "${AGENT_GROUP}" | awk -F: '{print $4}')" ]]; then
        if confirm "Remove empty group '${AGENT_GROUP}' ?"; then
            groupdel "${AGENT_GROUP}" 2>/dev/null || true
            log_ok "Group '${AGENT_GROUP}' removed."
        else
            log_warn "Kept group '${AGENT_GROUP}'."
        fi
    else
        log_warn "Group '${AGENT_GROUP}' still has members, not removing."
    fi
fi

echo
echo -e "${C_OK}=========================================================${C_RESET}"
echo -e "${C_OK} Cybersafe-AI Agent uninstalled.${C_RESET}"
echo -e "${C_OK}=========================================================${C_RESET}"
echo
