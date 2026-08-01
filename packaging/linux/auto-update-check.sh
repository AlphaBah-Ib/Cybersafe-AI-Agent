#!/usr/bin/env bash
#
# Cybersafe-AI Agent — Verification et declenchement de l'auto-update.
#
# Lance par le timer systemd cybersafe-update.timer (root, nocturne + jitter).
# Ce script NE modifie rien lui-meme : il decide s'il faut mettre a jour, puis
# delegue a update-agent.sh (qui telecharge, VERIFIE la signature, applique avec
# rollback). Tout est verifiable ; aucune commande destructive cachee.
#
# Etapes :
#   1. Respecte l'opt-out (auto_update.enabled=false dans config.yaml -> ne fait rien).
#   2. Interroge le backend pour la derniere version disponible.
#   3. Compare a la version installee ; si maj -> appelle update-agent.sh.
#
set -euo pipefail

AGENT_HOME="/opt/cybersafe-agent"
AGENT_VENV_PY="${AGENT_HOME}/venv/bin/python"
CONFIG_FILE="/etc/cybersafe/config.yaml"
UPDATE_SCRIPT="$(dirname "$(readlink -f "$0")")/update-agent.sh"

log(){ echo "[cybersafe-update] $*"; }

# --- 0. Preconditions -----------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  log "Doit etre lance en root."; exit 1
fi
if [ ! -x "${AGENT_VENV_PY}" ]; then
  log "Python du venv introuvable (${AGENT_VENV_PY}) — agent non installe ?"; exit 0
fi
if [ ! -f "${CONFIG_FILE}" ]; then
  log "Config introuvable (${CONFIG_FILE})."; exit 0
fi

# --- 1. Opt-out : le client peut figer sa version -------------------------
ENABLED="$("${AGENT_VENV_PY}" -c "from cybersafe_agent.config import load_config; print(load_config('${CONFIG_FILE}').auto_update_enabled)" 2>/dev/null || echo "True")"
if [ "${ENABLED}" != "True" ]; then
  log "Auto-update desactive (opt-out). Rien a faire."; exit 0
fi

# --- 2. Version installee + derniere version disponible -------------------
CURRENT="$("${AGENT_VENV_PY}" -c "import cybersafe_agent; print(cybersafe_agent.__version__)")"
TOKEN="$("${AGENT_VENV_PY}" -c "from cybersafe_agent.config import load_config; print(load_config('${CONFIG_FILE}').token)")"
API_URL="$("${AGENT_VENV_PY}" -c "from cybersafe_agent.config import load_config; print(load_config('${CONFIG_FILE}').api_url)")"

# On demande la release "latest" au backend. Endpoint dedie (a exposer) OU on
# lit latest_version deja renvoye par l'ingest. Ici : endpoint release/latest/.
LATEST_URL="${API_URL%/}/soc/agents/release/latest/"
META="$(curl -fsSL -H "X-Agent-Token: ${TOKEN}" "${LATEST_URL}" 2>/dev/null)" || {
  log "Impossible d'obtenir la derniere version (backend injoignable ?)."; exit 0
}
LATEST="$(printf '%s' "${META}" | "${AGENT_VENV_PY}" -c "import sys,json;print(json.load(sys.stdin).get('version',''))" 2>/dev/null || echo "")"
if [ -z "${LATEST}" ]; then
  log "Aucune release latest disponible."; exit 0
fi

# --- 3. Comparaison semantique (reutilise le comparateur de l'agent) ------
IS_NEWER="$("${AGENT_VENV_PY}" -c "from cybersafe_agent.sender import _is_newer; print(_is_newer('${LATEST}', '${CURRENT}'))")"
if [ "${IS_NEWER}" != "True" ]; then
  log "Deja a jour (installee ${CURRENT}, derniere ${LATEST}). Rien a faire."; exit 0
fi

# --- 4. Declenchement de la mise a jour (delegation a update-agent.sh) ----
log "Nouvelle version ${LATEST} disponible (installee ${CURRENT}). Mise a jour..."
if [ ! -x "${UPDATE_SCRIPT}" ] && [ ! -f "${UPDATE_SCRIPT}" ]; then
  log "update-agent.sh introuvable (${UPDATE_SCRIPT})."; exit 1
fi
exec bash "${UPDATE_SCRIPT}" "${LATEST}"
