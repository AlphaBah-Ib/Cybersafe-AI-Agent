#!/usr/bin/env bash
#
# Cybersafe-AI Agent — Mise a jour d'un agent Linux deja installe.
#
# Usage (a lancer en root sur le serveur ou l'agent tourne) :
#   sudo bash update-agent.sh [VERSION]
# Exemple :
#   sudo bash update-agent.sh v1.6.1
#
# Ce que fait ce script, etape par etape (tout est verifiable) :
#   1. Verifie l'installation existante et que le service tourne.
#   2. Telecharge le code de la version demandee depuis GitHub (repo public).
#   3. Sauvegarde le code actuel (backup .bak horodate) — REVERSIBLE.
#   4. Remplace le code de l'agent (garde le venv et la config intacts).
#   5. Verifie la syntaxe + l'import du module AVANT de redemarrer.
#   6. Redemarre le service et verifie qu'il repart.
#   7. En cas d'echec au redemarrage : ROLLBACK automatique depuis la sauvegarde.
#
# Idempotent : si la version installee est deja la cible, ne fait rien.
# Aucune commande destructive cachee : lisez le script, il fait exactement
# ce qui est ecrit.

set -euo pipefail

# --- Parametres -----------------------------------------------------------
VERSION="${1:-v1.6.1}"
REPO="AlphaBah-Ib/Cybersafe-AI-Agent"
AGENT_HOME="/opt/cybersafe-agent"
AGENT_CODE_DIR="${AGENT_HOME}/cybersafe_agent"
AGENT_VENV_PY="${AGENT_HOME}/venv/bin/python"
AGENT_USER="cybersafe"
AGENT_GROUP="cybersafe"
SERVICE_NAME="cybersafe-agent"
CONFIG_FILE="/etc/cybersafe/config.yaml"

TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/root/cybersafe-agent-backup-${TS}"
TMP_DIR="$(mktemp -d /tmp/cybersafe-update.XXXXXX)"
# ARCHIVE_URL supprime : le telechargement se fait desormais depuis le backend
# (release signee), plus depuis GitHub public. Voir bloc "Telechargement" ci-dessous.

# Couleurs (lisibilite)
C_OK="\033[1;32m"; C_INFO="\033[1;34m"; C_WARN="\033[1;33m"; C_ERR="\033[1;31m"; C_RESET="\033[0m"
info(){ echo -e "${C_INFO}[i]${C_RESET} $*"; }
ok(){   echo -e "${C_OK}[OK]${C_RESET} $*"; }
warn(){ echo -e "${C_WARN}[!]${C_RESET} $*"; }
err(){  echo -e "${C_ERR}[ERREUR]${C_RESET} $*" >&2; }

cleanup(){ rm -rf "${TMP_DIR}" 2>/dev/null || true; }
trap cleanup EXIT

# --- 0. Verifications preliminaires --------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  err "Ce script doit etre lance en root (sudo bash update-agent.sh ${VERSION})."
  exit 1
fi
if [ ! -d "${AGENT_CODE_DIR}" ]; then
  err "Agent introuvable dans ${AGENT_CODE_DIR}. L'agent est-il installe ?"
  exit 1
fi
if [ ! -x "${AGENT_VENV_PY}" ]; then
  err "Python du venv introuvable (${AGENT_VENV_PY})."
  exit 1
fi

info "Mise a jour de l'agent Cybersafe-AI vers ${VERSION}"
info "Service : ${SERVICE_NAME} | Code : ${AGENT_CODE_DIR}"

# --- 1. Recuperation des metadonnees de release signee (depuis le backend) --
REL_VERSION="${VERSION#v}"
if [ ! -f "${CONFIG_FILE}" ]; then
  err "Config agent introuvable (${CONFIG_FILE}). L'agent est-il configure ?"
  exit 1
fi
AGENT_TOKEN="$("${AGENT_VENV_PY}" -c "from cybersafe_agent.config import load_config; print(load_config('${CONFIG_FILE}').token)")"
API_URL="$("${AGENT_VENV_PY}" -c "from cybersafe_agent.config import load_config; print(load_config('${CONFIG_FILE}').api_url)")"
if [ -z "${AGENT_TOKEN}" ] || [ -z "${API_URL}" ]; then
  err "Token ou api_url absent de ${CONFIG_FILE}."
  exit 1
fi
# Version actuellement installee (avant remplacement) -> from_version du rapport.
CURRENT_VERSION="$("${AGENT_VENV_PY}" -c "import cybersafe_agent; print(cybersafe_agent.__version__)" 2>/dev/null || echo "")"

# Rapport de resultat au backend (sous-US 4). Best-effort : ne bloque jamais.
report_update(){
  local result="$1" msg="${2:-}"
  [ -z "${AGENT_TOKEN:-}" ] && return 0
  curl -fsS -m 10 -X POST \
    -H "X-Agent-Token: ${AGENT_TOKEN}" -H "Content-Type: application/json" \
    -d "{\"from_version\":\"${CURRENT_VERSION}\",\"to_version\":\"${REL_VERSION}\",\"result\":\"${result}\",\"message\":\"${msg}\"}" \
    "${API_URL%/}/soc/agents/update-report/" >/dev/null 2>&1 || true
}
RELEASE_URL="${API_URL%/}/soc/agents/release/${REL_VERSION}/"

info "Interrogation du backend pour la release ${REL_VERSION}..."
META="$(curl -fsSL -H "X-Agent-Token: ${AGENT_TOKEN}" "${RELEASE_URL}")" || {
  err "Echec interrogation ${RELEASE_URL} (release inconnue ou non signee ?)."
  exit 1
}
DOWNLOAD_URL="$(printf '%s' "${META}" | "${AGENT_VENV_PY}" -c "import sys,json;print(json.load(sys.stdin)['download_url'])")"
EXPECTED_SHA="$(printf '%s' "${META}" | "${AGENT_VENV_PY}" -c "import sys,json;print(json.load(sys.stdin)['sha256'])")"
SIGNATURE_B64="$(printf '%s' "${META}" | "${AGENT_VENV_PY}" -c "import sys,json;print(json.load(sys.stdin)['signature'])")"
if [ -z "${DOWNLOAD_URL}" ] || [ -z "${EXPECTED_SHA}" ] || [ -z "${SIGNATURE_B64}" ]; then
  err "Metadonnees de release incompletes (download_url/sha256/signature)."
  exit 1
fi

# --- 1b. Telechargement de l'archive signee (depuis le backend/bucket) -----
info "Telechargement de l'archive signee depuis ${DOWNLOAD_URL}"
if ! curl -fsSL -o "${TMP_DIR}/agent.tar.gz" "${DOWNLOAD_URL}"; then
  err "Echec du telechargement de l'archive."
  exit 1
fi

# --- 1c. VERIFICATION DE SIGNATURE (integrite + authenticite) --------------
info "Verification de la signature de l'archive..."
if ! "${AGENT_VENV_PY}" -m cybersafe_agent.signing verify \
       "${TMP_DIR}/agent.tar.gz" "${EXPECTED_SHA}" "${SIGNATURE_B64}"; then
  err "SIGNATURE INVALIDE — archive rejetee. Aucune mise a jour appliquee."
  exit 1
fi
ok "Signature valide : archive authentique et integre."

info "Extraction..."
tar xzf "${TMP_DIR}/agent.tar.gz" -C "${TMP_DIR}"
NEW_CODE_DIR="$(find "${TMP_DIR}" -maxdepth 3 -type d -name 'cybersafe_agent' | head -1)"
if [ -z "${NEW_CODE_DIR}" ] || [ ! -d "${NEW_CODE_DIR}" ]; then
  err "Dossier cybersafe_agent/ absent de l'archive telechargee. Abandon."
  exit 1
fi
SRC_ROOT="$(dirname "${NEW_CODE_DIR}")"
ok "Code ${VERSION} recupere et verifie."

# --- 1bis. Idempotence : deja a jour ? -----------------------------------
# Compare le contenu du nouveau code avec l'actuel (hash de l'arbre).
NEW_HASH="$(cd "${NEW_CODE_DIR}" && find . -type f -name '*.py' -exec sha256sum {} \; | sort | sha256sum | cut -d' ' -f1)"
CUR_HASH="$(cd "${AGENT_CODE_DIR}" && find . -type f -name '*.py' -exec sha256sum {} \; | sort | sha256sum | cut -d' ' -f1)"
if [ "${NEW_HASH}" = "${CUR_HASH}" ]; then
  ok "L'agent est deja a jour (${VERSION}). Rien a faire."
  exit 0
fi

# --- 2. Sauvegarde du code actuel (REVERSIBLE) ---------------------------
info "Sauvegarde du code actuel dans ${BACKUP_DIR}"
mkdir -p "${BACKUP_DIR}"
cp -a "${AGENT_CODE_DIR}" "${BACKUP_DIR}/cybersafe_agent"
ok "Sauvegarde faite. (Rollback possible depuis ${BACKUP_DIR})"

# --- 3. Remplacement du code (venv et config NON touches) ----------------
info "Remplacement du code de l'agent..."
# Remplace le contenu du dossier cybersafe_agent/ par la nouvelle version.
rm -rf "${AGENT_CODE_DIR}"
cp -a "${NEW_CODE_DIR}" "${AGENT_CODE_DIR}"
chown -R "${AGENT_USER}:${AGENT_GROUP}" "${AGENT_CODE_DIR}"
ok "Code remplace, permissions remises a ${AGENT_USER}:${AGENT_GROUP}."

# --- 4. Verification AVANT redemarrage (ne pas casser un agent OK) --------
info "Verification de la syntaxe et de l'import du module..."
VERIF_OK=1
# 4a. Syntaxe de tous les .py
if ! "${AGENT_VENV_PY}" - <<PYCHECK
import ast, pathlib, sys
root = pathlib.Path("${AGENT_CODE_DIR}")
errs = 0
for p in root.rglob("*.py"):
    try:
        ast.parse(p.read_text(encoding="utf-8"))
    except SyntaxError as e:
        print(f"SYNTAX ERROR: {p}: {e}")
        errs += 1
sys.exit(1 if errs else 0)
PYCHECK
then
  VERIF_OK=0
fi
# 4b. Import du package principal
if [ "${VERIF_OK}" = "1" ]; then
  if ! ( cd "${AGENT_HOME}" && "${AGENT_VENV_PY}" -c "import cybersafe_agent" 2>/dev/null ); then
    warn "L'import de cybersafe_agent a echoue."
    VERIF_OK=0
  fi
fi

rollback(){
  err "Verification/redemarrage en echec — ROLLBACK vers la version precedente."
  report_update "failed" "rollback: le nouvel agent n'a pas demarre correctement"
  rm -rf "${AGENT_CODE_DIR}"
  cp -a "${BACKUP_DIR}/cybersafe_agent" "${AGENT_CODE_DIR}"
  chown -R "${AGENT_USER}:${AGENT_GROUP}" "${AGENT_CODE_DIR}"
  systemctl restart "${SERVICE_NAME}" || true
  sleep 2
  if systemctl is-active --quiet "${SERVICE_NAME}"; then
    ok "Rollback effectue : l'agent precedent est restaure et actif."
  else
    err "Rollback effectue mais le service n'est pas actif. Verifiez :"
    err "  journalctl -u ${SERVICE_NAME} -n 30"
    err "  Sauvegarde conservee dans ${BACKUP_DIR}"
  fi
}

if [ "${VERIF_OK}" != "1" ]; then
  rollback
  exit 1
fi
ok "Verifications passees (syntaxe + import)."

# --- 5. Redemarrage + verification que le service repart -----------------
# --- Mise a jour du service de remediation (SOC-RESPONSE Option A) --------
REMEDIATION_UNIT_SRC="${SRC_ROOT}/packaging/linux/systemd/cybersafe-remediation.service"
REMEDIATION_UNIT_DST="/etc/systemd/system/cybersafe-remediation.service"
if [ -f "${REMEDIATION_UNIT_SRC}" ]; then
  info "Mise a jour de l'unite de remediation..."
  install -o root -g root -m 0644 "${REMEDIATION_UNIT_SRC}" "${REMEDIATION_UNIT_DST}"
  systemctl daemon-reload
  systemctl enable cybersafe-remediation.service >/dev/null 2>&1 || true
fi

info "Redemarrage du service ${SERVICE_NAME}..."
systemctl restart "${SERVICE_NAME}"
sleep 3
if systemctl list-unit-files | grep -q cybersafe-remediation.service; then
  info "Activation + demarrage du service de remediation..."
  # enable --now : idempotent (active au boot ET demarre maintenant, que le
  # service tourne deja ou non). Robuste au 1er deploiement.
  systemctl enable --now cybersafe-remediation.service 2>/dev/null \
    || systemctl restart cybersafe-remediation.service \
    || warn "remediation start KO (non bloquant)."
fi
if systemctl is-active --quiet "${SERVICE_NAME}"; then
  ok "Agent redemarre et actif sur la version ${VERSION}."
  report_update "success" "mise a jour ${CURRENT_VERSION} -> ${REL_VERSION} appliquee"
  info "Derniers logs :"
  journalctl -u "${SERVICE_NAME}" --no-pager -n 8 || true
  echo ""
  ok "Mise a jour terminee. Sauvegarde conservee : ${BACKUP_DIR}"
  info "Si tout fonctionne bien apres quelques minutes, vous pouvez supprimer la sauvegarde :"
  info "  rm -rf ${BACKUP_DIR}"
else
  rollback
  exit 1
fi
