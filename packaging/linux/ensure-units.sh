#!/usr/bin/env bash
#
# Cybersafe-AI Agent — installe ou met a niveau les unites systemd ajoutees
# apres l'installation initiale. Idempotent : ne touche a rien si tout est deja
# en place. Lance en root par install.sh, update-agent.sh et auto-update-check.sh.
#
# Le contenu des unites est EMBARQUE ici : une mise a jour par l'ancien script
# (qui ne rafraichit que les *.sh) suffit donc a les deployer au passage suivant.
#
# US-SOC-R12 porte 4a : cybersafe-proxy-apply (blocage au reverse proxy nginx).
#   - le service de remediation (non privilegie) ecrit l'etat voulu dans
#     /var/lib/cybersafe/proxy/desired.json ;
#   - cybersafe-proxy-apply.path detecte le changement et lance
#     cybersafe-proxy-apply.service (root) qui revalide tout, teste nginx et
#     recharge ; le statut est ecrit dans /var/lib/cybersafe-proxy (root).
#
set -euo pipefail

log(){ echo "[ensure-units] $*"; }

if [ "$(id -u)" -ne 0 ]; then
  log "Doit etre lance en root."; exit 1
fi
if ! id -u cybersafe >/dev/null 2>&1; then
  log "Utilisateur cybersafe absent : agent non installe, rien a faire."; exit 0
fi

CHANGED=0
write_unit(){
  local dst="$1" content="$2"
  if [ ! -f "${dst}" ] || [ "$(cat "${dst}")" != "${content}" ]; then
    printf '%s\n' "${content}" > "${dst}.tmp"
    chmod 0644 "${dst}.tmp"
    chown root:root "${dst}.tmp"
    mv -f "${dst}.tmp" "${dst}"
    CHANGED=1
    log "Unite installee ou mise a jour : ${dst}"
  fi
}

# --- Repertoires --------------------------------------------------------------
# Etat voulu : ecrit par le service de remediation (utilisateur cybersafe).
install -d -o cybersafe -g cybersafe -m 0750 /var/lib/cybersafe
install -d -o cybersafe -g cybersafe -m 0750 /var/lib/cybersafe/proxy
# Statut : ecrit par root uniquement (aucun lien symbolique possible par l'agent).
install -d -o root -g root -m 0755 /var/lib/cybersafe-proxy

# --- Unites ---------------------------------------------------------------------
PROXY_SERVICE="$(cat <<'EOF'
[Unit]
Description=Cybersafe-AI - application des blocages au reverse proxy (nginx)
Documentation=https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent
ConditionPathExists=/opt/cybersafe-agent/venv/bin/python

[Service]
Type=oneshot
# root requis : ecrit dans /etc/nginx/conf.d et recharge nginx. Le programme
# revalide integralement l'etat voulu et teste nginx avant tout rechargement.
User=root
WorkingDirectory=/opt/cybersafe-agent
ExecStart=/opt/cybersafe-agent/venv/bin/python -m cybersafe_agent.proxy_apply
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cybersafe-proxy-apply
TimeoutStartSec=120
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=-/etc/nginx/conf.d /var/lib/cybersafe-proxy
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
LockPersonality=true
EOF
)"

PROXY_PATH="$(cat <<'EOF'
[Unit]
Description=Cybersafe-AI - surveillance de l'etat voulu du reverse proxy
Documentation=https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent

[Path]
PathChanged=/var/lib/cybersafe/proxy/desired.json
Unit=cybersafe-proxy-apply.service

[Install]
WantedBy=multi-user.target
EOF
)"

write_unit /etc/systemd/system/cybersafe-proxy-apply.service "${PROXY_SERVICE}"
write_unit /etc/systemd/system/cybersafe-proxy-apply.path "${PROXY_PATH}"

if [ "${CHANGED}" = "1" ]; then
  systemctl daemon-reload
fi
systemctl enable cybersafe-proxy-apply.path >/dev/null 2>&1 || log "enable du .path differe."
systemctl start cybersafe-proxy-apply.path >/dev/null 2>&1 || log "demarrage du .path differe."
log "Unites a jour."
