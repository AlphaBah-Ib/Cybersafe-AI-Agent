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
# US-SOC-R14 porte 2 : cybersafe-isolation-guard (minuteur de securite de l'isolation).
#   - toutes les 30 s, root, independant du service de remediation ;
#   - restaure le reseau a l'echeance ou si plus aucun contact avec Cybersafe-AI ;
#   - horodatage dans /var/lib/cybersafe-isolation (root) : sans lui, l'agent
#     refuse toute isolation.
#
# US-SOC-R15 porte 2 : cybersafe-process-apply (reponse sur processus suspects).
#   - le service de remediation (non privilegie) depose l'ordre SIGNE dans
#     /var/lib/cybersafe/process/request.json ;
#   - cybersafe-process-apply.path lance cybersafe-process-apply.service (root,
#     capacites CAP_KILL / CAP_SYS_PTRACE / CAP_DAC_READ_SEARCH, aucun reseau) qui
#     re-verifie la signature, l'expiration et le nonce, re-identifie le processus
#     par son empreinte et agit par pidfd ; resultat dans /var/lib/cybersafe-process.
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
# [R12-P4B] enforce.conf (regles WAF et pays), ecrit par l'unite root si nginx est present.
if [ -d /etc/nginx ]; then
  install -d -o root -g root -m 0755 /etc/nginx/cybersafe
fi

# [R14-P2] etat d'isolation (service) et horodatage du minuteur (root).
install -d -o cybersafe -g cybersafe -m 0750 /var/lib/cybersafe/isolation
install -d -o root -g root -m 0755 /var/lib/cybersafe-isolation

# [R15-P2] demande (service) et resultats + journal anti-rejeu (root, lisibles par l'agent).
install -d -o cybersafe -g cybersafe -m 0750 /var/lib/cybersafe/process
install -d -o root -g cybersafe -m 0750 /var/lib/cybersafe-process

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
ReadWritePaths=-/etc/nginx/conf.d -/etc/nginx/cybersafe /var/lib/cybersafe-proxy
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

# [R14-P2] minuteur de securite de l'isolation : il ne fait que RETIRER l'isolation.
GUARD_SERVICE="$(cat <<'EOF'
[Unit]
Description=Cybersafe-AI - minuteur de securite de l'isolation reseau (restauration automatique)
Documentation=https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent
ConditionPathExists=/opt/cybersafe-agent/venv/bin/python

[Service]
Type=oneshot
# root (capacites reduites) : lit l'etat ecrit par le service, retire les regles
# d'isolation, ecrit son horodatage. Independant du service de remediation.
User=root
WorkingDirectory=/opt/cybersafe-agent
ExecStart=/opt/cybersafe-agent/venv/bin/python -m cybersafe_agent.isolation_guard
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cybersafe-isolation-guard
TimeoutStartSec=60
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_OVERRIDE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/cybersafe /var/lib/cybersafe-isolation
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
LockPersonality=true
EOF
)"

GUARD_TIMER="$(cat <<'EOF'
[Unit]
Description=Cybersafe-AI - declencheur du minuteur de securite de l'isolation (30 s)
Documentation=https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF
)"

# [R15-P2] reponse sur processus : root a capacites reduites, sans reseau.
PROCESS_SERVICE="$(cat <<'EOF'
[Unit]
Description=Cybersafe-AI - reponse sur processus suspects (inspection, gel, arret)
Documentation=https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent
ConditionPathExists=/opt/cybersafe-agent/venv/bin/python

[Service]
Type=oneshot
# root (capacites reduites) : lit /proc de tous les processus, signale par pidfd.
# Re-verifie integralement l'ordre signe : le service de remediation n'est qu'un messager.
User=root
WorkingDirectory=/opt/cybersafe-agent
ExecStart=/opt/cybersafe-agent/venv/bin/python -m cybersafe_agent.process_apply
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cybersafe-process-apply
TimeoutStartSec=120
CapabilityBoundingSet=CAP_KILL CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/cybersafe-process
RestrictAddressFamilies=AF_UNIX
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
SystemCallArchitectures=native
MemoryMax=256M
TasksMax=16
EOF
)"

PROCESS_PATH="$(cat <<'EOF'
[Unit]
Description=Cybersafe-AI - surveillance des demandes de reponse sur processus
Documentation=https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent

[Path]
PathChanged=/var/lib/cybersafe/process/request.json
Unit=cybersafe-process-apply.service

[Install]
WantedBy=multi-user.target
EOF
)"

write_unit /etc/systemd/system/cybersafe-proxy-apply.service "${PROXY_SERVICE}"
write_unit /etc/systemd/system/cybersafe-proxy-apply.path "${PROXY_PATH}"
write_unit /etc/systemd/system/cybersafe-isolation-guard.service "${GUARD_SERVICE}"
write_unit /etc/systemd/system/cybersafe-isolation-guard.timer "${GUARD_TIMER}"
write_unit /etc/systemd/system/cybersafe-process-apply.service "${PROCESS_SERVICE}"
write_unit /etc/systemd/system/cybersafe-process-apply.path "${PROCESS_PATH}"

if [ "${CHANGED}" = "1" ]; then
  systemctl daemon-reload
fi
systemctl enable cybersafe-proxy-apply.path >/dev/null 2>&1 || log "enable du .path differe."
systemctl start cybersafe-proxy-apply.path >/dev/null 2>&1 || log "demarrage du .path differe."
systemctl enable cybersafe-isolation-guard.timer >/dev/null 2>&1 || log "enable du minuteur d'isolation differe."
systemctl start cybersafe-isolation-guard.timer >/dev/null 2>&1 || log "demarrage du minuteur d'isolation differe."
systemctl enable cybersafe-process-apply.path >/dev/null 2>&1 || log "enable du .path processus differe."
systemctl start cybersafe-process-apply.path >/dev/null 2>&1 || log "demarrage du .path processus differe."
log "Unites a jour."
