# -*- coding: utf-8 -*-
"""
US-SOC-R14 (agent 2.4.0) — minuteur de securite de l'isolation reseau.

Lance en root toutes les 30 s par cybersafe-isolation-guard.timer, INDEPENDAMMENT
du service de remediation : si le serveur est isole et que l'echeance est passee,
ou que plus aucun contact avec Cybersafe-AI n'a eu lieu depuis 5 min, le reseau
est restaure. Il ne fait jamais que RETIRER l'isolation : aucune entree ne peut
l'amener a couper davantage le reseau.

    /opt/cybersafe-agent/venv/bin/python -m cybersafe_agent.isolation_guard
"""
import logging
import sys

from .isolation import guard_tick


def main():
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(levelname)s %(name)s %(message)s")
    status = guard_tick()
    if status == "restore_failed":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
