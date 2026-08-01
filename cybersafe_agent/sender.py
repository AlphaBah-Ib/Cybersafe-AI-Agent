"""
Envoi des events au backend Cybersafe avec retry exponentiel + spool disque.

SOC-020 :
- POST vers /api/soc/ingest/ avec header X-Agent-Token
- Retry exponentiel : 1s, 2s, 4s, 8s, 16s, max 60s
- Pas de retry sur 4xx (sauf 429) — erreur définitive

SOC-022 :
- Si tous les retries échouent et un spool est fourni, le batch est
  persisté sur disque dans le spool au lieu d'être perdu.
- À chaque envoi réussi, on tente de drainer un fichier de spool en
  plus (rattrapage progressif sans bloquer le flux normal).
- Au démarrage, l'agent peut appeler drain_spool_blocking() pour
  tenter de vider le spool en une fois.
"""
import logging
import time
from typing import List, Optional

import requests

from . import __version__


def _parse_version(v):
    """Parse '1.10.3' (ou 'v1.10.3') -> (1, 10, 3). None si non parsable."""
    try:
        return tuple(int(x) for x in str(v).strip().lstrip("v").split("."))
    except (ValueError, AttributeError):
        return None


def _is_newer(latest, current):
    """True si latest > current (comparaison semantique par tuple, pas string)."""
    lv, cv = _parse_version(latest), _parse_version(current)
    if lv is None or cv is None:
        return False
    return lv > cv
from .spool import EventSpool


logger = logging.getLogger("cybersafe.sender")


class EventSender:
    """
    Envoi d'events au backend Cybersafe avec retry exponentiel.

    En cas d'erreur réseau ou 5xx/429, retry avec backoff exponentiel.
    En cas de 4xx (sauf 429), pas de retry — erreur définitive.

    Si un EventSpool est fourni :
    - Les batches qui échouent en transient (réseau, 5xx, 429) sont
      persistés sur disque pour un rejeu ultérieur.
    - Les 4xx définitifs ne sont PAS spoolés (le rejeu donnerait la
      même erreur — typiquement token invalide ou batch malformé).
    - À chaque envoi réussi, le sender tente de drainer un fichier
      de spool, ce qui assure un rattrapage progressif.
    """

    def __init__(
        self,
        ingest_url: str,
        token: str,
        max_attempts: int = 6,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        timeout: float = 10.0,
        spool: Optional[EventSpool] = None,
    ):
        self.ingest_url = ingest_url
        self.token = token
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.timeout = timeout
        self.spool = spool

        # Session HTTP réutilisée (connection pooling)
        self.session = requests.Session()
        self.session.headers.update({
            "X-Agent-Token": token,
            "Content-Type": "application/json",
            "User-Agent": f"Cybersafe-Agent/{__version__}",
        })

    # ── API publique ─────────────────────────────────────────────────────

    def send(self, events: List[dict]) -> bool:
        """
        Envoie un batch d'events.

        Returns:
            True si le batch a été envoyé avec succès OU spoolé sur disque
                pour rejeu ultérieur (l'event n'est pas perdu).
            False uniquement si l'envoi a définitivement échoué (4xx hors 429)
                et n'a donc pas de sens à être rejoué.
        """
        if not events:
            return True

        outcome = self._send_once(events)

        if outcome == "ok":
            # On profite de la connexion saine pour drainer un peu de spool
            self._opportunistic_drain_one()
            return True

        if outcome == "fatal":
            # 4xx définitif (autre que 429) — inutile de spooler
            return False

        # outcome == "transient" : on tente le spool si dispo
        if self.spool is not None:
            try:
                path = self.spool.write(events)
                if path is not None:
                    return True
                # Spool plein ET batch trop gros → on a tout perdu, log
                logger.error(
                    f"❌ Batch lost: spool refused to persist "
                    f"({len(events)} events)"
                )
                return False
            except Exception as e:
                logger.error(f"❌ Spool error while persisting batch: {e}")
                return False

        # Pas de spool configuré → batch perdu (comportement historique)
        logger.error(
            f"❌ Batch lost (no spool): {len(events)} events"
        )
        return False

    def drain_spool_blocking(self, max_files: Optional[int] = None) -> int:
        """
        Tente de rejouer le spool en bloquant jusqu'à succès complet ou échec.

        À appeler typiquement au démarrage de l'agent pour rattraper les
        batches en attente depuis la session précédente.

        Args:
            max_files: limite optionnelle du nombre de fichiers à rejouer
                en une passe. None = tout drainer.

        Returns:
            Le nombre de fichiers rejoués avec succès.
        """
        if self.spool is None:
            return 0

        replayed = 0
        while True:
            if max_files is not None and replayed >= max_files:
                break

            path = self.spool.oldest()
            if path is None:
                break  # spool vide

            events = self.spool.read(path)
            if events is None:
                # Fichier corrompu, déjà supprimé par spool.read()
                continue

            logger.info(
                f"♻ Replaying spooled batch {path.name} ({len(events)} events)..."
            )
            outcome = self._send_once(events)

            if outcome == "ok":
                self.spool.remove(path)
                replayed += 1
            elif outcome == "fatal":
                # 4xx définitif sur des données qui dormaient sur disque :
                # on ne va pas tourner en boucle, on les drop.
                logger.error(
                    f"❌ Spooled batch {path.name} rejected by backend "
                    f"(fatal error) — discarding"
                )
                self.spool.remove(path)
            else:
                # transient: on s'arrête, on retentera plus tard
                logger.info(
                    f"⏸ Spool drain paused (transient error) — "
                    f"{self.spool.count()} file(s) still queued"
                )
                break

        if replayed > 0:
            logger.info(f"✅ Drained {replayed} spool file(s)")
        return replayed

    def close(self):
        """Ferme proprement la session HTTP."""
        self.session.close()

    # ── Internals ────────────────────────────────────────────────────────

    def _send_once(self, events: List[dict]) -> str:
        """
        Envoie un batch avec retry exponentiel.

        Returns:
            "ok"        : batch envoyé avec succès (2xx).
            "fatal"     : 4xx définitif (≠ 429), inutile de réessayer.
            "transient" : tous les retries ont échoué (réseau / 5xx / 429),
                          le batch peut être spoolé pour rejeu ultérieur.
        """
        for attempt in range(1, self.max_attempts + 1):
            try:
                response = self.session.post(
                    self.ingest_url,
                    json=events,
                    timeout=self.timeout,
                )

                # Succès (2xx)
                if 200 <= response.status_code < 300:
                    try:
                        data = response.json()
                        logger.info(
                            f"✅ Batch sent: {data.get('ingested', 0)} ingested, "
                            f"{data.get('duplicates', 0)} duplicates"
                        )
                        # AGENT auto-update (sous-US 1) : le backend signale la
                        # derniere version dispo. On INFORME seulement (aucun
                        # telechargement/execution : sous-US 2 et 3).
                        _latest = data.get("latest_version")
                        if _latest and _is_newer(_latest, __version__):
                            logger.info(
                                f"🔄 Nouvelle version {_latest} disponible "
                                f"(version actuelle: {__version__}). "
                                f"Mise a jour automatique non encore active."
                            )
                    except ValueError:
                        logger.info(f"✅ Batch sent ({len(events)} events)")
                    return "ok"

                # 4xx (sauf 429) → erreur définitive, pas de retry
                if 400 <= response.status_code < 500 and response.status_code != 429:
                    logger.error(
                        f"❌ HTTP {response.status_code}: {response.text[:300]}"
                    )
                    return "fatal"

                # 429 (rate limit) ou 5xx → retry
                logger.warning(
                    f"⚠ HTTP {response.status_code} "
                    f"(attempt {attempt}/{self.max_attempts})"
                )

            except requests.exceptions.RequestException as e:
                logger.warning(
                    f"⚠ Network error "
                    f"(attempt {attempt}/{self.max_attempts}): {e}"
                )

            # Pas la dernière tentative → backoff exponentiel
            if attempt < self.max_attempts:
                delay = min(
                    self.base_delay * (2 ** (attempt - 1)),
                    self.max_delay,
                )
                logger.info(f"   Retry in {delay:.1f}s...")
                time.sleep(delay)

        logger.error(
            f"❌ Batch failed after {self.max_attempts} attempts "
            f"({len(events)} events) — will spool if available"
        )
        return "transient"

    def _opportunistic_drain_one(self) -> None:
        """
        Tente de rejouer UN fichier de spool, sans bloquer.

        Appelé après chaque envoi réussi : si le spool contient des
        batches en attente, on en rejoue un seul pour ne pas saturer
        la connexion ni retarder le flux courant. Le rattrapage se
        fait progressivement, batch par batch.
        """
        if self.spool is None:
            return

        path = self.spool.oldest()
        if path is None:
            return

        events = self.spool.read(path)
        if events is None:
            return  # déjà supprimé par spool.read si corrompu

        logger.info(
            f"♻ Replaying spooled batch {path.name} ({len(events)} events)..."
        )
        outcome = self._send_once(events)

        if outcome == "ok":
            self.spool.remove(path)
            remaining = self.spool.count()
            if remaining > 0:
                logger.info(
                    f"   Spool drain progress: {remaining} file(s) remaining"
                )
        elif outcome == "fatal":
            logger.error(
                f"❌ Spooled batch {path.name} rejected by backend "
                f"(fatal error) — discarding"
            )
            self.spool.remove(path)
        # transient → on garde, on retentera au prochain envoi réussi
