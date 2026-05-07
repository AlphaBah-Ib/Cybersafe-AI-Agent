"""
Envoi des events au backend Cybersafe avec retry exponentiel.

SOC-020 :
- POST vers /api/soc/ingest/ avec header X-Agent-Token
- Retry exponentiel : 1s, 2s, 4s, 8s, 16s, max 60s
- Pas de retry sur 4xx (sauf 429) — erreur définitive
"""
import logging
import time
from typing import List

import requests


logger = logging.getLogger("cybersafe.sender")


class EventSender:
    """
    Envoi d'events au backend Cybersafe avec retry exponentiel.

    En cas d'erreur réseau ou 5xx/429, retry avec backoff exponentiel.
    En cas de 4xx (sauf 429), pas de retry — erreur définitive.
    """

    def __init__(
        self,
        ingest_url: str,
        token: str,
        max_attempts: int = 6,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        timeout: float = 10.0,
    ):
        self.ingest_url = ingest_url
        self.token = token
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.timeout = timeout

        # Session HTTP réutilisée (connection pooling)
        self.session = requests.Session()
        self.session.headers.update({
            "X-Agent-Token": token,
            "Content-Type": "application/json",
            "User-Agent": "Cybersafe-Agent/1.0",
        })

    def send(self, events: List[dict]) -> bool:
        """
        Envoie un batch d'events.

        Returns:
            True si le batch a été envoyé avec succès.
            False si tous les retries ont échoué.
        """
        if not events:
            return True

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
                    except ValueError:
                        logger.info(f"✅ Batch sent ({len(events)} events)")
                    return True

                # 4xx (sauf 429) → erreur définitive, pas de retry
                if 400 <= response.status_code < 500 and response.status_code != 429:
                    logger.error(
                        f"❌ HTTP {response.status_code}: {response.text[:300]}"
                    )
                    return False

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
            f"({len(events)} events lost)"
        )
        return False

    def close(self):
        """Ferme proprement la session HTTP."""
        self.session.close()
