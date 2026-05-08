"""
Spool disque pour résilience (SOC-022).

Quand un envoi au backend échoue après tous les retries, le batch est
écrit sur disque dans /var/spool/cybersafe/ pour ne pas être perdu.
Au prochain succès d'envoi, le spool est rejoué chronologiquement.

Format de fichier : un fichier JSON par batch.
    {
        "version": 1,
        "spooled_at": "2026-05-08T20:12:45.672Z",
        "events": [...]
    }

Les noms de fichiers sont chronologiquement triables :
    YYYYMMDD-HHMMSS-mmm-XXXX.json
ce qui permet un rejeu naturel par sorted(listdir()).

Limite de taille (FIFO) : quand la taille totale du spool dépasse
max_size_mb, les plus vieux fichiers sont supprimés en premier.
"""
import json
import logging
import os
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


logger = logging.getLogger("cybersafe.spool")

SPOOL_FORMAT_VERSION = 1
FILE_SUFFIX = ".json"
TMP_SUFFIX = ".tmp"


class EventSpool:
    """
    Spool disque FIFO pour les batches d'events qui n'ont pas pu être envoyés.

    Args:
        directory: chemin du dossier spool (créé si manquant).
        max_size_mb: limite en mégaoctets de la taille totale du spool.
            Au-delà, les fichiers les plus vieux sont supprimés (FIFO).
    """

    def __init__(self, directory: str, max_size_mb: int = 100):
        self.directory = Path(directory)
        self.max_size_bytes = int(max_size_mb) * 1024 * 1024

        # Création du dossier si manquant (le runner doit avoir les droits)
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
        except PermissionError as e:
            logger.error(
                f"❌ Cannot create spool directory {self.directory}: {e}"
            )
            raise

    # ── Écriture ─────────────────────────────────────────────────────────

    def write(self, events: List[dict]) -> Optional[Path]:
        """
        Persiste un batch d'events sur disque, atomiquement.

        Évince les plus vieux fichiers si nécessaire pour respecter
        la limite de taille.

        Returns:
            Le Path du fichier écrit, ou None en cas d'échec
            (par exemple si le batch est trop gros pour la limite).
        """
        if not events:
            return None

        payload = {
            "version": SPOOL_FORMAT_VERSION,
            "spooled_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"
            ),
            "events": events,
        }
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        new_size = len(body)

        # Évince si nécessaire pour faire de la place
        self._evict_until_fits(new_size)

        # Refus définitif si même après éviction le batch ne tient pas
        if new_size > self.max_size_bytes:
            logger.warning(
                f"⚠ Batch too large for spool "
                f"({new_size} bytes > {self.max_size_bytes} bytes limit) — dropped"
            )
            return None

        # Nom de fichier chronologique + suffix random (anti-collision)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")[:-3]
        rand = secrets.token_hex(2)  # 4 chars hex
        target = self.directory / f"{ts}-{rand}{FILE_SUFFIX}"

        # Écriture atomique : tmp dans le même dossier puis rename
        try:
            with tempfile.NamedTemporaryFile(
                dir=self.directory,
                prefix=".spool-",
                suffix=TMP_SUFFIX,
                delete=False,
            ) as tmp:
                tmp.write(body)
                tmp.flush()
                os.fsync(tmp.fileno())
                tmp_path = Path(tmp.name)
            os.rename(tmp_path, target)
        except OSError as e:
            logger.error(f"❌ Failed to write spool file: {e}")
            return None

        logger.info(
            f"💾 Spooled batch of {len(events)} events to "
            f"{target.name} ({new_size} bytes)"
        )
        return target

    # ── Lecture / rejeu ──────────────────────────────────────────────────

    def oldest(self) -> Optional[Path]:
        """Retourne le fichier le plus ancien, ou None si spool vide."""
        files = self._list_files()
        return files[0] if files else None

    def read(self, path: Path) -> Optional[List[dict]]:
        """
        Lit et parse un fichier spool.

        Returns:
            La liste d'events, ou None si le fichier est invalide
            (auquel cas il est supprimé pour ne pas bloquer le rejeu).
        """
        try:
            with open(path, "rb") as f:
                payload = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(
                f"⚠ Corrupt spool file {path.name} ({e}) — discarding"
            )
            self.remove(path)
            return None

        events = payload.get("events")
        if not isinstance(events, list):
            logger.warning(
                f"⚠ Invalid spool file {path.name} (no events list) — discarding"
            )
            self.remove(path)
            return None

        return events

    def remove(self, path: Path) -> None:
        """Supprime un fichier spool (idempotent)."""
        try:
            path.unlink(missing_ok=True)
        except OSError as e:
            logger.warning(f"⚠ Failed to remove spool file {path.name}: {e}")

    # ── Stats ────────────────────────────────────────────────────────────

    def count(self) -> int:
        """Nombre de fichiers en spool."""
        return len(self._list_files())

    def total_size_bytes(self) -> int:
        """Taille totale du spool sur disque (octets)."""
        total = 0
        for f in self._list_files():
            try:
                total += f.stat().st_size
            except OSError:
                pass
        return total

    # ── Internals ────────────────────────────────────────────────────────

    def _list_files(self) -> List[Path]:
        """Liste les fichiers .json triés par nom = chronologique."""
        try:
            entries = [
                self.directory / name
                for name in os.listdir(self.directory)
                if name.endswith(FILE_SUFFIX) and not name.startswith(".")
            ]
        except OSError:
            return []
        entries.sort(key=lambda p: p.name)
        return entries

    def _evict_until_fits(self, incoming_bytes: int) -> None:
        """
        Supprime les plus vieux fichiers tant que la place pour `incoming_bytes`
        n'est pas disponible sous la limite.
        """
        if incoming_bytes >= self.max_size_bytes:
            # Inutile d'évincer : le fichier seul ne tiendra pas.
            # On vide quand même le spool pour libérer la place.
            for f in self._list_files():
                self.remove(f)
            return

        files = self._list_files()
        current = sum(f.stat().st_size for f in files if f.exists())
        i = 0
        while current + incoming_bytes > self.max_size_bytes and i < len(files):
            try:
                size = files[i].stat().st_size
            except OSError:
                size = 0
            self.remove(files[i])
            current -= size
            i += 1
            if i == 1:
                logger.warning(
                    f"⚠ Spool over limit — evicting oldest file(s) (FIFO)"
                )
