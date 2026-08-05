"""
Cybersafe Agent — Linux log collector for Cybersafe-AI SOC.

Agent qui tail des fichiers de log Linux et envoie les events
au backend Cybersafe via /api/soc/ingest/.

Usage:
    python -m cybersafe_agent
"""

__version__ = "1.8.0"
__all__ = []
