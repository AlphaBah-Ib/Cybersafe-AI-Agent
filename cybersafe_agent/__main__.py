"""
Point d'entrée pour `python -m cybersafe_agent` et pour le binaire PyInstaller.

Utilise des imports absolus pour être compatible avec les deux modes :
- En dev : `python -m cybersafe_agent` (Python définit __package__='cybersafe_agent')
- En binaire PyInstaller : __main__.py est exécuté comme script (__package__ vide)
"""
from cybersafe_agent.main import run


if __name__ == "__main__":
    run()
