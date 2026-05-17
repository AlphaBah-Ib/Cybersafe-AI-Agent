"""
Point d'entrée pour `python -m cybersafe_agent` et pour le binaire PyInstaller.

Utilise des imports absolus pour être compatible avec les deux modes :
- En dev : `python -m cybersafe_agent` (Python définit __package__='cybersafe_agent')
- En binaire PyInstaller : __main__.py est exécuté comme script (__package__ vide)

Appelle main() (et non run() directement) pour que les flags CLI
(--help, --version, --config, --service) soient parsés AVANT toute
tentative de charger config.yaml.
"""
from cybersafe_agent.main import main


if __name__ == "__main__":
    main()
