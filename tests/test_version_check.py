"""
AGENT auto-update (sous-US 1) — comparaison de versions cote agent.
Verrouille _parse_version / _is_newer, notamment le piege du compare de chaines
('1.9.0' > '1.10.0' est faux en string mais doit etre False en semantique).
A ce stade l'agent INFORME seulement (aucun telechargement) ; ces helpers
decident juste s'il faut logger qu'une mise a jour existe.
"""
import pytest

from cybersafe_agent.sender import _parse_version, _is_newer


class TestParseVersion:
    def test_basic(self):
        assert _parse_version("1.10.3") == (1, 10, 3)

    def test_strips_v_prefix(self):
        assert _parse_version("v1.8.0") == (1, 8, 0)

    def test_whitespace_tolerant(self):
        assert _parse_version("  1.7.3  ") == (1, 7, 3)

    @pytest.mark.parametrize("bad", [None, "", "abc", "1.x.0", "1..0"])
    def test_malformed_returns_none(self, bad):
        assert _parse_version(bad) is None


class TestIsNewer:
    def test_semantic_not_string_compare(self):
        # le coeur : 1.10.0 > 1.9.0 (faux si compare comme des chaines)
        assert _is_newer("1.10.0", "1.9.0") is True
        assert _is_newer("1.9.0", "1.10.0") is False

    def test_equal_is_not_newer(self):
        assert _is_newer("1.7.3", "1.7.3") is False

    def test_older_is_not_newer(self):
        assert _is_newer("1.6.0", "1.7.3") is False

    def test_v_prefix_handled(self):
        assert _is_newer("v1.8.0", "1.7.3") is True

    def test_patch_bump(self):
        assert _is_newer("1.7.4", "1.7.3") is True

    @pytest.mark.parametrize("latest,current", [
        (None, "1.7.3"), ("abc", "1.7.3"), ("1.8.0", None), ("1.8.0", "xyz"),
    ])
    def test_malformed_never_newer(self, latest, current):
        assert _is_newer(latest, current) is False
