"""Le déploiement compare les épingles de requirements.txt au venv qui sert."""

import importlib.util
import sys
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "check_requirements_installed",
    Path(__file__).resolve().parents[1] / "scripts" / "check_requirements_installed.py",
)
chk = importlib.util.module_from_spec(_SPEC)
sys.modules["check_requirements_installed"] = chk
_SPEC.loader.exec_module(chk)


def _installe(versions):
    return lambda nom: versions.get(chk.normaliser(nom))


def test_epingles_lues_avec_includes(tmp_path):
    (tmp_path / "base.txt").write_text("anyio==4.14.2  # commentaire\n\nPyJWT==2.10.1\n")
    (tmp_path / "dev.txt").write_text("-r base.txt\n# rien\npytest==9.0.3\n")
    assert chk.epingles(tmp_path / "dev.txt") == {"anyio": "4.14.2", "pyjwt": "2.10.1", "pytest": "9.0.3"}


def test_ecarts_version_et_absence(tmp_path):
    (tmp_path / "r.txt").write_text("anyio==4.14.2\ncryptography==50.0.0\nredis==6.0.0\n")
    ecarts = chk.ecarts(tmp_path / "r.txt", _installe({"anyio": "4.13.0", "cryptography": "50.0.0"}))
    assert ecarts == [("anyio", "4.14.2", "4.13.0"), ("redis", "6.0.0", None)]


def test_noms_normalises(tmp_path):
    (tmp_path / "r.txt").write_text("Typing_Extensions==4.15.0\n")
    assert chk.ecarts(tmp_path / "r.txt", _installe({"typing-extensions": "4.15.0"})) == []


def test_ligne_non_epinglee_refusee(tmp_path):
    (tmp_path / "r.txt").write_text("anyio>=4\n")
    try:
        chk.epingles(tmp_path / "r.txt")
    except ValueError as e:
        assert "anyio>=4" in str(e)
    else:
        raise AssertionError("une ligne sans == doit être refusée")
