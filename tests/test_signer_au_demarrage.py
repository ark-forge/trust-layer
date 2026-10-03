"""Le signeur se vérifie au démarrage du service, pas à l'import de `trust_layer.config`.

Depuis tl-signer (P5a), seul l'utilisateur trust-layer joint le socket : un fail-fast à l'import empêchait
tout script d'administration (provision_challenge_key.py, --allow-key-ref) de tourner en ubuntu, alors
qu'aucun ne signe. Le service, lui, refuse toujours de démarrer sans moyen de signer.
"""

import os
import subprocess
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]


def _python(code, tmp_path, **env):
    tout = {**os.environ, "SETTINGS_ENV_PATH": "/dev/null", "TRUST_DATA_DIR": str(tmp_path / "data"),
            "TRUST_PROOFS_DIR": str(tmp_path / "proofs"), "SIGNING_KEY_PATH": str(tmp_path / "absente.pem"), **env}
    return subprocess.run([sys.executable, "-c", code], cwd=RACINE, env=tout, capture_output=True, text=True,
                          timeout=120)


def test_un_script_d_administration_importe_les_cles_sans_signeur(tmp_path):
    r = _python("import trust_layer.config, trust_layer.keys, trust_layer.provisioning; print('ok')", tmp_path,
                TL_SIGNER_SOCKET=str(tmp_path / "nulle-part.sock"))
    assert r.returncode == 0 and r.stdout.strip() == "ok", r.stderr[-600:]


def test_sans_signeur_le_service_refuse_de_demarrer(tmp_path):
    code = ("from fastapi.testclient import TestClient\n"
            "from trust_layer.app import app\n"
            "with TestClient(app):\n"
            "    print('démarré')\n")
    r = _python(code, tmp_path, TL_SIGNER_SOCKET=str(tmp_path / "nulle-part.sock"))
    assert r.returncode != 0 and "démarré" not in r.stdout
    assert "tl-signer unreachable" in r.stderr, r.stderr[-600:]


def test_sans_cle_en_mode_herite_le_service_refuse_de_demarrer(tmp_path):
    code = ("from fastapi.testclient import TestClient\n"
            "from trust_layer.app import app\n"
            "with TestClient(app):\n"
            "    print('démarré')\n")
    r = _python(code, tmp_path, TL_SIGNER_SOCKET="")
    assert r.returncode != 0 and "Signing key unavailable" in r.stderr, r.stderr[-600:]


def test_get_signer_initialise_a_la_demande(tmp_path):
    """Un script qui signe vraiment (démo, réputation) obtient le signeur sans passer par le démarrage."""
    from trust_layer.crypto import generate_keypair
    cle = tmp_path / "cle.pem"
    publique = generate_keypair(cle)
    code = ("import trust_layer.config as c\n"
            "assert c.ARKFORGE_PUBLIC_KEY is None\n"
            "s = c.get_signer()\n"
            "print(c.ARKFORGE_PUBLIC_KEY)\n")
    r = _python(code, tmp_path, TL_SIGNER_SOCKET="", SIGNING_KEY_PATH=str(cle))
    assert r.returncode == 0 and r.stdout.strip() == publique, r.stderr[-600:]
