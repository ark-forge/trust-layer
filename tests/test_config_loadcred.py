"""Secrets under the Trust Layer's own user (P5a): the CEO vault arrives as systemd
credentials (LoadCredential=), since the service can no longer read ubuntu's files."""

import json
import os
import sys

FAKE_VAULT = '''
import json, os
from pathlib import Path
VAULT_FILE = Path("/nonexistent/vault.json.enc")
KEY_FILE = Path("/nonexistent/.vault_key")
class _Vault:
    def get_section(self, name):
        if os.environ.get("VAULT_MASTER_KEY") != "mk-test":
            raise PermissionError("no master key")
        return json.loads(VAULT_FILE.read_text()).get(name, {})
vault = _Vault()
'''


def test_vault_is_read_from_credentials_and_master_key_not_left_in_env(tmp_path, monkeypatch):
    import trust_layer.config as cfg
    ceo = tmp_path / "ceo" / "automation"
    ceo.mkdir(parents=True)
    (ceo / "__init__.py").write_text("")
    (ceo / "vault.py").write_text(FAKE_VAULT)
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "vault.json.enc").write_text(json.dumps({"proveit": {"challenge_hosts": "corpus.example"}}))
    (creds / "vault_key").write_text("mk-test\n")

    monkeypatch.setenv("VAULT_PATH", str(tmp_path / "ceo"))
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds))
    monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)
    monkeypatch.delenv("TRUST_LAYER_CHALLENGE_HOSTS", raising=False)
    for m in [m for m in sys.modules if m == "automation" or m.startswith("automation.")]:
        monkeypatch.delitem(sys.modules, m)
    monkeypatch.setattr(sys, "path", list(sys.path))

    cfg._load_secrets()

    assert os.environ["TRUST_LAYER_CHALLENGE_HOSTS"] == "corpus.example"
    assert "VAULT_MASTER_KEY" not in os.environ
