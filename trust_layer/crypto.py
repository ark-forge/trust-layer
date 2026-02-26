"""Ed25519 signing for ArkForge proof origin authentication."""

import base64
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url decode, adding back padding."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def generate_keypair(path: Path) -> str:
    """Generate Ed25519 keypair, save private key to path. Returns public key string.

    Only call once at deployment. Raises if file already exists.
    """
    if path.exists():
        raise FileExistsError(f"Signing key already exists at {path}")

    private_key = Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    path.chmod(0o600)

    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return f"ed25519:{_b64url_encode(pub_bytes)}"


def load_signing_key(path: Path) -> Ed25519PrivateKey:
    """Load Ed25519 private key from PEM file. Raises RuntimeError if absent."""
    if not path.exists():
        raise RuntimeError(
            f"Signing key not found at {path}. "
            "Generate one with: python -m trust_layer.crypto"
        )
    pem_data = path.read_bytes()
    private_key = serialization.load_pem_private_key(pem_data, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise RuntimeError(f"Key at {path} is not Ed25519")
    return private_key


def sign_proof(private_key: Ed25519PrivateKey, chain_hash_hex: str) -> str:
    """Sign chain hash with Ed25519. Returns 'ed25519:<base64url_64bytes>'."""
    signature = private_key.sign(chain_hash_hex.encode("utf-8"))
    return f"ed25519:{_b64url_encode(signature)}"


def verify_proof_signature(pubkey_str: str, chain_hash_hex: str, sig_str: str) -> bool:
    """Verify Ed25519 signature. Returns True if valid, False otherwise."""
    try:
        if not pubkey_str.startswith("ed25519:"):
            return False
        if not sig_str.startswith("ed25519:"):
            return False

        pub_bytes = _b64url_decode(pubkey_str[len("ed25519:"):])
        sig_bytes = _b64url_decode(sig_str[len("ed25519:"):])

        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        public_key.verify(sig_bytes, chain_hash_hex.encode("utf-8"))
        return True
    except Exception:
        return False


def get_public_key_b64url(private_key: Ed25519PrivateKey) -> str:
    """Extract public key string from private key: 'ed25519:<base64url_43chars>'."""
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return f"ed25519:{_b64url_encode(pub_bytes)}"


if __name__ == "__main__":
    import sys
    key_path = Path(__file__).parent / ".signing_key.pem"
    if "--force" in sys.argv and key_path.exists():
        key_path.unlink()
    pubkey = generate_keypair(key_path)
    print(f"Keypair generated. Public key:\n{pubkey}")
    print(f"Private key saved to: {key_path}")
