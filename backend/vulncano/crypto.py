import base64
import hashlib
import json
import secrets

from cryptography.fernet import Fernet, InvalidToken

from .config import get_settings

TOKEN_PREFIX = "vlc_"


class SecretKeyMissing(RuntimeError):
    pass


def _fernet() -> Fernet:
    key = get_settings().secret_key
    if not key:
        raise SecretKeyMissing(
            "VULNCANO_SECRET_KEY is not set, so scanner credentials cannot be stored. "
            "Generate one with: python -c \"import secrets;print(secrets.token_urlsafe(32))\""
        )
    digest = hashlib.sha256(key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_config(config: dict) -> str:
    return _fernet().encrypt(json.dumps(config).encode()).decode()


def decrypt_config(blob: str) -> dict:
    if not blob:
        return {}
    try:
        return json.loads(_fernet().decrypt(blob.encode()).decode())
    except InvalidToken as exc:
        raise ValueError(
            "stored scanner credentials cannot be decrypted, VULNCANO_SECRET_KEY changed since they were saved"
        ) from exc


def new_api_token() -> tuple[str, str, str]:
    """Return (plaintext token, prefix shown in the UI, sha256 hash stored in the database)."""
    raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
    return raw, raw[:12], hash_api_token(raw)


def hash_api_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()
