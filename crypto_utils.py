"""Encrypts secrets that must live in the database (per-server monitoring
passwords, the SMTP password) instead of in-memory-only like the personal SSH
passwords users type in each session -- the background alert checker has no
user session to borrow a password from, so it needs something durable, and
"durable" for a password means "encrypted at rest", never plaintext.

The one secret this can't itself protect is CRED_ENCRYPTION_KEY -- it has to
live in the environment (same as SECRET_KEY already does), generated once:

    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Everything downstream of that one bootstrap key (SMTP settings, per-server
monitoring credentials, recipients, thresholds) is stored in the database and
editable live from the Alerts settings page -- no redeploy needed to change
any of it.
"""

import os

from cryptography.fernet import Fernet, InvalidToken

_KEY = os.environ.get("CRED_ENCRYPTION_KEY")
_fernet = Fernet(_KEY.encode()) if _KEY else None


def encryption_available():
    return _fernet is not None


def encrypt(plaintext):
    """Returns None for empty input (so callers can store NULL instead of an
    encrypted empty string). Raises RuntimeError if no key is configured --
    callers should check encryption_available() first to fail with a clearer
    message than this."""
    if not plaintext:
        return None
    if _fernet is None:
        raise RuntimeError(
            "CRED_ENCRYPTION_KEY is not set -- cannot store credentials securely. "
            "Generate one and set it as an environment variable before saving "
            "monitoring credentials or SMTP passwords."
        )
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext):
    if not ciphertext:
        return None
    if _fernet is None:
        raise RuntimeError("CRED_ENCRYPTION_KEY is not set -- cannot decrypt stored credentials.")
    try:
        return _fernet.decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        # Most likely CRED_ENCRYPTION_KEY changed since this was saved.
        raise RuntimeError("Stored credential could not be decrypted -- CRED_ENCRYPTION_KEY may have changed.")
