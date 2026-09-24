"""Whether the user opted into a signed log, and the key that signs it (R21).

The user opts in with `sunglasses receipts init`, which writes the key. From
then on a key that exists but cannot sign is a receipt failure, never a quiet
return to unsigned rows: the log would stop being signed at the moment nobody
is looking. So every way the key can be unusable is named here once, with the
one command that clears it, and the hook, the proxy and `--verify` all say the
same sentence.

Answering "is there a key" imports nothing. The signing code is imported only
to load a key that is there, so an install without one never loads it.
"""
from __future__ import annotations

import pathlib

KEY_DIR = "keys"
KEY_GLOB = "receipt-*.ed25519"
EXTRA = "sunglasses[receipts]"
OFF = "sunglasses receipts off"


class KeyUnusable(Exception):
    """The user opted in and the key cannot sign. The message names the cause
    and the command that clears it; it never carries key material."""


def has_key(home) -> bool:
    return any((pathlib.Path(home) / KEY_DIR).glob(KEY_GLOB))


def signer(home):
    """The user's signer. Raises KeyUnusable, naming the cause, when the key is
    there and cannot be used, or when it is gone."""
    home = pathlib.Path(home)
    try:
        from . import keys
    except ImportError:
        raise KeyUnusable(
            f"the signing key in {home / KEY_DIR} needs {EXTRA}, which is not "
            f"installed. Install it: pip install '{EXTRA}' (or `{OFF}` to "
            f"stop signing)") from None
    path = keys.private_path(home)
    try:
        found = keys.load(home)
    except keys.KeyUnsafe:
        raise KeyUnusable(
            f"the signing key {path} is not private to you. Fix it: "
            f"chmod 600 {path} (or `{OFF}` to stop signing)") from None
    except (OSError, ValueError) as failed:
        raise KeyUnusable(
            f"the signing key {path} cannot be read ({type(failed).__name__}). "
            f"Fix it: chmod 600 {path} (or `{OFF}` to stop signing)") from None
    if found is None:
        raise KeyUnusable(
            f"the signing key is gone from {home / KEY_DIR}, and a signed log "
            f"never turns unsigned by itself. Restore the key, or run `{OFF}`")
    return found
