"""The user's key (T9 RULING 11 Q2): made only by an explicit `init`, stored
0600 in 0700, public halves append-only, and no key of ours in the package."""
import os
import pathlib
import stat
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import keys                                                # noqa: E402
import wire                                                # noqa: E402


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_init_makes_one_key_with_owner_only_modes(tmp_path):
    fp = keys.init(tmp_path)
    private = keys.private_path(tmp_path)
    assert private.name == f"receipt-{fp[:16]}.ed25519"
    assert _mode(private) == 0o600
    assert _mode(private.parent) == 0o700
    public = keys.public_path(tmp_path, fp)
    assert wire.key_fingerprint(public.read_bytes()) == fp


def test_the_loaded_signer_is_the_key_init_made(tmp_path):
    fp = keys.init(tmp_path)
    signer = keys.load(tmp_path)
    assert signer.fingerprint == fp
    message = b"sunglasses"
    keys.public_key(tmp_path, fp).verify(signer.sign(message), message)


def test_no_key_means_no_signer_and_nothing_is_made(tmp_path):
    """Never implicitly on first write: loading never creates."""
    assert keys.load(tmp_path) is None
    assert not (tmp_path / "keys").exists()


def test_init_refuses_when_a_key_exists(tmp_path):
    keys.init(tmp_path)
    before = keys.private_path(tmp_path).read_bytes()
    with pytest.raises(keys.KeyExists):
        keys.init(tmp_path)
    assert keys.private_path(tmp_path).read_bytes() == before


def test_a_private_key_readable_by_others_is_refused(tmp_path):
    keys.init(tmp_path)
    os.chmod(keys.private_path(tmp_path), 0o644)
    with pytest.raises(keys.KeyUnsafe):
        keys.load(tmp_path)


def test_a_public_key_is_never_overwritten(tmp_path):
    fp = keys.init(tmp_path)
    public = keys.public_path(tmp_path, fp)
    with pytest.raises(keys.KeyExists):
        keys.write_public(tmp_path, b"\x00" * 32, fingerprint=fp)
    assert wire.key_fingerprint(public.read_bytes()) == fp


def test_two_homes_get_two_keys(tmp_path):
    assert keys.init(tmp_path / "a") != keys.init(tmp_path / "b")


def test_no_key_of_ours_ships_in_the_package():
    """Q2: the package carries no private key and no hardcoded seed except the
    published TEST seed the vectors are made from."""
    package = HERE.parent.parent
    assert not [p for p in package.rglob("*.ed25519")]
    seeds = [p for p in package.rglob("*.py")
             if "from_private_bytes(" in p.read_text(encoding="utf-8")
             and p.name not in {"keys.py", "make_vectors.py"}
             and "tests" not in p.parts]
    assert seeds == [], seeds
