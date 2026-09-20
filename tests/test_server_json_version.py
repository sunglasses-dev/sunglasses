"""
server.json is the FOURTH place the release version lives, and it was the only
one with no gate (beta-readiness row 6, 2026-09-20).

`__version__`, the CHANGELOG heading and the git tag are all checked by
something: the release workflow refuses a tag that does not equal
`sunglasses.__version__`, and the readiness doc gates the CHANGELOG. But
`server.json` — the MCP registry manifest — pins the version TWICE, at the top
level and inside `packages[0]`, and a search of the repo, of `.github/` and of
the ship skill found nothing that reads it, validates it or bumps it. Ship 0.6.0
without touching it and the registry entry advertises 0.5.9 against a PyPI that
serves 0.6.0.

This test makes the bump PR go red unless server.json moves with it.

`check(doc, version)` is a pure function returning a list of problems, so the
same reader can be aimed at mutated documents. The negative controls below are
what prove the reader can actually fail: a version check that cannot REACH the
field it checks passes for the wrong reason, which is worse than no check.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import sunglasses

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "server.json"


def check(doc: dict, version: str) -> list[str]:
    """Every reason `doc` is not a manifest for `version`. Empty list == good."""
    problems: list[str] = []

    top = doc.get("version")
    if top is None:
        problems.append("no top-level 'version' field at all")
    elif top != version:
        problems.append(f"top-level version={top!r}, expected {version!r}")

    packages = doc.get("packages")
    if not isinstance(packages, list) or not packages:
        # Without this the loop below runs zero times and the function returns
        # clean on a manifest that pins nothing. That is the failure mode.
        problems.append("'packages' is missing or empty, so no package version was checked")
        return problems

    pypi = [p for p in packages if p.get("registryType") == "pypi"]
    if not pypi:
        problems.append("no packages entry with registryType 'pypi'")
        return problems

    for entry in pypi:
        got = entry.get("version")
        ident = entry.get("identifier", "<no identifier>")
        if got is None:
            problems.append(f"pypi package {ident!r} has no 'version' field")
        elif got != version:
            problems.append(f"pypi package {ident!r} version={got!r}, expected {version!r}")

    return problems


def test_server_json_pins_the_version_the_package_declares():
    """THE gate: both version fields track sunglasses.__version__."""
    assert MANIFEST.is_file(), (
        f"{MANIFEST} is missing. This is a gate on that file, not an optional "
        f"extra — do not delete the manifest to make the test pass."
    )
    doc = json.loads(MANIFEST.read_text(encoding="utf-8"))
    problems = check(doc, sunglasses.__version__)
    assert not problems, (
        "server.json disagrees with sunglasses.__version__ "
        f"({sunglasses.__version__}):\n  " + "\n  ".join(problems) +
        "\n\nBumping the release means bumping server.json too: the top-level "
        "'version' AND packages[].version. Nothing else in this repo will "
        "remind you."
    )


def test_the_manifest_really_does_pin_the_version_in_two_places():
    """The premise of the gate. If the shape changes, this says so out loud."""
    doc = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert "version" in doc, "top-level version pin has gone"
    pypi = [p for p in doc.get("packages", []) if p.get("registryType") == "pypi"]
    assert len(pypi) == 1, f"expected exactly one pypi package entry, got {len(pypi)}"
    assert "version" in pypi[0], "packages[0] version pin has gone"


# --- negative controls: proof that `check` can fail, per mutation ------------
# Each row is a real way the manifest can drift. If any of these comes back
# clean, the gate above is decorative.

@pytest.mark.parametrize(
    "mutate,because",
    [
        (lambda d: d.update({"version": "0.6.0"}),
         "top-level bumped, package left behind"),
        (lambda d: d["packages"][0].update({"version": "0.6.0"}),
         "package bumped, top-level left behind"),
        (lambda d: (d.update({"version": "0.6.0"}),
                    d["packages"][0].update({"version": "0.6.0"})),
         "both bumped but __version__ was not"),
        (lambda d: d.pop("version"),
         "top-level pin deleted"),
        (lambda d: d["packages"][0].pop("version"),
         "package pin deleted"),
        (lambda d: d.update({"packages": []}),
         "packages emptied — the loop would run zero times"),
        (lambda d: d.update({"packages": [{"registryType": "npm", "version": "0.5.9"}]}),
         "the pypi entry is gone"),
    ],
)
def test_the_reader_catches_each_way_the_manifest_can_drift(mutate, because):
    doc = json.loads(MANIFEST.read_text(encoding="utf-8"))
    mutate(doc)
    problems = check(doc, sunglasses.__version__)
    assert problems, f"check() returned clean on a bad manifest: {because}"


def test_the_reader_is_clean_on_the_real_manifest_at_the_declared_version():
    """The positive control the mutations are measured against."""
    doc = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert check(doc, sunglasses.__version__) == []
