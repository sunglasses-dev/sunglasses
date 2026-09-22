"""The published attack-db must equal what the exporter produces from patterns.py.

`attack-db/` is a GENERATED mirror: `scripts/export_patterns_to_attack_db.py`
reads `sunglasses/patterns.py` and writes one JSON per rule. Nothing enforced
that the committed mirror was ever regenerated, so a pattern edit that landed
without a re-export left the PUBLISHED attack database disagreeing with the
SHIPPED scanner, silently and for as long as nobody happened to run the
exporter.

That is not hypothetical. This test was written red: on `eab0299` it failed on
`GLS-ENC-ALT-210`, whose committed mirror was missing the
`(?<![A-Za-z0-9+/])` lookbehind that `patterns.py` has carried since the
ratio-gate work. Anyone reading attack-db to reproduce our detection would
have built the wrong regex.

THE JSON IS THE SITUATION, THIS FILE IS THE FIX. Re-exporting once closes
today's drift; only an assertion keeps it closed.

WHY THE COMPARISON EXCLUDES ONE FIELD, AND ONLY ONE. `manifest.json` carries
`generated_at`, a wall-clock stamp that differs on every run. A test that
compared it would fail on days rather than on defects, so it is dropped from
the manifest comparison and nothing else is. The per-rule files carry no clock:
the exporter preserves an existing file's `date_added` and stamps today's only
on a genuinely new rule, so a re-export of an unchanged rule is byte-identical.
"""
import collections
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
COMMITTED = ROOT / "attack-db"


@pytest.fixture(scope="module")
def fresh_export():
    """Run the real exporter into a throwaway copy of the tree.

    A copy rather than a re-implementation: the point is to compare against
    what the shipped script actually produces, so a change to the exporter is
    caught too. `attack-db` is copied in because the exporter reads each
    existing file to preserve its `date_added`.
    """
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        for part in ("sunglasses", "scripts", "attack-db"):
            shutil.copytree(ROOT / part, tmp / part,
                            ignore=shutil.ignore_patterns("__pycache__"))
        proc = subprocess.run(
            [sys.executable, str(tmp / "scripts" / "export_patterns_to_attack_db.py")],
            cwd=tmp, capture_output=True, text=True)
        assert proc.returncode == 0, (
            f"the exporter itself failed, so this test measured nothing:\n"
            f"{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}")
        yield tmp / "attack-db"


def _rule_files(root):
    return {p.relative_to(root).as_posix()
            for p in root.rglob("*.json") if p.name != "manifest.json"}


def test_every_rule_file_is_present_in_both(fresh_export):
    committed, fresh = _rule_files(COMMITTED), _rule_files(fresh_export)
    assert committed == fresh, (
        f"the mirror's FILE SET is stale.\n"
        f"  in patterns.py but not committed: {sorted(fresh - committed)[:10]}\n"
        f"  committed but no longer a rule  : {sorted(committed - fresh)[:10]}\n"
        f"Run scripts/export_patterns_to_attack_db.py and commit the result.")


def test_every_rule_file_matches_a_fresh_export(fresh_export):
    """Byte-for-byte, every rule. This is the assertion that keeps it closed."""
    drifted = []
    for rel in sorted(_rule_files(COMMITTED) & _rule_files(fresh_export)):
        a = (COMMITTED / rel).read_bytes()
        b = (fresh_export / rel).read_bytes()
        if a == b:
            continue
        try:
            ja, jb = json.loads(a), json.loads(b)
            fields = sorted(k for k in set(ja) | set(jb) if ja.get(k) != jb.get(k))
        except json.JSONDecodeError:
            fields = ["<unparseable>"]
        drifted.append((rel, fields))
    assert not drifted, (
        "the committed attack-db disagrees with a fresh export, so the "
        "PUBLISHED attack database does not describe the SHIPPED scanner:\n  "
        + "\n  ".join(f"{rel}  fields: {fields}" for rel, fields in drifted)
        + "\nRun scripts/export_patterns_to_attack_db.py and commit the result.")


def test_the_manifest_matches_apart_from_its_clock(fresh_export):
    a = json.loads((COMMITTED / "manifest.json").read_text())
    b = json.loads((fresh_export / "manifest.json").read_text())
    a.pop("generated_at", None)
    b.pop("generated_at", None)
    assert a == b, (
        f"attack-db/manifest.json is stale (ignoring generated_at).\n"
        f"  committed: {a}\n  fresh    : {b}")


def test_the_clock_field_is_the_only_thing_excluded():
    """A guard on the exclusion itself.

    If the exporter ever adds a second volatile field, the test above would
    start failing on days rather than defects, and the temptation would be to
    exclude that one too. This fails first and names it, so the decision is
    taken deliberately.

    It earned that on its first run: it named `generator`, a key the author had
    not accounted for. That one is a constant string, so it stays INSIDE the
    comparison and only the expected shape changed. `generated_at` is still the
    only field excluded from anything.
    """
    keys = set(json.loads((COMMITTED / "manifest.json").read_text()))
    assert keys == {"generated_at", "source", "total_patterns", "categories",
                    "generator"}, (
        f"attack-db/manifest.json's shape changed: {sorted(keys)}. Decide "
        f"whether the new field is deterministic before widening the "
        f"exclusion in test_the_manifest_matches_apart_from_its_clock.")


def _mirrored_by_rule_id(root):
    """rule id -> the files describing it, read from the files themselves."""
    by = collections.defaultdict(list)
    for path in sorted(root.rglob("*.json")):
        if path.name == "manifest.json":
            continue
        try:
            doc = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        rule_id = doc.get("rule_id") or doc.get("id")
        if rule_id:
            by[rule_id].append(path.relative_to(root).as_posix())
    return by


def test_no_rule_is_described_by_more_than_one_file():
    """The direction the file-set comparison above CANNOT report.

    `test_every_rule_file_is_present_in_both` prints two differences, and the
    second one -- "committed but no longer a rule" -- can never be non-empty.
    `fresh_export` COPIES the committed tree before running the exporter, which
    it has to, because the exporter reads each existing file to preserve
    `date_added`; and the exporter only ever writes. So anything stale in the
    committed tree is also in the "fresh" one and the difference is empty by
    construction. The message promises a direction the fixture forbids.

    That is not theoretical. A mirror FILENAME is derived from the rule's NAME,
    so shortening seven sibling names to fit the 60-character cap produced seven
    new files and left the seven old ones in place -- the published mirror
    described each of those rules TWICE, under two different names, and parity
    stayed green.

    This guard is deliberately NARROW: one rule, one file. It does not ask
    whether every file corresponds to a rule, because that question has a
    different and much larger answer -- an export into an EMPTY tree reproduces
    1568 of the 1599 committed files, and the 24 GHSA-family leftovers are a
    decision about published data rather than something a test should delete on
    someone's behalf.
    """
    duplicated = {rule_id: files
                  for rule_id, files in _mirrored_by_rule_id(COMMITTED).items()
                  if len(files) > 1}
    assert duplicated == {}, (
        "the published mirror describes these rules more than once, which "
        "usually means a rule was RENAMED and the old file was left behind "
        "(the filename is derived from the name, and the exporter only adds):\n  "
        + "\n  ".join(f"{rule_id}: {files}" for rule_id, files in
                      sorted(duplicated.items()))
        + "\nDelete the stale file and re-run "
          "scripts/export_patterns_to_attack_db.py.")


def test_the_duplicate_reader_can_actually_see_a_duplicate(tmp_path):
    """The control. Build the artefact, watch the reader name it.

    Without it, a reader that returned `{}` for every input -- a bad glob, a
    key that is not `rule_id`, a parse error swallowed -- would pass the row
    above on a mirror that was full of duplicates.
    """
    (tmp_path / "a.json").write_text(json.dumps({"rule_id": "GLS-CONTROL-1"}))
    (tmp_path / "b.json").write_text(json.dumps({"rule_id": "GLS-CONTROL-1"}))
    (tmp_path / "c.json").write_text(json.dumps({"rule_id": "GLS-CONTROL-2"}))
    seen = _mirrored_by_rule_id(tmp_path)
    assert sorted(seen["GLS-CONTROL-1"]) == ["a.json", "b.json"], seen
    assert seen["GLS-CONTROL-2"] == ["c.json"], seen
    # And it must read the REAL mirror, not an empty set, or the row above is
    # green because it measured nothing.
    assert len(_mirrored_by_rule_id(COMMITTED)) > 1000
