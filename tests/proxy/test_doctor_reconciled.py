"""T10.R2/R3 — the doctor, reconciled onto `sunglasses.install`.

Starting material is T8's `doctor.py` from #168 745849a, credited: `aggregate`,
`process_exit_code`, `self_test_valid`, `run`/`render` and the constants are
his, and the three rules I am not re-deriving are his too (every control that
ran must have FAILED or the run is void · a failed self-test is exit 1 whatever
the inventory says · an unreadable source is NAMED in the inventory, never
omitted).

What these tests pin is the reconciliation ruled in R-DOCTOR-OWNER and
R-DOCTOR-R3a, which is where his file and mine met and disagreed:

  1. ONE classifier. `install.classify` decides WRAPPED, not a second
     implementation. Two classifiers is a user told they are protected by the
     tool that is not protecting them.
  2. ONE artifact identity. His `artifact_identity()` returns `sys.executable`
     and hashes the INTERPRETER; `install.py` wires and hashes the proxy ENTRY
     POINT. Hashing the interpreter would call every wrapper on the machine
     WRAPPED as long as the python binary matched.
  3. ONE parser. His reader takes `json.loads` bare, so a duplicate-key config
     that `install` REFUSES would be read by the doctor as if it were fine, and
     the doctor would report on a document it had silently resolved.
  4. Exit 2 exists. R-DOCTOR-R3a: an unreadable config or record is an
     operational error, named, never 3 and never 0.
"""
import json
import pathlib

import pytest

from sunglasses import install as inst
from sunglasses.proxy import doctor

# All THREE controls, because T10.R1 requires skipped_invocation too and a run
# missing one is void. Supplying two was correct before that was pinned.
_CONTROLS = {c: "FAIL" for c in doctor.REQUIRED_CONTROLS}
_PASSING = {c: "PASS" for c in doctor.SELF_TEST_CHECKS}


@pytest.fixture
def artifact(tmp_path):
    a = tmp_path / "artifact" / "__main__.py"
    a.parent.mkdir(parents=True)
    a.write_text("# proxy entry point\n", encoding="utf-8")
    return a


@pytest.fixture
def cfg(tmp_path):
    p = tmp_path / ".mcp.json"
    p.write_text(json.dumps({"mcpServers": {
        "github": {"command": "npx", "args": ["-y", "server-github"]},
    }}, indent=2), encoding="utf-8")
    return p


@pytest.fixture
def home(tmp_path):
    return tmp_path / "sgh"


# ─────────────────────────────────────────── 1 · one classifier

def test_the_doctor_classifies_with_installs_classifier(cfg, home, artifact):
    """A route install wrapped must read WRAPPED to the doctor, and it must be
    `install.classify` that says so."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    entries, unreadable = doctor.read_sources(
        sources=[("project", cfg)], artifact=artifact)
    assert unreadable == []
    assert [(e.name, e.state) for e in entries] == [("github", "WRAPPED")]


def test_an_unwrapped_entry_reads_direct(cfg, artifact):
    entries, _ = doctor.read_sources(sources=[("project", cfg)], artifact=artifact)
    assert [(e.name, e.state) for e in entries] == [("github", "DIRECT")]


def test_the_doctor_and_install_never_disagree(cfg, home, artifact):
    """The property the ruling exists for. Whatever install.classify says about
    an entry, the doctor's inventory says the same."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    entry = json.loads(cfg.read_text())["mcpServers"]["github"]
    # the three ways a wrapper stops being ours, from #177's own controls
    for mutate in (
        lambda e: e.__setitem__("command", "/bin/echo"),
        lambda e: e.__setitem__("args", []),
        lambda e: e[inst.MARKER].__setitem__("sha256", "0" * 64),
    ):
        broken = json.loads(json.dumps(entry))
        mutate(broken)
        doc = {"mcpServers": {"github": broken}}
        cfg.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        entries, _ = doctor.read_sources(sources=[("project", cfg)], artifact=artifact)
        assert entries[0].state == inst.classify(broken, artifact=artifact)
        assert entries[0].state == "UNVERIFIED"


# ─────────────────────────────────── 2 · one artifact identity

def test_artifact_identity_is_the_proxy_entry_point_not_the_interpreter(artifact):
    """T8's version returned `sys.executable` and hashed the interpreter. Every
    wrapper on the machine runs under some python, so hashing the interpreter
    makes the hash half of "path AND hash" agree with anything that shares a
    python. The identity is the artifact `install` wires, and its hash is that
    file's bytes."""
    import hashlib, sys
    path, sha = doctor.artifact_identity(artifact)
    assert path == str(artifact)
    assert path != sys.executable
    assert sha == hashlib.sha256(artifact.read_bytes()).hexdigest()


def test_a_build_with_no_entry_point_verifies_nothing(cfg, artifact):
    """This branch HAS no proxy/__main__.py, which is the real situation and
    not an error to raise at a reader. Nothing can be WRAPPED against an
    artifact that is not there."""
    path, present = doctor.artifact_path()
    assert present is False
    assert path.name == "__main__.py"
    entries, unreadable = doctor.read_sources(sources=[("project", cfg)])
    assert unreadable == []
    assert [e.state for e in entries] == ["DIRECT"]


# ────────────────────────────────────────────── 3 · one parser

def test_a_duplicate_key_config_is_unreadable_not_quietly_resolved(tmp_path, artifact):
    """`install` refuses this document. The doctor must not read it as fine and
    report on a version of it that it resolved on the user's behalf."""
    p = tmp_path / ".mcp.json"
    p.write_bytes(b'{"mcpServers":{"a":{"command":"x"},"keep":{"command":"1"},'
                  b'"keep":{"command":"2"}}}')
    entries, unreadable = doctor.read_sources(
        sources=[("project", p)], artifact=artifact)
    assert entries == []
    assert unreadable == [str(p)]


# ──────────────────────────────────────── 4 · exit 2 exists

def test_an_unreadable_source_is_exit_2_and_names_the_file(tmp_path, artifact):
    """R-DOCTOR-R3a. Operational, never doubt, never clean."""
    p = tmp_path / ".mcp.json"
    p.write_bytes(b"{ this is not json")
    report = doctor.run(sources=[("project", p)], artifact=artifact,
                        self_test=lambda: (True, _CONTROLS, _PASSING))
    assert report.exit_code == 2
    assert str(p) in json.dumps(doctor.render(report))


def test_a_clean_direct_inventory_is_still_3_not_2(cfg, artifact):
    """Doubt and operational error must not collapse into each other either."""
    report = doctor.run(sources=[("project", cfg)], artifact=artifact,
                        self_test=lambda: (True, _CONTROLS, _PASSING))
    assert report.exit_code == 3


def test_a_failed_self_test_outranks_an_unreadable_source(tmp_path, artifact):
    """Precedence 1 > 2 > 3 > 0. T8's rule, kept: an instrument that failed has
    no standing to report on anything else."""
    p = tmp_path / ".mcp.json"
    p.write_bytes(b"{ not json")
    report = doctor.run(sources=[("project", p)], artifact=artifact,
                        self_test=lambda: (False, {}))
    assert report.exit_code == 1


# ───────────────────────────── one implementation, enforced not just intended

def test_the_doctor_defines_no_second_classifier():
    """R-DOCTOR-OWNER, as a test rather than an intention.

    The reconciliation wired `read_sources` to `install.classify` and left T8's
    original `classify` sitting in the module, unreachable from inside it but
    perfectly reachable as `doctor.classify(...)` from outside — with a
    DIFFERENT signature, which is the disagreement the ruling exists to prevent.
    Found while re-verifying against #178's modules. Dead code that contradicts
    a ruling is not dead, it is waiting.
    """
    assert not hasattr(doctor, "_is_wrapper")
    assert not hasattr(doctor, "_same_sha")
    assert getattr(doctor, "classify", None) is inst.classify


def test_the_doctor_defines_no_second_exception_family():
    """Same reason. Two `ConfigConflict` types means an `except` in one module
    silently misses the other's, which is a refusal that turns into a crash."""
    assert doctor.ConfigConflict is inst.ConfigConflict
    assert doctor.ConfigIOError is inst.ConfigIOError


# ═══════════════════════════════════════════════════════════════════════════
# Round 2. ASTRA's three blockers on 3d3ee8c (R-DOCTOR-R2). Reproduced here so
# the protection lives in the repo and not only in a reviewer's temp directory.
# Both were RED on 3d3ee8c.
#
# No skip guard on the permission row, deliberately. It requires not running as
# root, and a control that excuses itself when the environment is inconvenient
# is the shape this lane has already ruled against twice. If it ever runs as
# root it fails loudly, which is the correct outcome for a check whose premise
# is gone.
# ═══════════════════════════════════════════════════════════════════════════


def test_an_unsearchable_parent_is_named_unreadable_not_absent(cfg, artifact, tmp_path):
    """R-DOCTOR-R2(1). `Path.exists()` answers False for EACCES and ENOTDIR as
    well as for a file that is not there, so a REAL config inside a directory
    with search permission removed was reported ABSENT: never named, never
    counted unreadable, and the run exited 0 while the other source read
    WRAPPED. "I could not look" collapsed into "there was nothing to see", and
    it collapsed the safe-sounding way round, which is the one collapse R3
    exists to prevent."""
    locked = tmp_path / "locked"
    locked.mkdir()
    hidden = locked / "config.json"
    hidden.write_bytes(cfg.read_bytes())
    locked.chmod(0)
    try:
        report = doctor.run(
            sources=[("project", cfg), ("locked", hidden)], artifact=artifact,
            self_test=lambda: (True, _CONTROLS, dict(_PASSING)),
            launcher=lambda e: (True, dict(_PASSING)))
        assert report.exit_code == 2, (
            f"an unreadable source exited {report.exit_code}, not 2")
        assert any(str(hidden) == e.get("source")
                   for e in report.outcome.inventory), (
            "the file we could not read was not named in the inventory")
    finally:
        locked.chmod(0o700)


def test_a_genuinely_absent_source_is_still_absent(cfg, artifact, tmp_path):
    """The other side of the same guard, so probing by read did not turn every
    missing file into an operational error. ENOENT is the only absence."""
    report = doctor.run(
        sources=[("project", cfg), ("nowhere", tmp_path / "not-here.json")],
        artifact=artifact,
        self_test=lambda: (True, _CONTROLS, dict(_PASSING)),
        launcher=lambda e: (True, dict(_PASSING)))
    assert report.exit_code != 2, "a missing file was treated as unreadable"
    assert not any("not-here.json" in str(e.get("source", ""))
                   for e in report.outcome.inventory)


def test_the_self_tests_checks_are_not_overwritten_by_a_route(cfg, home, artifact):
    """R-DOCTOR-R2(2). The launcher loop assigned its checks to the SAME local
    that held the self-test's, so `self_test_checks` ended up holding the LAST
    route's: the rendered self-test said its deadline check PASSED while the
    failure class said DEADLINE. The exit code survived and the EVIDENCE named
    the wrong thing, which is worse than a wrong exit, because the evidence is
    the part an operator reads and acts on."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    failing = dict(_PASSING, deadline="FAIL")

    report = doctor.run(
        sources=[("project", cfg)], artifact=artifact,
        self_test=lambda: (False, _CONTROLS, failing),
        launcher=lambda e: (True, dict(_PASSING)))
    rendered = doctor.render(report)

    assert rendered["self_test"]["checks"]["deadline"] == "FAIL", (
        "the route's checks overwrote the self-test's")
    assert rendered["self_test"]["failure_class"] == "DEADLINE"
    # And the route's own checks are still reported, under the route.
    assert rendered["route_checks"], "the launcher's checks went nowhere"
    assert all(v.get("deadline") == "PASS"
               for v in rendered["route_checks"].values())
