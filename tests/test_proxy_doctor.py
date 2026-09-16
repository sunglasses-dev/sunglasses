"""T10's doctor and install, specified from the rows before the module exists.

T10.R3 is the row that decides this slice, and it is a statement about DOUBT.
The aggregate is ROUTE_VERIFIED only when every known source is readable, every
entry in every source is WRAPPED, and every wrapped route PASSED. Anything else,
including a source we could not read, is ROUTE_UNVERIFIED with exit 3.

That asymmetry is the whole point. A config file we cannot parse is not a config
file with nothing in it, and an unknown source is not an absent one. A doctor
that reports "verified" while one of its inputs was unreadable has told an
operator their traffic is mediated on the strength of a file it never opened,
which is the most expensive sentence this tool can say.

R1's self-test carries constant-allow and constant-deny controls that must FAIL.
An instrument that cannot detect a broken detector is not evidence that the
detector works, and a self-test with no controls proves only that something ran.
"""
import json

import pytest

doctor = pytest.importorskip("sunglasses.proxy.doctor",
                             reason="the doctor is the slice being specified")


def _entry(state, passed=True):
    return doctor.Entry(name="fs", source="project", state=state, passed=passed)


# ── T10.R3: the aggregate, and what doubt does to it ──────────────────────

def test_everything_readable_wrapped_and_passing_is_verified():
    outcome = doctor.aggregate(sources_readable=True,
                               entries=[_entry(doctor.WRAPPED, passed=True)])
    assert outcome.aggregate == "ROUTE_VERIFIED"
    assert outcome.exit_code == 0


@pytest.mark.parametrize("readable,entries,why", [
    (False, [_entry(doctor.WRAPPED, True)], "a source could not be read"),
    (True, [_entry(doctor.DIRECT)], "an entry is DIRECT"),
    (True, [_entry(doctor.UNVERIFIED)], "an entry is UNVERIFIED"),
    (True, [_entry(doctor.WRAPPED, passed=False)], "a wrapped route failed"),
    (True, [_entry(doctor.WRAPPED, True), _entry(doctor.DIRECT)],
     "one good entry does not cover a bad one"),
    (True, [], "no entries at all is not proof of mediation"),
])
def test_any_doubt_at_all_makes_the_aggregate_unverified(readable, entries, why):
    """Every one of these is a way of not knowing, and not knowing is not a
    pass. The last case matters most: an empty config is not a mediated one."""
    outcome = doctor.aggregate(sources_readable=readable, entries=entries)
    assert outcome.aggregate == "ROUTE_UNVERIFIED", why
    assert outcome.exit_code == 3


def test_the_three_lines_are_reported_separately():
    """R3 says three separate lines: per-wrapper results, inventory, and ONE
    aggregate. Collapsing them loses which of the three a reader is looking at,
    and an operator needs the inventory even when the aggregate is a failure."""
    outcome = doctor.aggregate(
        sources_readable=True,
        entries=[_entry(doctor.WRAPPED, True), _entry(doctor.DIRECT)])
    assert len(outcome.per_wrapper) == 1
    assert len(outcome.inventory) == 2
    assert isinstance(outcome.aggregate, str)


def test_an_unreadable_source_is_named_in_the_inventory_not_omitted():
    """Omitting what could not be read is how an unreadable source becomes an
    absent one in a reader's mind."""
    outcome = doctor.aggregate(sources_readable=False, entries=[],
                               unreadable=["~/.claude.json"])
    assert "~/.claude.json" in json.dumps(outcome.inventory)


# ── T10.R1: an instrument that cannot fail proves nothing ─────────────────

def test_the_self_test_controls_must_fail_for_the_run_to_count():
    """R1: constant-allow and constant-deny controls that must FAIL.

    A self-test whose controls pass has shown that its checks agree with a
    detector that always says the same thing, which is exactly as much evidence
    as running nothing.
    """
    assert doctor.self_test_valid(controls={"constant_allow": "FAIL",
                                            "constant_deny": "FAIL"}) is True
    assert doctor.self_test_valid(controls={"constant_allow": "PASS",
                                            "constant_deny": "FAIL"}) is False
    assert doctor.self_test_valid(controls={"constant_deny": "FAIL"}) is False


def test_every_named_self_test_check_is_required():
    """R1 lists five. A run that skipped one and reported PASS would be
    reporting on the four it felt like doing."""
    assert doctor.SELF_TEST_CHECKS == (
        "initialized", "s1_forward_byte_equal", "s2_block_schema",
        "deadline", "disconnect")


# ── T10.R2: classification, and the wrapper that is not ours ──────────────

def test_a_wrapper_naming_a_different_artifact_is_unverified_not_wrapped():
    """R2 says a wrapper naming a DIFFERENT artifact is UNVERIFIED. It looks
    wrapped, which is precisely why it needs saying: something is mediating,
    and it is not this."""
    assert doctor.classify(command=["/other/python", "-m", "sunglasses.proxy"],
                           artifact="/ours/python",
                           artifact_sha="a" * 64) == doctor.UNVERIFIED


def test_the_artifact_is_matched_by_path_and_hash():
    assert doctor.classify(command=["/ours/python", "-m", "sunglasses.proxy"],
                           artifact="/ours/python",
                           artifact_sha="a" * 64,
                           command_sha="a" * 64) == doctor.WRAPPED
    assert doctor.classify(command=["/ours/python", "-m", "sunglasses.proxy"],
                           artifact="/ours/python",
                           artifact_sha="a" * 64,
                           command_sha="b" * 64) == doctor.UNVERIFIED


def test_an_unwrapped_server_is_direct():
    assert doctor.classify(command=["npx", "some-server"],
                           artifact="/ours/python",
                           artifact_sha="a" * 64) == doctor.DIRECT


# ── T10.R4 to R6: the install transaction ─────────────────────────────────

def test_installing_records_everything_needed_to_restore_exactly(tmp_path):
    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": {"fs": {"command": "npx",
                                                        "args": ["server"]}}}))
    record = doctor.install(config, "fs", ["python", "-m", "sunglasses.proxy"],
                            root=tmp_path)
    for field in ("original_entry", "installed_entry", "file_sha_before",
                  "file_sha_after", "original_bytes_path"):
        assert field in record
    assert pathlib_exists(record["original_bytes_path"])


def pathlib_exists(path):
    import pathlib
    return pathlib.Path(path).exists()


def test_installing_twice_is_idempotent_and_never_wraps_the_wrapper(tmp_path):
    """R4. A wrapper around a wrapper inspects its own output, which is both
    useless and a loop."""
    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": {"fs": {"command": "npx",
                                                        "args": ["server"]}}}))
    first = doctor.install(config, "fs", ["python", "-m", "sunglasses.proxy"],
                           root=tmp_path)
    second = doctor.install(config, "fs", ["python", "-m", "sunglasses.proxy"],
                            root=tmp_path)
    assert second["already_wrapped"] is True
    assert second["installed_entry"] == first["installed_entry"]
    assert json.loads(config.read_text())["mcpServers"]["fs"] == \
        first["installed_entry"]


def test_uninstall_restores_the_original_bytes_when_the_file_is_untouched(tmp_path):
    config = tmp_path / ".mcp.json"
    original = json.dumps({"mcpServers": {"fs": {"command": "npx",
                                                 "args": ["server"]}}})
    config.write_text(original)
    doctor.install(config, "fs", ["python", "-m", "sunglasses.proxy"],
                   root=tmp_path)
    outcome = doctor.uninstall(config, "fs", root=tmp_path)
    assert outcome.byte_exact is True
    assert config.read_text() == original


def test_uninstall_after_an_unrelated_edit_says_so_rather_than_clobbering(tmp_path):
    """R5. The file changed, so a byte-exact restore would throw away somebody
    else's edit. The entry is restored and the report says what it could not
    promise."""
    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": {"fs": {"command": "npx",
                                                        "args": ["server"]}}}))
    doctor.install(config, "fs", ["python", "-m", "sunglasses.proxy"],
                   root=tmp_path)
    edited = json.loads(config.read_text())
    edited["mcpServers"]["other"] = {"command": "elsewhere"}
    config.write_text(json.dumps(edited))

    outcome = doctor.uninstall(config, "fs", root=tmp_path)
    assert outcome.byte_exact is False
    assert "not byte-identical" in outcome.detail
    assert json.loads(config.read_text())["mcpServers"]["other"] == {
        "command": "elsewhere"}, "an unrelated entry was destroyed"
    assert json.loads(config.read_text())["mcpServers"]["fs"]["command"] == "npx"


def test_an_unknown_state_refuses_to_mutate_anything(tmp_path):
    """R5: unknown or conflicting state is CONFIG_CONFLICT and NO mutation.
    Guessing here edits a file we have already established we do not understand.
    """
    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": {"fs": {"command": "mystery"}}}))
    before = config.read_text()
    outcome = doctor.uninstall(config, "fs", root=tmp_path)
    assert outcome.reason == "CONFIG_CONFLICT"
    assert config.read_text() == before, "the file was mutated on a conflict"


def test_an_interrupted_write_leaves_the_original_intact(tmp_path):
    """R6. No half-written JSON, no success output, and the original still
    readable, because a config this tool corrupted is a machine that cannot
    start its servers."""
    config = tmp_path / ".mcp.json"
    original = json.dumps({"mcpServers": {"fs": {"command": "npx"}}})
    config.write_text(original)

    with pytest.raises(doctor.ConfigIOError):
        doctor.install(config, "fs", ["python", "-m", "sunglasses.proxy"],
                       root=tmp_path, fail_write=OSError("disk full"))
    assert config.read_text() == original
    json.loads(config.read_text())
