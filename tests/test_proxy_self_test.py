"""T10.R1's LIVE self test, specified before it exists.

`doctor.run()` has reported SELF_TEST_UNAVAILABLE since the doctor was written,
because R1's self test spawns the installed artifact and there was nothing to
spawn. There is now, so this is the check that makes `sunglasses proxy doctor`
mean something.

The measurement is the one that matters and it is taken on the FAR SIDE. The
self test sends one protected call through the artifact to the bundled echo
server and then reads the server's own ingress file. PASS requires the payload
to be ABSENT there. Asking the proxy whether it withheld something is asking
the defendant, and a self test that grades itself is the instrument this whole
lane exists to refuse.

R1's controls are why the run counts at all. constant-allow, constant-deny and
skipped-invocation must each FAIL, because an instrument that cannot notice a
broken detector is not evidence that the detector works.
"""
import json
import pathlib
import sys

import pytest

from sunglasses.proxy import doctor

pytestmark = pytest.mark.skipif(
    not hasattr(doctor, "live_self_test"),
    reason="the live self test is the slice being specified")


def test_the_self_test_passes_against_the_real_artifact(tmp_path):
    """End to end, spawning the artifact, through real pipes."""
    ok, checks = doctor.live_self_test(root=tmp_path)
    assert ok is True, checks
    assert set(checks) >= set(doctor.SELF_TEST_CHECKS)
    for name in doctor.SELF_TEST_CHECKS:
        assert checks[name] == "PASS", f"{name} did not pass: {checks}"


def test_the_run_is_valid_and_its_controls_all_failed(tmp_path):
    ok, _checks = doctor.live_self_test(root=tmp_path)
    controls = doctor.last_controls()
    assert ok is True
    assert doctor.self_test_valid(controls) is True
    for name, verdict in controls.items():
        assert verdict == "FAIL", f"control {name} did not fail: {controls}"


def test_the_protected_payload_is_absent_from_the_servers_own_ingress(tmp_path):
    """The reading this is all for. It is taken from the file the SERVER
    writes, on the other side of the thing being measured."""
    _ok, checks = doctor.live_self_test(root=tmp_path, keep=True)
    ingress = (tmp_path / "selftest.ingress").read_bytes()
    assert ingress, "the instrument never ran"
    assert doctor.SELF_TEST_SECRET.encode() not in ingress
    assert checks["s2_block_schema"] == "PASS"


def test_a_clean_call_does_reach_the_server_byte_for_byte(tmp_path):
    """S1's half. Without it the self test passes against a proxy that blocks
    everything, which is a mediator nobody can use and an instrument that
    cannot tell that apart."""
    _ok, checks = doctor.live_self_test(root=tmp_path, keep=True)
    ingress = (tmp_path / "selftest.ingress").read_bytes()
    assert doctor.SELF_TEST_CLEAN.encode() in ingress
    assert checks["s1_forward_byte_equal"] == "PASS"


def test_the_doctor_reports_the_self_test_instead_of_unavailable(tmp_path):
    """The whole point: `sunglasses proxy doctor` now says something it
    measured rather than that it could not measure anything."""
    report = doctor.run(sources=[], root=tmp_path)
    assert report.self_test_ok is True
    assert report.self_test_detail != doctor.SELF_TEST_UNAVAILABLE


def test_the_block_check_reads_the_envelope_and_not_just_the_absence(tmp_path):
    """R1 names the T4.R7 schema. A refusal that arrives with the wrong shape
    is a refusal the client cannot act on, and absence alone would pass
    against a proxy that dropped the call on the floor."""
    _ok, checks = doctor.live_self_test(root=tmp_path, keep=True)
    envelope = json.loads((tmp_path / "selftest.envelope").read_text())
    assert envelope["error"]["message"] == "SUNGLASSES_WITHHELD"
    assert envelope["error"]["data"]["reason_code"] == "PROHIBITED_SECRET"
    assert checks["s2_block_schema"] == "PASS"


# ── the instrument has to be able to fail ────────────────────────────────
#
# Every test above asserts PASS against a working proxy, and a mutation that
# simply removes a check still passes those, because the real system genuinely
# passes. Eight mutations of the self test survived on exactly that. The fix is
# the lane's own rule, applied to the instrument: ship a check only after
# seeing it fail.

FAKES = str(pathlib.Path(__file__).resolve().parent / "fakes")


def _fake(name):
    return [sys.executable, str(pathlib.Path(FAKES) / name)]


def test_it_fails_against_a_proxy_that_mediates_nothing(tmp_path):
    """The protected payload reaches the server. Any self test that still says
    PASS is measuring nothing."""
    ok, checks = doctor.live_self_test(root=tmp_path, keep=True,
                                       proxy_argv=_fake("passthrough_proxy.py"))
    assert ok is False
    assert checks["s2_block_schema"] == "FAIL"
    assert doctor.SELF_TEST_SECRET.encode() in \
        (tmp_path / "selftest.ingress").read_bytes()


def test_it_fails_against_a_proxy_that_forwards_nothing(tmp_path):
    """The other half. A mediator that blocks everything is unusable, and an
    instrument that calls it healthy cannot tell the two failures apart."""
    ok, checks = doctor.live_self_test(root=tmp_path,
                                       proxy_argv=_fake("blocking_proxy.py"))
    assert ok is False
    assert checks["s1_forward_byte_equal"] == "FAIL"


def test_the_controls_trip_when_the_instrument_is_broken(tmp_path):
    """R1's controls are graded against the same reading the checks use, so a
    passthrough proxy must make constant_allow PASS, which invalidates the
    whole run."""
    doctor.live_self_test(root=tmp_path,
                          proxy_argv=_fake("passthrough_proxy.py"))
    controls = doctor.last_controls()
    assert controls["constant_allow"] == "PASS"
    assert doctor.self_test_valid(controls) is False


def test_it_fails_against_a_proxy_that_lies_about_withholding(tmp_path):
    """The case the far-side reading exists for, and the only one that proves
    the self test is not grading itself. This proxy returns a correctly shaped
    SUNGLASSES_WITHHELD envelope AND forwards every byte anyway."""
    ok, checks = doctor.live_self_test(root=tmp_path, keep=True,
                                       proxy_argv=_fake("lying_proxy.py"))
    envelope = json.loads((tmp_path / "selftest.envelope").read_text())
    assert envelope["error"]["data"]["reason_code"] == "PROHIBITED_SECRET", \
        "the liar did not produce a convincing reply, so this proves nothing"
    assert doctor.SELF_TEST_SECRET.encode() in \
        (tmp_path / "selftest.ingress").read_bytes()
    assert checks["s2_block_schema"] == "FAIL", "the reply was believed"
    assert ok is False


def test_it_fails_against_a_proxy_that_drops_without_answering(tmp_path):
    """Absence alone is not enough. The payload never reaches the server here
    and the client is left with no answer, which T6.R1 calls a hang."""
    ok, checks = doctor.live_self_test(root=tmp_path, keep=True,
                                       proxy_argv=_fake("silent_drop_proxy.py"))
    assert doctor.SELF_TEST_SECRET.encode() not in \
        (tmp_path / "selftest.ingress").read_bytes()
    assert checks["s2_block_schema"] == "FAIL"
    assert ok is False


def test_the_deadline_check_fails_when_the_worker_answers_in_time(tmp_path):
    """A check that has never been seen to fail is not a check."""
    prompt = [sys.executable, "-c",
              "import sys,json;sys.stdin.read();print(json.dumps({}))"]
    _ok, checks = doctor.live_self_test(root=tmp_path, worker_argv=prompt)
    assert checks["deadline"] == "FAIL"


def test_a_self_test_that_cannot_run_reports_failure_not_a_pass(monkeypatch):
    """default_self_test swallows the exception on purpose, and the one thing
    it must never swallow it into is a PASS."""
    def explode(*_a, **_kw):
        raise RuntimeError("the artifact is not installed")

    monkeypatch.setattr(doctor, "live_self_test", explode)
    ok, checks = doctor.default_self_test()
    assert ok is False
    assert set(checks.values()) == {"FAIL"}
