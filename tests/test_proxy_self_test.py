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
