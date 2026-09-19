"""T10.R1 — the self-test's decision logic, and R-DOCTOR-R3b's DEADLINE class.

What these pin is the part that is pure and decidable today. The live spawn of
`python -m sunglasses.proxy` against the bundled echo server needs
`proxy/__main__.py` and `proxy/echo_server.py`, which live in #168 and land
before this does; the driver below takes them as arguments so the decision logic
is exercised now and the real artifact is a substitution, not a rewrite.

Stated plainly because #177's review said the same thing about its stand-in
artifact: NOTHING HERE PROVES PROXY STARTUP OR ROUTE ENFORCEMENT. It proves the
doctor decides correctly about results it is handed.
"""
import pytest

from sunglasses.proxy import doctor as d


PASSING = {c: "PASS" for c in d.SELF_TEST_CHECKS}
CONTROLS_OK = {"constant_allow": "FAIL", "constant_deny": "FAIL",
               "skipped_invocation": "FAIL"}


def verdict(checks=None, controls=None):
    return d.judge_self_test(dict(PASSING if checks is None else checks),
                             dict(CONTROLS_OK if controls is None else controls))


# ───────────────────────────────────────── the controls are the self-test

def test_all_checks_pass_and_all_controls_fail_is_the_only_valid_run():
    v = verdict()
    assert v.ok is True
    assert v.failed_checks == []


@pytest.mark.parametrize("control", ["constant_allow", "constant_deny",
                                     "skipped_invocation"])
def test_a_control_that_passes_voids_the_whole_run(control):
    """T8's rule, kept verbatim: a control reporting PASS means the checks
    agreed with something that always says the same thing, which is worth
    exactly as much as running nothing."""
    c = dict(CONTROLS_OK); c[control] = "PASS"
    assert verdict(controls=c).ok is False


def test_a_missing_required_control_voids_the_run():
    c = dict(CONTROLS_OK); del c["constant_allow"]
    assert verdict(controls=c).ok is False


def test_the_skipped_invocation_control_is_required_not_optional():
    """The product-level form of the defect that got nine of eighteen CLI tests
    past a process which never started. A route self-test that cannot tell
    "inspected and allowed" from "never asked" is the same bug with stakes."""
    c = dict(CONTROLS_OK); del c["skipped_invocation"]
    assert verdict(controls=c).ok is False


# ───────────────────────────────────────────── DEADLINE is its own class

def test_a_deadline_miss_is_its_own_class_not_a_schema_miss():
    """R-DOCTOR-R3b. An operator must be able to tell "the box was slow" from
    "the block came back malformed", because they are different repairs."""
    checks = dict(PASSING); checks["deadline"] = "FAIL"
    v = verdict(checks=checks)
    assert v.failed_checks == ["deadline"]
    assert v.failure_class == d.DEADLINE


def test_a_schema_miss_is_not_reported_as_a_deadline():
    checks = dict(PASSING); checks["s2_block_schema"] = "FAIL"
    v = verdict(checks=checks)
    assert v.failure_class != d.DEADLINE


def test_a_deadline_miss_is_a_real_failure_not_a_warning():
    """The bound does not move and the miss is not softened. A gate that goes
    advisory when the machine is busy is a gate nobody reads."""
    checks = dict(PASSING); checks["deadline"] = "FAIL"
    assert verdict(checks=checks).ok is False


def test_a_deadline_miss_exits_1_like_any_other_self_test_failure(tmp_path):
    cfg = tmp_path / ".mcp.json"
    cfg.write_text('{"mcpServers":{}}', encoding="utf-8")
    checks = dict(PASSING); checks["deadline"] = "FAIL"
    report = d.run(sources=[("project", cfg)],
                   self_test=lambda: (False, CONTROLS_OK, checks))
    assert report.exit_code == 1


# ──────────────────────────────── the measured figure, beside the bound

def test_the_report_prints_measured_beside_bound(tmp_path):
    """R-DOCTOR-R3b: the honesty is in the printed figure, not a softer bound.

    THIS ROW USED TO TEST THE FORMATTER ALONE, and that is why it passed while
    `deadline_line` was called by nothing, `Report` carried no measured figure
    and `render` emitted neither the measurement nor the bound. ASTRA's
    test_F2 found it by walking the AST for a caller. A control that exercises
    a helper proves the helper; it says nothing about whether the product ever
    reaches it, which is the same lesson as every other one this PR earned. It
    drives run -> render now, and the assertions are about what an operator
    actually sees."""
    cfg = tmp_path / ".mcp.json"
    cfg.write_text('{"mcpServers":{}}', encoding="utf-8")
    checks = dict(PASSING); checks["deadline"] = "FAIL"

    rendered = d.render(d.run(sources=[("project", cfg)],
                              self_test=lambda: (False, CONTROLS_OK, checks)))

    st = rendered["self_test"]
    assert st["bound_ms"] == d.DEADLINE_BOUND_MS == 2250
    assert isinstance(st["measured_ms"], int) and st["measured_ms"] >= 0
    # The line an operator reads carries BOTH numbers, not just the bound.
    assert str(st["measured_ms"]) in st["deadline"]
    assert str(d.DEADLINE_BOUND_MS) in st["deadline"]


def test_the_measured_figure_is_taken_and_not_handed_to_us(tmp_path):
    """The figure is measured around the self-test call in `run`, so a slow
    self-test shows up as a large measurement. A number the seam could supply
    would be a claim, not a measurement."""
    import time as _t
    cfg = tmp_path / ".mcp.json"
    cfg.write_text('{"mcpServers":{}}', encoding="utf-8")

    def slow():
        _t.sleep(0.05)
        return (True, CONTROLS_OK, dict(PASSING))

    rendered = d.render(d.run(sources=[("project", cfg)], self_test=slow))
    assert rendered["self_test"]["measured_ms"] >= 40, rendered["self_test"]


def test_the_bound_is_the_contracts_figure_and_is_not_configurable():
    """No env var, no argument. A bound a caller can move is not a bound."""
    import inspect
    assert "DEADLINE_BOUND_MS = 2250" in inspect.getsource(d)


# ───────────────────────────── never leak what the upstream said

def test_a_check_verdict_carrying_an_exception_string_is_dropped():
    """R3's last sentence. The way that promise breaks is a dict passed through
    whole, so both key and value are allowlisted."""
    leaked = {"deadline": "FAIL: Traceback (most recent call last): secret"}
    assert d._safe_checks(leaked) == {}
