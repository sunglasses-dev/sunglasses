"""A test that MUST fail, so the merge gate can be proven rather than assumed.

A ruleset nobody has watched refuse something is a belief, not a control. This
file exists to make `certify` go red on a pull request, so we can observe
GitHub refusing the merge with our own eyes.

DELETE THIS FILE, and the branch it lives on, once the refusal is recorded.
It is a fixture for one experiment, not part of the suite.
"""


def test_this_must_fail_so_the_gate_can_be_proven():
    assert False, (
        "deliberate failure: proving the main ruleset refuses a merge when "
        "certify is red"
    )
