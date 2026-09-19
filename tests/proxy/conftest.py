"""R-168-R12. One marker, applied from outside so ASTRA's file stays verbatim.

`test_list_crossings.py` is his `list_crossings.py` byte-for-byte (sha256
checkable), and LC02 is RED on it -- but LC02 is red on b707bf2 and on cf294f5
too, so it is not a regression from this round, and T9's R-168-R12 adopted
LC01, LC03, GA01 and GA02 as the acceptance and NOT LC02.

It is marked here rather than edited out of his file, and marked STRICT, so it
stays visible and turns into a demand the moment somebody makes it pass.
LC02 asks whether a completed list's id may be admitted again from inside the
client sink; its first assertion is `admitted == [True]` and the reuse is
currently rejected. Whether that is a defect or the intended rule is T9's to
rule, and it is disclosed in the body rather than hidden behind a passing suite.
"""
import pytest

_XFAIL = {
    "test_LC02_list_reuse_at_sink": (
        "R-168-R12: pre-existing on b707bf2 and cf294f5, NOT adopted into the "
        "R-168-R12 acceptance (LC01, LC03, GA01, GA02). Completed-list id reuse "
        "from inside the sink is currently rejected; ruling owed."),
}


def pytest_collection_modifyitems(items):
    for item in items:
        for name, reason in _XFAIL.items():
            if item.name.startswith(name):
                item.add_marker(pytest.mark.xfail(strict=True, reason=reason))
