"""Ninth round on the PDF containers: every entry of an array is paid for before it is read.

Review of the eighth round found that two walks paid for what they kept and not for what
they looked at:

* an action array (and an action table) resolved and queued every entry before the action
  cap or the document budget was asked, so twenty thousand entries cost twenty thousand
  resolutions after the budget was spent;
* a value array skipped the charge and the member count for an entry it had seen before, and
  copied the whole array before the first check, so twenty thousand repeats of one entry
  cost nothing.
"""
import pytest

from sunglasses.extractors.pdf import PDFExtractor

ENTRIES = 20_000
LEFT = 64   # bytes of the document budget left to the walk under test


class _Counted:
    """An object that counts how often it is resolved."""
    resolutions = 0

    def __init__(self, target):
        self._target = target

    def get_object(self):
        type(self).resolutions += 1
        return self._target


@pytest.fixture(autouse=True)
def _reset():
    _Counted.resolutions = 0


def _spent_extractor(left=LEFT):
    extractor = PDFExtractor()
    extractor.failures = []
    extractor.budget.read = extractor.budget.MAX_BYTES - left
    return extractor


def _action():
    return {"/S": "/JavaScript", "/JS": "app.alert(1)"}


def test_an_action_array_is_not_resolved_past_the_budget():
    extractor = _spent_extractor()
    shared = _Counted(_action())
    extractor._scripts_in([shared] * ENTRIES, "document")
    assert _Counted.resolutions <= 8, _Counted.resolutions
    assert any("limit" in f and "not inspected" in f for f in extractor.failures), extractor.failures


def test_an_action_table_is_not_walked_past_the_budget():
    extractor = _spent_extractor()
    table = {f"/K{i}": _Counted(_action()) for i in range(ENTRIES)}
    extractor._scripts_in(table, "document", table=True)
    assert _Counted.resolutions <= 8, _Counted.resolutions
    assert any("limit" in f and "not inspected" in f for f in extractor.failures), extractor.failures


def test_every_entry_of_an_action_array_is_charged_whatever_it_holds():
    extractor = PDFExtractor()
    extractor.failures = []
    before = extractor.budget.read
    extractor._scripts_in([_Counted(None)] * 100, "document")
    assert extractor.budget.read - before >= 100 * PDFExtractor.VISIT_COST


def test_an_action_array_within_the_budget_is_still_read():
    extractor = PDFExtractor()
    extractor.failures = []
    found = extractor._scripts_in([_Counted(_action())], "document")
    assert found == [("javascript:document", "app.alert(1)")]


class _NoIter(list):
    def __iter__(self):
        raise AssertionError("the whole array was copied before its first check")


def test_a_value_array_is_not_copied_before_it_is_checked():
    extractor = PDFExtractor()
    extractor.failures = []
    assert sorted(extractor._as_text(_NoIter(["a", "b", "c"])).split()) == ["a", "b", "c"]


def test_repeats_of_one_entry_are_charged_and_counted():
    extractor = PDFExtractor()
    extractor.failures = []
    shared = "same"
    extractor._as_text([shared] * (PDFExtractor.MAX_ARRAY_MEMBERS + 10))
    assert any(f"more than {PDFExtractor.MAX_ARRAY_MEMBERS} members" in f for f in extractor.failures), \
        extractor.failures


def test_repeats_of_one_entry_stop_at_the_budget():
    extractor = _spent_extractor()
    seen = {"n": 0}
    real = PDFExtractor._identity

    def counted(obj):
        seen["n"] += 1
        return real(obj)

    PDFExtractor._identity = staticmethod(counted)
    try:
        extractor._as_text(["same"] * ENTRIES)
    finally:
        PDFExtractor._identity = staticmethod(real)
    assert seen["n"] <= 8, seen["n"]
    assert any("limit" in f and "not inspected" in f for f in extractor.failures), extractor.failures


def test_a_shared_member_is_still_read_once():
    extractor = PDFExtractor()
    extractor.failures = []
    text = extractor._as_text(["alpha", "beta", "alpha"])
    assert text == "alpha beta"


def test_a_document_with_an_action_array_of_repeats_pays_for_every_entry(tmp_path):
    from test_pdf_containers import Doc

    d = Doc()
    n = d.add(b"<< /S /JavaScript /JS (app.alert(1)) >>")
    d.catalog_extra = b"/OpenAction [" + b" ".join(f"{n} 0 R".encode() for _ in range(ENTRIES)) + b"]"
    path = tmp_path / "repeats.pdf"
    path.write_bytes(d.build())
    extractor = PDFExtractor()
    extractor.extract(str(path))
    assert extractor.budget.read >= ENTRIES * PDFExtractor.VISIT_COST
