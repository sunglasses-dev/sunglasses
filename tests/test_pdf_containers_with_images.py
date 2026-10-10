"""The container walk and the image only page check share one document budget.

The picture walk charges the decoded content of every page it visits. It runs after every other
check, so a large page content cannot leave the page tree, the annotations, the form values or the
attachments without budget.
"""
import pytest

from test_pdf_containers import Doc

pytest.importorskip("PyPDF2")

from sunglasses.extractors import pdf as pdf_module
from sunglasses.extractors.pdf import PDFExtractor


def test_the_picture_walk_runs_after_every_other_check(tmp_path, monkeypatch):
    order = []
    for name in ("_extract_annotations", "_extract_form_fields", "_extract_document_scripts",
                 "_extract_outlines", "_extract_associated_files", "_extract_page_extras",
                 "_extract_attachments"):
        real = getattr(PDFExtractor, name)
        monkeypatch.setattr(PDFExtractor, name,
                            lambda self, *a, _n=name, _r=real, **k: order.append(_n) or _r(self, *a, **k))
    real_count = pdf_module._ImageWalk._count
    monkeypatch.setattr(pdf_module._ImageWalk, "_count",
                        lambda self, *a, **k: order.append("pictures") or real_count(self, *a, **k))
    path = tmp_path / "plain.pdf"
    path.write_bytes(Doc().build())
    PDFExtractor().extract(str(path))
    assert "pictures" in order and "_extract_attachments" in order
    assert order.index("pictures") > max(i for i, n in enumerate(order) if n != "pictures"), order


def test_both_walks_use_one_visit_cost():
    assert pdf_module._ImageWalk.VISIT_COST == PDFExtractor.VISIT_COST == pdf_module._VISIT_COST


# A content stream that is decoded and then refused is still paid for.
import zlib


class _ContentStream(dict):
    def __init__(self, payload, extra):
        super().__init__(extra)
        self._data = zlib.compress(payload)

    def get_data(self):  # the walk must never call the reader's own decode
        raise AssertionError("the reader's decode was used")


def _walk():
    return pdf_module._ImageWalk(pdf_module._ReadBudget())


@pytest.mark.parametrize("state,extra,entries", [
    ("unsized", {"/Filter": ["/FlateDecode", "/RunLengthDecode"]}, 2),
    ("error", {"/Filter": ["/FlateDecode"], "/DecodeParms": {"/Predictor": 99}}, 1),
])
def test_a_refused_content_chain_is_charged_for_the_stages_it_decoded(state, extra, entries):
    walk = _walk()
    stream = _ContentStream(b"\x00" * 100_000, extra)
    with pytest.raises(ValueError):
        walk._content(stream)
    # The stream's own Flate input, the stages that were decoded, plus one visit for each entry
    # of the filter list.
    assert walk.budget.read == len(stream._data) + 100_000 + entries * walk.VISIT_COST, state


@pytest.mark.parametrize("extra", [
    {"/Filter": ["/FlateDecode", "/RunLengthDecode"]},
    {"/Filter": ["/FlateDecode"], "/DecodeParms": {"/Predictor": 99}},
])
def test_the_same_refused_chain_on_many_pages_exhausts_the_shared_budget(extra):
    walk = _walk()
    stopped_at = None
    for page in range(200):
        try:
            walk._content(_ContentStream(b"\x00" * (1 << 20), extra))
        except ValueError:
            continue
        except pdf_module._WalkBudget:
            stopped_at = page
            break
    assert stopped_at is not None and stopped_at <= 65, stopped_at


# A content array is paid for entry by entry: one holder visit does not cover its streams.
class _Entry:
    """An array entry that counts how often it is resolved."""
    resolutions = 0

    def __init__(self, stream):
        self._stream = stream

    def get_object(self):
        type(self).resolutions += 1
        return self._stream


def _empty_stream():
    return _ContentStream(b"", {"/Filter": ["/FlateDecode"]})


def _decode_counter(monkeypatch):
    calls = {"n": 0}
    real = pdf_module._decode_bounded

    def counted(*args, **kwargs):
        calls["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(pdf_module, "_decode_bounded", counted)
    return calls


def test_a_content_array_of_empty_streams_stops_when_the_allowance_is_gone(monkeypatch):
    _Entry.resolutions = 0
    calls = _decode_counter(monkeypatch)
    walk = _walk()
    walk.budget.read = walk.budget.MAX_BYTES - 32
    holder = {"/Contents": [_Entry(_empty_stream()) for _ in range(20_000)]}
    with pytest.raises(pdf_module._WalkBudget):
        walk._content(holder)
    assert calls["n"] <= 2, calls["n"]
    assert _Entry.resolutions <= 3, _Entry.resolutions


def test_every_entry_of_a_content_array_is_charged_even_when_it_decodes_to_nothing():
    walk = _walk()
    holder = {"/Contents": [_empty_stream() for _ in range(100)]}
    assert walk._content(holder) == b"\n".join([b""] * 100)
    assert walk.budget.read >= 100 * walk.VISIT_COST


def test_a_single_content_stream_is_not_charged_twice():
    walk = _walk()
    # Each call pays for the one entry of its filter list and the Flate input of the stream, and
    # for nothing else.
    one = walk.VISIT_COST + len(_empty_stream()._data)
    walk._content({"/Contents": _empty_stream()})
    assert walk.budget.read == one
    walk._content(_empty_stream())
    assert walk.budget.read == 2 * one
