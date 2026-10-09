"""Resource chain, graphics-state fonts, shared visits and bounded decode, in the image only page check.

Review of the fifth round found these gaps in the walk that decides which pictures a page paints.

A name drawn inside a form, a soft-mask group or a glyph procedure that has resources of its own
is looked up the way a renderer looks it up: in those resources first and then in the resources
of whatever encloses it. The walk used to stop at the first non-empty table, so a picture that
only the page held, drawn from inside such a form, came back complete and clean.

A graphics state selected with gs can set the font through its /Font entry. A Type3 font set that
way is walked like one selected with Tf.

An annotation /AS counts only when it is a name. A text string that starts with a slash is not one,
and every state is read.

A result computed while a cycle through a node above was cut short is not kept, so the page order
does not change which page is named.

Annotations and their appearance states are visited once for pages that share them, and every visit
is charged. A content stream is inflated no further than the room left in the budget before it is
decoded in full.
"""

import zlib

import pytest

from test_pdf_image_only_page import _extract, _head, _image, _page, _stream, _write
from test_pdf_image_only_page_softmask import FORM, GROUP, USE

pytest.importorskip("PyPDF2")

TYPE3 = (b"<< /Type /Font /Subtype /Type3 /FontBBox [0 0 1000 1000] /FontMatrix [.001 0 0 .001 0 0] "
         b"/CharProcs << /A %d 0 R >> /Encoding << /Type /Encoding /Differences [65 /A] >> "
         b"/FirstChar 65 /LastChar 65 /Widths [1000] /Resources << %s >> >>")


def _warned(result):
    return [w for w in result.warnings if "inspected" in w or "not read" in w]


def _found(result):
    return result.complete is False and any("image" in w for w in result.warnings)


# 1. A Type3 font set through a graphics state ---------------------------------------------
def gs_font_pdf(path, glyph=b"1000 0 d0 q 1000 0 0 1000 0 0 cm /Im0 Do Q", selected=True):
    content = b"/GS gs BT 40 400 Td (A) Tj ET" if selected else b"BT 40 400 Td (A) Tj ET"
    objs = _head(3) + [
        _page(b"/ExtGState << /GS << /Type /ExtGState /Font [5 0 R 12] >> >>", contents=4),
        _stream(b"", content),
        TYPE3 % (6, b"/XObject << /Im0 7 0 R >>"),
        _stream(b"", glyph),
        _image(),
    ]
    return _write(path, objs)


def test_a_type3_font_set_through_a_graphics_state_is_reported(tmp_path):
    result = _extract(gs_font_pdf(tmp_path / "g.pdf"))
    assert _found(result), result.warnings
    assert any("page 1" in w and "glyph" in w for w in result.warnings), result.warnings


def test_a_graphics_state_font_whose_glyphs_hold_no_picture_is_not_reported(tmp_path):
    result = _extract(gs_font_pdf(tmp_path / "g.pdf", glyph=b"1000 0 d0 0 0 500 500 re f"))
    assert not _warned(result), result.warnings


def test_a_graphics_state_font_that_is_never_selected_is_not_reported(tmp_path):
    assert not _warned(_extract(gs_font_pdf(tmp_path / "g.pdf", selected=False)))


def test_a_graphics_state_font_that_is_not_type3_adds_nothing(tmp_path):
    objs = _head(3) + [
        _page(b"/ExtGState << /GS << /Type /ExtGState /Font [5 0 R 12] >> >>", contents=4),
        _stream(b"", b"/GS gs BT 40 400 Td (A) Tj ET"),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    assert not _warned(_extract(_write(tmp_path / "g.pdf", objs)))


def test_a_graphics_state_font_selected_inside_a_form_is_reported(tmp_path):
    objs = _head(3) + [
        _page(b"/XObject << /Fm 4 0 R >>", contents=5),
        _stream(FORM + b" /Resources << /ExtGState << /GS << /Font [6 0 R 12] >> >> >>",
                b"/GS gs BT (A) Tj ET"),
        _stream(b"", b"/Fm Do"),
        TYPE3 % (7, b"/XObject << /Im0 8 0 R >>"),
        _stream(b"", b"1000 0 d0 /Im0 Do"),
        _image(),
    ]
    assert _found(_extract(_write(tmp_path / "g.pdf", objs)))


def test_a_graphics_state_font_that_is_a_cycle_terminates(tmp_path):
    objs = _head(3) + [
        _page(b"/ExtGState << /GS << /Font [5 0 R 12] >> >>", contents=4),
        _stream(b"", b"/GS gs BT (A) Tj ET"),
        TYPE3 % (6, b"/ExtGState << /GS << /Font [5 0 R 12] >> >>"),
        _stream(b"", b"1000 0 d0 /GS gs BT (A) Tj ET"),
    ]
    assert not _warned(_extract(_write(tmp_path / "g.pdf", objs)))


# 2. A name is looked up in the resources of what encloses the form -----------------------
def scoped_form_pdf(path, own=b"/ProcSet [/PDF]", page=b"/XObject << /Fm 4 0 R /Im 6 0 R >>"):
    objs = _head(3) + [
        _page(page, contents=5),
        _stream(FORM + b" /Resources << " + own + b" >>", b"/Im Do"),
        _stream(b"", b"/Fm Do"),
        _image(),
    ]
    return _write(path, objs)


def test_a_form_with_resources_of_its_own_draws_a_name_only_the_page_holds(tmp_path):
    assert _found(_extract(scoped_form_pdf(tmp_path / "s.pdf")))


def test_a_form_whose_own_resources_hold_a_different_xobject_table_still_reaches_the_page(tmp_path):
    result = _extract(scoped_form_pdf(tmp_path / "s.pdf", own=b"/XObject << /Other 6 0 R >>"))
    assert _found(result), result.warnings


def test_a_name_held_nowhere_draws_nothing(tmp_path):
    result = _extract(scoped_form_pdf(tmp_path / "s.pdf", page=b"/XObject << /Fm 4 0 R >>"))
    assert not _warned(result), result.warnings


def test_a_name_the_form_holds_itself_shadows_the_page_entry(tmp_path):
    objs = _head(3) + [
        _page(b"/XObject << /Fm 4 0 R /Im 6 0 R >>", contents=5),
        _stream(FORM + b" /Resources << /XObject << /Im 7 0 R >> >>", b"/Im Do"),
        _stream(b"", b"/Fm Do"),
        _image(),
        _stream(FORM + b" /Resources << >>", b""),
    ]
    assert not _warned(_extract(_write(tmp_path / "s.pdf", objs)))


def test_a_soft_mask_group_with_resources_of_its_own_draws_a_name_only_the_page_holds(tmp_path):
    objs = _head(3) + [
        _page(b"/ExtGState << /GS 5 0 R >> /XObject << /Im 7 0 R >>", contents=4),
        _stream(b"", USE),
        b"<< /Type /ExtGState /SMask << /S /Luminosity /G 6 0 R >> >>",
        _stream(GROUP + b" /Resources << /ProcSet [/PDF] >>", b"q 240 0 0 240 0 0 cm /Im Do Q"),
        _image(),
    ]
    assert _found(_extract(_write(tmp_path / "s.pdf", objs)))


def test_a_glyph_procedure_with_resources_of_its_own_draws_a_name_only_the_page_holds(tmp_path):
    objs = _head(3) + [
        _page(b"/Font << /F1 5 0 R >> /XObject << /Im0 7 0 R >>", contents=4),
        _stream(b"", b"BT /F1 200 Tf 40 400 Td (A) Tj ET"),
        TYPE3 % (6, b"/ProcSet [/PDF]"),
        _stream(b"", b"1000 0 d0 /Im0 Do"),
        _image(),
    ]
    assert _found(_extract(_write(tmp_path / "s.pdf", objs)))


def test_a_font_the_form_selects_is_looked_up_in_the_page_resources(tmp_path):
    objs = _head(3) + [
        _page(b"/XObject << /Fm 4 0 R >> /Font << /F1 6 0 R >>", contents=5),
        _stream(FORM + b" /Resources << /ProcSet [/PDF] >>", b"BT /F1 200 Tf (A) Tj ET"),
        _stream(b"", b"/Fm Do"),
        TYPE3 % (7, b"/XObject << /Im0 8 0 R >>"),
        _stream(b"", b"1000 0 d0 /Im0 Do"),
        _image(),
    ]
    assert _found(_extract(_write(tmp_path / "s.pdf", objs)))


def test_a_graphics_state_the_form_selects_is_looked_up_in_the_page_resources(tmp_path):
    objs = _head(3) + [
        _page(b"/XObject << /Fm 4 0 R >> /ExtGState << /GS 6 0 R >>", contents=5),
        _stream(FORM + b" /Resources << /ProcSet [/PDF] >>", b"/GS gs 0 0 9 9 re f"),
        _stream(b"", b"/Fm Do"),
        b"<< /SMask << /S /Alpha /G 7 0 R >> >>",
        _stream(GROUP + b" /Resources << /XObject << /Im 8 0 R >> >>", b"/Im Do"),
        _image(),
    ]
    assert _found(_extract(_write(tmp_path / "s.pdf", objs)))


# 3. /AS counts when it is a name ----------------------------------------------------------
def states_pdf(path, annot_extra):
    objs = _head(3) + [
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 240 240] /Annots [4 0 R] >>",
        b"<< /Type /Annot /Subtype /Stamp /Rect [0 0 240 240] " + annot_extra
        + b" /AP << /N << /Off 5 0 R /On 6 0 R >> >> >>",
        _stream(FORM + b" /Resources << >>", b""),
        _stream(FORM + b" /Resources << /XObject << /Im 7 0 R >> >>", b"q 240 0 0 240 0 0 cm /Im Do Q"),
        _image(),
    ]
    return _write(path, objs)


@pytest.mark.parametrize("annot_extra", [b"/AS (/Off)", b"/AS <2F4F6666>", b"/AS (/On)"],
                         ids=["slash_string", "hex_string", "slash_string_on"])
def test_a_text_string_that_starts_with_a_slash_is_not_a_selected_state(tmp_path, annot_extra):
    assert _found(_extract(states_pdf(tmp_path / "a.pdf", annot_extra)))


def test_a_real_name_still_selects_one_state(tmp_path):
    assert not _warned(_extract(states_pdf(tmp_path / "a.pdf", b"/AS /Off")))


# 4. A cut cycle is not kept ----------------------------------------------------------------
def cycle_pdf(path, second_page=b"/F2 Do", first_page=b"/F1 Do"):
    """F1 paints a picture and draws F2, and F2 draws F1 again. One page draws F1; the other draws F2."""
    resources = b"/XObject << /F1 5 0 R /F2 6 0 R >>"
    objs = _head(3, 4) + [
        _page(resources, contents=7),
        _page(resources, contents=8),
        _stream(FORM + b" /Resources << /XObject << /F2 6 0 R /Im 9 0 R >> >>", b"/Im Do /F2 Do"),
        _stream(FORM + b" /Resources << /XObject << /F1 5 0 R >> >>", b"/F1 Do"),
        _stream(b"", first_page),
        _stream(b"", second_page),
        _image(),
    ]
    return _write(path, objs)


def _pages(result):
    """The page numbers the warnings name (the counts differ with the path taken, the pages do not)."""
    import re

    return sorted({int(n) for w in result.warnings if "image" in w for n in re.findall(r"page (\d+)", w)})


def test_a_form_in_a_cycle_is_named_on_every_page_that_reaches_the_picture(tmp_path):
    assert _pages(_extract(cycle_pdf(tmp_path / "c.pdf"))) == [1, 2]


def test_the_page_order_does_not_change_which_pages_are_named(tmp_path):
    forward = _pages(_extract(cycle_pdf(tmp_path / "c.pdf")))
    backward = _pages(_extract(cycle_pdf(tmp_path / "d.pdf", first_page=b"/F2 Do", second_page=b"/F1 Do")))
    assert forward == backward, (forward, backward)


def test_a_page_that_draws_the_cut_node_first_is_named(tmp_path):
    result = _extract(cycle_pdf(tmp_path / "c.pdf", first_page=b"/F2 Do", second_page=b"/F2 Do"))
    assert _pages(result) == [1, 2], result.warnings


def test_two_mask_groups_that_select_each_other_are_named_on_each_page(tmp_path):
    resources = b"/ExtGState << /GA 7 0 R /GB 8 0 R >>"
    objs = _head(3, 4) + [
        _page(resources, contents=5),
        _page(resources, contents=6),
        _stream(b"", b"/GA gs 0 0 9 9 re f"),
        _stream(b"", b"/GB gs 0 0 9 9 re f"),
        b"<< /SMask << /S /Alpha /G 9 0 R >> >>",
        b"<< /SMask << /S /Alpha /G 10 0 R >> >>",
        _stream(GROUP + b" /Resources << /ExtGState << /GB 8 0 R >> /XObject << /Im 11 0 R >> >>",
                b"/Im Do /GB gs 0 0 9 9 re f"),
        _stream(GROUP + b" /Resources << /ExtGState << /GA 7 0 R >> >>", b"/GA gs 0 0 9 9 re f"),
        _image(),
    ]
    assert _pages(_extract(_write(tmp_path / "m.pdf", objs))) == [1, 2]


# 5. A selected mask counts even when nothing is painted under it ---------------------------
def test_a_mask_selected_and_restored_before_anything_is_painted_still_counts(tmp_path):
    from test_pdf_image_only_page_softmask import mask_pdf

    path = mask_pdf(tmp_path / "m.pdf", content=b"q /GS gs Q 0 0 0 rg 0 0 240 240 re f")
    assert _found(_extract(path))


# 6. Pages that share annotations visit them once and every visit is charged --------------
def shared_annots_pdf(path, pages=40, annots=3, states=8):
    kids = list(range(3, 3 + pages))
    first_annot = 3 + pages
    objs = _head(*kids)
    for _ in kids:
        objs.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 240 240] /Annots %d 0 R >>"
                    % (first_annot + annots))
    first_state = first_annot + annots + 1
    for i in range(annots):
        objs.append(b"<< /Type /Annot /Subtype /Stamp /Rect [0 0 9 9] /AP << /N %d 0 R >> >>"
                    % (first_state + i * 0))
    objs.append(b"[" + b" ".join(b"%d 0 R" % (first_annot + i) for i in range(annots)) + b"]")
    objs.append(b"<< " + b" ".join(b"/S%d %d 0 R" % (i, first_state + 1 + i) for i in range(states)) + b" >>")
    for _ in range(states):
        objs.append(_stream(FORM + b" /Resources << >>", b""))
    return _write(path, objs)


def test_pages_that_share_an_annotation_list_visit_each_state_once(tmp_path, monkeypatch):
    from sunglasses.extractors import pdf as pdf_module

    calls = []
    real = pdf_module._ImageWalk._form
    monkeypatch.setattr(pdf_module._ImageWalk, "_form",
                        lambda self, *a, **k: calls.append(1) or real(self, *a, **k))
    # The annotation list sits at index first_annot + annots, the /N table right after it.
    _extract(shared_annots_pdf(tmp_path / "s.pdf", pages=40, annots=3, states=8))
    assert len(calls) <= 3 * 8, len(calls)


def test_every_annotation_and_state_visited_is_charged(tmp_path, monkeypatch):
    from sunglasses.extractors import pdf as pdf_module

    monkeypatch.setattr(pdf_module._ReadBudget, "MAX_BYTES", pdf_module._ImageWalk.VISIT_COST * 6)
    result = _extract(shared_annots_pdf(tmp_path / "s.pdf", pages=1, annots=4, states=8))
    assert result.complete is False and _warned(result), result.warnings


# 7. A stream is inflated no further than the room left, then decoded ------------------------
def big_group_pdf(path, size):
    group = _stream(GROUP + b" /Filter /FlateDecode /Resources << /XObject << /Im 7 0 R >> >>",
                    zlib.compress(b" " * size + b"/Im Do"))
    objs = _head(3) + [
        _page(b"/ExtGState << /GS 5 0 R >>", contents=4),
        _stream(b"", USE),
        b"<< /Type /ExtGState /SMask << /S /Luminosity /G 6 0 R >> >>",
        group,
        _image(),
    ]
    return _write(path, objs)


def test_a_stream_that_inflates_past_the_budget_is_not_decoded_in_full(tmp_path, monkeypatch):
    from PyPDF2.generic import EncodedStreamObject
    from sunglasses.extractors import pdf as pdf_module

    monkeypatch.setattr(pdf_module._ReadBudget, "MAX_BYTES", 4096)
    decoded = []
    real = EncodedStreamObject.get_data
    monkeypatch.setattr(EncodedStreamObject, "get_data",
                        lambda self, *a, **k: decoded.append(1) or real(self, *a, **k))
    result = _extract(big_group_pdf(tmp_path / "b.pdf", 5_000_000))
    assert not decoded, "the group was decoded in full"
    assert result.complete is False and _warned(result), result.warnings


def test_a_stream_inside_the_budget_is_read_and_its_picture_found(tmp_path):
    assert _found(_extract(big_group_pdf(tmp_path / "b.pdf", 1000)))


def test_an_ascii85_then_flate_group_is_read(tmp_path):
    import base64

    body = base64.a85encode(zlib.compress(b"/Im Do"), adobe=False) + b"~>"
    group = _stream(GROUP + b" /Filter [/ASCII85Decode /FlateDecode] /Resources << /XObject << /Im 7 0 R >> >>", body)
    objs = _head(3) + [
        _page(b"/ExtGState << /GS 5 0 R >>", contents=4),
        _stream(b"", USE),
        b"<< /Type /ExtGState /SMask << /S /Luminosity /G 6 0 R >> >>",
        group,
        _image(),
    ]
    assert _found(_extract(_write(tmp_path / "b.pdf", objs)))


def test_a_text_page_with_a_two_filter_content_chain_stays_complete(tmp_path):
    import base64

    from test_pdf_image_only_page import TEXT_STREAM

    body = base64.a85encode(zlib.compress(TEXT_STREAM), adobe=False) + b"~>"
    objs = _head(3) + [
        _page(b"/Font << /F1 4 0 R >>", contents=5),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        _stream(b"/Filter [/ASCII85Decode /FlateDecode]", body),
    ]
    result = _extract(_write(tmp_path / "t.pdf", objs))
    assert result.complete is not False and not _warned(result), result.warnings


# 8. The budget cannot be spent past its end -------------------------------------------------
def test_a_read_that_does_not_fit_spends_the_rest_and_raises():
    from sunglasses.extractors import pdf as pdf_module

    budget = pdf_module._ReadBudget()
    assert budget.remaining() == pdf_module._ReadBudget.MAX_BYTES
    budget.spend(10)
    assert budget.remaining() == pdf_module._ReadBudget.MAX_BYTES - 10
    with pytest.raises(pdf_module._WalkBudget):
        budget.spend(budget.remaining() + 1)
    assert budget.remaining() == 0


def test_a_read_that_exactly_fits_is_allowed():
    from sunglasses.extractors import pdf as pdf_module

    budget = pdf_module._ReadBudget()
    budget.spend(budget.remaining())
    assert budget.remaining() == 0
    with pytest.raises(pdf_module._WalkBudget):
        budget.spend(1)
