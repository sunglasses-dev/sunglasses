"""Soft-mask groups and the selected state of an annotation, in the image only page check.

Review of the fourth round found two gaps.

A graphics state selected with the gs operator can carry a soft mask, and the mask is a
group (a form) that paints through the page. A picture inside that group changes what is
rendered, and the check never opened the group, so such a page came back complete and
clean. The group is now read under the same walk and budget as any other form, from the
page, from a form, from a glyph procedure and from an annotation appearance. A state the
page defines but never selects, a mask set to None and a state without a mask paint
nothing and add no warning. A mask whose group cannot be read is reported as content that
was not inspected.

The check read every normal appearance state of an annotation, and a picture in a state
the annotation does not select gave a false warning. The state named by the annotation's
/AS is read alone. With no usable /AS every state is still read, which is conservative
coverage and not a claim about what a viewer draws.
"""

import pytest

from test_pdf_image_only_page import _extract, _head, _image, _page, _stream, _write

pytest.importorskip("PyPDF2")

FORM = b"/Type /XObject /Subtype /Form /BBox [0 0 612 792]"
GROUP = FORM + b" /Group << /S /Transparency /CS /DeviceRGB >>"
USE = b"q /GS gs 0 0 0 rg 0 0 240 240 re f Q"


def _warned(result):
    return [w for w in result.warnings if "inspected" in w or "not read" in w]


def _found(result):
    return result.complete is False and any("image" in w for w in result.warnings)


def mask_pdf(path, content=USE, state=b"/Type /ExtGState /SMask << /S /Luminosity /G 6 0 R >>",
             group=None, group_resources=b"/XObject << /Im 7 0 R >>", group_content=b"q 240 0 0 240 0 0 cm /Im Do Q",
             extra=()):
    group = group or _stream(GROUP + b" /Resources << " + group_resources + b" >>", group_content)
    objs = _head(3) + [
        _page(b"/ExtGState << /GS 5 0 R >>", contents=4),
        _stream(b"", content),
        b"<< " + state + b" >>",
        group,
        _image(),
    ] + list(extra)
    return _write(path, objs)


# 1. A picture inside the soft-mask group is a painted picture ------------------------------
def test_a_soft_mask_group_that_paints_a_picture_is_reported(tmp_path):
    result = _extract(mask_pdf(tmp_path / "m.pdf"))
    assert _found(result), result.warnings
    assert any("page 1" in w for w in result.warnings), result.warnings


def test_a_picture_in_a_form_drawn_by_the_mask_group_is_reported(tmp_path):
    inner = _stream(FORM + b" /Resources << /XObject << /Im 7 0 R >> >>", b"/Im Do")
    result = _extract(mask_pdf(tmp_path / "m.pdf", group_resources=b"/XObject << /Fm 8 0 R >>",
                               group_content=b"/Fm Do", extra=[inner]))
    assert _found(result), result.warnings


def test_a_mask_state_written_directly_in_the_resources_is_reported(tmp_path):
    objs = _head(3) + [
        _page(b"/ExtGState << /GS << /SMask << /S /Alpha /G 5 0 R >> >> >>", contents=4),
        _stream(b"", USE),
        _stream(GROUP + b" /Resources << /XObject << /Im 6 0 R >> >>", b"/Im Do"),
        _image(),
    ]
    assert _found(_extract(_write(tmp_path / "m.pdf", objs)))


def test_a_mask_object_held_by_reference_is_reported(tmp_path):
    result = _extract(mask_pdf(tmp_path / "m.pdf", state=b"/Type /ExtGState /SMask 8 0 R",
                               extra=[b"<< /S /Luminosity /G 6 0 R >>"]))
    assert _found(result), result.warnings


def test_a_mask_selected_inside_a_form_is_reported(tmp_path):
    objs = _head(3) + [
        _page(b"/XObject << /Fm 4 0 R >>", contents=8),
        _stream(FORM + b" /Resources << /ExtGState << /GS 5 0 R >> >>", USE),
        b"<< /Type /ExtGState /SMask << /S /Luminosity /G 6 0 R >> >>",
        _stream(GROUP + b" /Resources << /XObject << /Im 7 0 R >> >>", b"/Im Do"),
        _image(),
        _stream(b"", b"/Fm Do"),
    ]
    # 4 is the form; 8 is the page content that draws it
    assert _found(_extract(_write(tmp_path / "m.pdf", objs)))


def test_a_mask_selected_in_a_glyph_procedure_is_reported(tmp_path):
    objs = _head(3) + [
        _page(b"/Font << /F1 5 0 R >>", contents=4),
        _stream(b"", b"BT /F1 200 Tf 40 400 Td (A) Tj ET"),
        b"<< /Type /Font /Subtype /Type3 /FontBBox [0 0 1000 1000] /FontMatrix [0.001 0 0 0.001 0 0] "
        b"/CharProcs << /A 6 0 R >> /Encoding << /Type /Encoding /Differences [65 /A] >> "
        b"/FirstChar 65 /LastChar 65 /Widths [1000] /Resources << /ExtGState << /GS 7 0 R >> >> >>",
        _stream(b"", b"1000 0 d0 /GS gs 0 0 1000 1000 re f"),
        b"<< /Type /ExtGState /SMask << /S /Luminosity /G 8 0 R >> >>",
        _stream(GROUP + b" /Resources << /XObject << /Im 9 0 R >> >>", b"/Im Do"),
        _image(),
    ]
    assert _found(_extract(_write(tmp_path / "m.pdf", objs)))


def test_a_mask_selected_in_an_annotation_appearance_is_reported(tmp_path):
    objs = _head(3) + [
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R] >>",
        b"<< /Type /Annot /Subtype /Stamp /Rect [10 10 200 200] /AP << /N 5 0 R >> >>",
        _stream(FORM + b" /Resources << /ExtGState << /GS 6 0 R >> >>", USE),
        b"<< /Type /ExtGState /SMask << /S /Luminosity /G 7 0 R >> >>",
        _stream(GROUP + b" /Resources << /XObject << /Im 8 0 R >> >>", b"/Im Do"),
        _image(),
    ]
    assert _found(_extract(_write(tmp_path / "m.pdf", objs)))


def test_a_mask_group_inside_a_mask_group_is_reported(tmp_path):
    inner_state = b"<< /Type /ExtGState /SMask << /S /Alpha /G 9 0 R >> >>"
    result = _extract(mask_pdf(tmp_path / "m.pdf", group_resources=b"/ExtGState << /GS2 8 0 R >>",
                               group_content=b"/GS2 gs 0 0 10 10 re f",
                               extra=[inner_state,
                                      _stream(GROUP + b" /Resources << /XObject << /Im 7 0 R >> >>", b"/Im Do")]))
    assert _found(result), result.warnings


def test_two_pages_that_select_the_same_mask_both_report(tmp_path):
    objs = _head(3, 4) + [
        _page(b"/ExtGState << /GS 6 0 R >>", contents=5),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 5 0 R "
        b"/Resources << /ExtGState << /GS 6 0 R >> >> >>",
        _stream(b"", USE),
        b"<< /Type /ExtGState /SMask << /S /Luminosity /G 7 0 R >> >>",
        _stream(GROUP + b" /Resources << /XObject << /Im 8 0 R >> >>", b"/Im Do"),
        _image(),
    ]
    result = _extract(_write(tmp_path / "m.pdf", objs))
    assert result.complete is False
    assert any("page 1" in w for w in result.warnings) and any("page 2" in w for w in result.warnings), \
        result.warnings


# 2. Nothing painted, nothing reported ------------------------------------------------------
def test_a_mask_state_the_page_defines_but_never_selects_adds_no_warning(tmp_path):
    result = _extract(mask_pdf(tmp_path / "m.pdf", content=b"0 0 240 240 re f"))
    assert not _warned(result) and result.complete is not False, result.warnings


def test_a_mask_set_to_none_adds_no_warning(tmp_path):
    result = _extract(mask_pdf(tmp_path / "m.pdf", state=b"/Type /ExtGState /SMask /None"))
    assert not _warned(result), result.warnings


def test_a_state_without_a_mask_adds_no_warning(tmp_path):
    result = _extract(mask_pdf(tmp_path / "m.pdf", state=b"/Type /ExtGState /CA 0.5 /ca 0.5"))
    assert not _warned(result), result.warnings


def test_a_mask_group_that_only_draws_vectors_and_holds_an_unused_picture_adds_no_warning(tmp_path):
    result = _extract(mask_pdf(tmp_path / "m.pdf", group_content=b"0 0 240 240 re f"))
    assert not _warned(result), result.warnings


def test_a_selected_state_the_resources_do_not_hold_adds_no_warning(tmp_path):
    result = _extract(mask_pdf(tmp_path / "m.pdf", content=b"/Other gs 0 0 10 10 re f"))
    assert not _warned(result), result.warnings


@pytest.mark.parametrize("content", [
    b"(/GS gs) Tj",
    b"% /GS gs\n0 0 10 10 re f",
    b"/GS gsx",
    b"/GS gs_ 0 0 10 10 re f",
])
def test_text_that_only_looks_like_a_gs_operator_adds_no_warning(tmp_path, content):
    result = _extract(mask_pdf(tmp_path / "m.pdf", content=content))
    assert not _warned(result), result.warnings


# 3. A mask that cannot be read is reported ---------------------------------------------------
def test_a_mask_without_a_readable_group_is_reported(tmp_path):
    result = _extract(mask_pdf(tmp_path / "m.pdf", state=b"/Type /ExtGState /SMask << /S /Alpha >>"))
    assert result.complete is False and _warned(result), result.warnings


def test_a_selected_state_with_a_name_that_is_not_plain_ascii_and_is_not_found_is_reported(tmp_path):
    result = _extract(mask_pdf(tmp_path / "m.pdf", content=b"/G\xc3\xa9 gs 0 0 10 10 re f"))
    assert any("could not be matched" in w for w in result.warnings), result.warnings


def test_a_mask_group_that_selects_its_own_state_ends_and_adds_no_warning(tmp_path):
    result = _extract(mask_pdf(tmp_path / "m.pdf", group_resources=b"/ExtGState << /GS 5 0 R >>",
                               group_content=b"/GS gs 0 0 10 10 re f"))
    assert not _warned(result), result.warnings


def test_a_chain_of_mask_groups_deeper_than_the_bound_is_reported(tmp_path):
    depth = 12
    objs = _head(3) + [_page(b"/ExtGState << /GS 5 0 R >>", contents=4), _stream(b"", USE)]
    first = 5
    for level in range(depth):
        state, group = first + 2 * level, first + 2 * level + 1
        nxt = state + 2
        objs.append(b"<< /Type /ExtGState /SMask << /S /Alpha /G %d 0 R >> >>" % group)
        objs.append(_stream(GROUP + b" /Resources << /ExtGState << /GS %d 0 R >> >>" % nxt, b"/GS gs 0 0 1 1 re f"))
    objs.append(b"<< /Type /ExtGState /CA 1 >>")
    result = _extract(_write(tmp_path / "m.pdf", objs))
    assert result.complete is False, result.warnings


# 4. Only the selected appearance state is read ---------------------------------------------
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


def test_a_picture_in_an_unselected_state_adds_no_warning(tmp_path):
    result = _extract(states_pdf(tmp_path / "a.pdf", b"/AS /Off"))
    assert not _warned(result), result.warnings


def test_a_picture_in_the_selected_state_is_reported(tmp_path):
    assert _found(_extract(states_pdf(tmp_path / "a.pdf", b"/AS /On")))


@pytest.mark.parametrize("annot_extra", [b"", b"/AS (On)", b"/AS 3"], ids=["no_AS", "string_AS", "number_AS"])
def test_with_no_usable_selected_state_every_state_is_read(tmp_path, annot_extra):
    assert _found(_extract(states_pdf(tmp_path / "a.pdf", annot_extra)))


def test_a_selected_state_that_the_appearance_does_not_hold_adds_no_warning(tmp_path):
    result = _extract(states_pdf(tmp_path / "a.pdf", b"/AS /Missing"))
    assert not _warned(result), result.warnings


def test_the_selected_state_alone_is_read_when_the_picture_is_in_the_other_one(tmp_path):
    assert not _warned(_extract(states_pdf(tmp_path / "a.pdf", b"/AS /Off")))
    assert _found(_extract(states_pdf(tmp_path / "b.pdf", b"/AS /On")))
