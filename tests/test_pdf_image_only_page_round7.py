"""Seventh round on the image only page check: one bounded decoder, direct fonts, hidden
annotations.

Review of the sixth round found these gaps:

* a content stream was decoded before it was charged. The sizing probe gave up on a gzip header,
  a bad checksum or a truncated stream, and the stream then fell through to the reader's own
  decode, which has no bound (and a byte by byte fallback that is quadratic). A filter chain was
  sized only up to its first filter that the probe did not know, and the intermediate output of
  Flate then ASCII85 was neither charged nor decoded once;
* a Type3 font held as a direct dictionary has no object number, so it was neither cached nor
  guarded, and nested direct fonts were walked once per path;
* an annotation with the Hidden or NoView flag draws nothing, yet its appearance was walked and
  the page named as not inspected.

The check now decodes through the same bounded decoder as the container walk of the PDF extractor:
every stage is charged, a chain that cannot be sized is not decoded, and the reader's get_data()
is never called.
"""

import base64
import gzip
import zlib

import pytest

from test_pdf_image_only_page import _extract, _head, _image, _page, _stream, _write
from test_pdf_image_only_page_paths import appearance_pdf
from test_pdf_image_only_page_softmask import GROUP, USE

pytest.importorskip("PyPDF2")

IM = b"/Im Do"


def _warned(result):
    return [w for w in result.warnings if "inspected" in w or "not read" in w or "not checked" in w]


def _found(result):
    return result.complete is False and any("image" in w for w in result.warnings)


def _no_reader_decode(monkeypatch):
    """Record the times the picture walk asks the reader to decode a stream. The text
    extraction runs the reader's decode on page content as it always did; only calls made
    from the walk are counted."""
    import inspect

    from PyPDF2.generic import DecodedStreamObject, EncodedStreamObject

    calls = []

    def counted(real):
        def get_data(self, *args, **kwargs):
            if any(frame.function == "_content" for frame in inspect.stack()):
                calls.append(1)
            return real(self, *args, **kwargs)
        return get_data

    for owner in (EncodedStreamObject, DecodedStreamObject):
        monkeypatch.setattr(owner, "get_data", counted(owner.get_data))
    return calls


def group_pdf(path, body, filt=b"", extra=b""):
    """A page that sets a soft mask whose group holds `body` (the group's content stream)."""
    group = _stream(GROUP + filt + b" /Resources << /XObject << /Im 7 0 R >> >>" + extra, body)
    objs = _head(3) + [
        _page(b"/ExtGState << /GS 5 0 R >>", contents=4),
        _stream(b"", USE),
        b"<< /Type /ExtGState /SMask << /S /Luminosity /G 6 0 R >> >>",
        group,
        _image(),
    ]
    return _write(path, objs)


def _bad_adler(data):
    packed = bytearray(zlib.compress(data, 9))
    packed[-1] ^= 0xFF
    return bytes(packed)


# 1. A stream the old probe could not size is still bounded --------------------------------
@pytest.mark.parametrize("make", [
    lambda d: gzip.compress(d), _bad_adler, lambda d: zlib.compress(d)[:-4],
], ids=["gzip", "bad_checksum", "no_checksum"])
def test_a_gzip_bad_checksum_or_cut_stream_is_read_and_its_picture_found(tmp_path, monkeypatch, make):
    calls = _no_reader_decode(monkeypatch)
    result = _extract(group_pdf(tmp_path / "g.pdf", make(IM), b" /Filter /FlateDecode"))
    assert _found(result), result.warnings
    assert calls == [], "the reader's own decode ran"


@pytest.mark.parametrize("pack", [gzip.compress, _bad_adler], ids=["gzip", "bad_checksum"])
def test_such_a_stream_that_inflates_past_the_budget_is_not_decoded_in_full(tmp_path, monkeypatch, pack):
    from sunglasses.extractors import pdf as pdf_module

    monkeypatch.setattr(pdf_module._ReadBudget, "MAX_BYTES", 4096)
    calls = _no_reader_decode(monkeypatch)
    result = _extract(group_pdf(tmp_path / "b.pdf", pack(b" " * 5_000_000 + IM), b" /Filter /FlateDecode"))
    assert result.complete is False and _warned(result), result.warnings
    assert calls == []


def test_a_truncated_stream_is_read_as_far_as_it_goes_and_named(tmp_path, monkeypatch):
    calls = _no_reader_decode(monkeypatch)
    text = IM + b" " * 200_000
    packed = zlib.compress(text, 9)
    result = _extract(group_pdf(tmp_path / "t.pdf", packed[:len(packed) // 2], b" /Filter /FlateDecode"))
    assert result.complete is False, result.warnings
    assert any("ends before" in w for w in result.warnings), result.warnings
    assert calls == []


# 2. A chain is sized stage by stage -------------------------------------------------------
@pytest.mark.parametrize("filters", [
    b"[/LZWDecode /ASCII85Decode]", b"[/Crypt /FlateDecode]", b"[/ASCIIHexDecode /FlateDecode]",
], ids=["lzw_first", "crypt_first", "hex_first"])
def test_a_chain_with_a_filter_that_cannot_be_sized_is_reported_and_not_decoded(tmp_path, monkeypatch, filters):
    calls = _no_reader_decode(monkeypatch)
    result = _extract(group_pdf(tmp_path / "u.pdf", zlib.compress(IM), b" /Filter " + filters))
    assert result.complete is False and _warned(result), result.warnings
    assert calls == []


def test_the_intermediate_output_of_a_chain_is_charged(tmp_path, monkeypatch):
    from sunglasses.extractors import pdf as pdf_module

    final = IM + b" " * 600_000
    middle = base64.a85encode(final) + b"~>"   # about 750 KB of text before the last stage
    body = zlib.compress(middle, 9)
    path = group_pdf(tmp_path / "c.pdf", body, b" /Filter [/FlateDecode /ASCII85Decode]")
    # The final output fits in a megabyte; the stage in front of it does not leave room.
    monkeypatch.setattr(pdf_module._ReadBudget, "MAX_BYTES", 1 << 20)
    result = _extract(path)
    assert result.complete is False and _warned(result), result.warnings
    assert not any("image(s) not read" in w for w in result.warnings), result.warnings
    monkeypatch.setattr(pdf_module._ReadBudget, "MAX_BYTES", 4 << 20)
    assert any("image(s) not read" in w for w in _extract(path).warnings)


def test_an_ascii85_stage_is_decoded_once(tmp_path, monkeypatch):
    from PyPDF2 import filters as pdf_filters

    calls = []
    real = pdf_filters.ASCII85Decode.decode
    monkeypatch.setattr(pdf_filters.ASCII85Decode, "decode",
                        staticmethod(lambda *a, **k: calls.append(1) or real(*a, **k)))
    body = base64.a85encode(zlib.compress(IM), adobe=False) + b"~>"
    result = _extract(group_pdf(tmp_path / "a.pdf", body, b" /Filter [/ASCII85Decode /FlateDecode]"))
    assert _found(result), result.warnings
    assert len(calls) == 1, calls


def test_an_ascii85_z_bomb_is_counted_and_not_decoded(tmp_path, monkeypatch):
    from PyPDF2 import filters as pdf_filters
    from sunglasses.extractors import pdf as pdf_module

    monkeypatch.setattr(pdf_module._ReadBudget, "MAX_BYTES", 1 << 20)
    monkeypatch.setattr(pdf_filters.ASCII85Decode, "decode",
                        staticmethod(lambda *a, **k: pytest.fail("decoded past the bound")))
    result = _extract(group_pdf(tmp_path / "z.pdf", b"z" * 400_000 + b"~>", b" /Filter /ASCII85Decode"))
    assert result.complete is False and _warned(result), result.warnings


def test_a_png_predictor_content_stream_is_read(tmp_path, monkeypatch):
    calls = _no_reader_decode(monkeypatch)
    columns = 8
    raw = IM + b" " * (columns - len(IM) % columns)
    rows = b"".join(b"\x00" + raw[i:i + columns] for i in range(0, len(raw), columns))
    result = _extract(group_pdf(tmp_path / "p.pdf", zlib.compress(rows),
                                b" /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns %d >>" % columns))
    assert _found(result), result.warnings
    assert calls == []


def test_the_reader_decode_is_never_used_for_a_plain_page(tmp_path, monkeypatch):
    from test_pdf_image_only_page import image_only_pdf

    calls = _no_reader_decode(monkeypatch)
    assert _found(_extract(image_only_pdf(tmp_path / "plain.pdf")))
    assert calls == []


# 3. A Type3 font held as a direct dictionary is cached and charged ------------------------
def _nested_direct_fonts(levels, glyphs):
    """A font whose glyph procedures select a font held as a direct dictionary in the
    resources, which selects the next one, down to a font whose glyph paints a picture. Every
    glyph of a level shares one procedure stream, so only the fonts multiply the visits."""
    names = b" ".join(b"/G%d %%d 0 R" % i for i in range(glyphs))
    tail = (b"<< /Type /Font /Subtype /Type3 /FontBBox [0 0 1000 1000] /FontMatrix [.001 0 0 .001 0 0] "
            b"/CharProcs << " + names + b" >> /Encoding << /Type /Encoding /Differences [65 /G0] >> "
            b"/FirstChar 65 /LastChar 65 /Widths [1000] /Resources << %s >> >>")
    font = tail.replace(b"%d", b"6") % b"/XObject << /Im0 5 0 R >>"
    for _ in range(levels):
        font = tail.replace(b"%d", b"7") % (b"/Font << /F1 " + font + b" >>")
    return font


def nested_direct_fonts_pdf(path, levels, glyphs):
    objs = _head(3) + [
        _page(b"/Font << /F1 " + _nested_direct_fonts(levels, glyphs) + b" >>", contents=4),
        _stream(b"", b"BT /F1 12 Tf (A) Tj ET"),
        _image(),
        _stream(b"", b"1000 0 d0 /Im0 Do"),
        _stream(b"", b"/F1 12 Tf (A) Tj"),
    ]
    return _write(path, objs)


def test_nested_direct_fonts_are_walked_once_each(tmp_path, monkeypatch):
    from sunglasses.extractors import pdf as pdf_module

    calls = []
    real = pdf_module._ImageWalk._count
    monkeypatch.setattr(pdf_module._ImageWalk, "_count",
                        lambda self, *a, **k: calls.append(1) or real(self, *a, **k))
    levels, glyphs = 5, 8
    result = _extract(nested_direct_fonts_pdf(tmp_path / "d.pdf", levels, glyphs))
    assert result.complete is False, result.warnings
    assert len(calls) <= 2 * (levels + 1) * glyphs + 4, len(calls)


def test_a_visit_to_a_glyph_procedure_is_charged(tmp_path, monkeypatch):
    from sunglasses.extractors import pdf as pdf_module

    glyphs = 40
    names = b" ".join(b"/G%d 6 0 R" % i for i in range(glyphs))
    objs = _head(3) + [
        _page(b"/Font << /F1 5 0 R >>", contents=4),
        _stream(b"", b"BT /F1 12 Tf (A) Tj ET"),
        b"<< /Type /Font /Subtype /Type3 /FontBBox [0 0 1000 1000] /FontMatrix [.001 0 0 .001 0 0] "
        b"/CharProcs << " + names + b" >> /Encoding << /Type /Encoding /Differences [65 /G0] >> "
        b"/FirstChar 65 /LastChar 65 /Widths [1000] >>",
        _stream(b"", b""),
    ]
    path = _write(tmp_path / "v.pdf", objs)
    monkeypatch.setattr(pdf_module._ReadBudget, "MAX_BYTES", pdf_module._ImageWalk.VISIT_COST * 10)
    result = _extract(path)
    assert result.complete is False and _warned(result), result.warnings


# 4. An annotation that is not shown draws nothing -----------------------------------------
AP = b"/AP << /N 5 0 R >>"


@pytest.mark.parametrize("flags", [2, 32, 34, 3, 6])
def test_a_hidden_or_no_view_annotation_draws_nothing(tmp_path, flags):
    result = _extract(appearance_pdf(tmp_path / "h.pdf", AP + b" /F %d" % flags))
    assert not _warned(result), (flags, result.warnings)


@pytest.mark.parametrize("flags", [0, 4, 1, 8, 28, 64, 128, 256])
def test_an_annotation_that_is_shown_is_still_walked(tmp_path, flags):
    result = _extract(appearance_pdf(tmp_path / "s.pdf", AP + b" /F %d" % flags))
    assert _warned(result), (flags, result.warnings)


def test_an_annotation_without_flags_or_with_a_flag_that_is_not_a_number_is_still_walked(tmp_path):
    assert _warned(_extract(appearance_pdf(tmp_path / "n.pdf", AP)))
    assert _warned(_extract(appearance_pdf(tmp_path / "x.pdf", AP + b" /F (hidden)")))
