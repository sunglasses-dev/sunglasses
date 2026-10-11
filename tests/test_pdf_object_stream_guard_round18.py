"""Eighteenth round on the object stream guard: the dependency cases, through the extractor.

Round 17 showed that the guard leaves no compressed object stream to the reader, for a lookup that
fails at one depth and works at another. This file names the other ways a lookup can reach, or
fail to reach, an object stream, and holds each to the same two facts:

  1. the reader's own Flate decode never runs (the spy on it stays empty), because the guard
     decoded the stream, once, and handed the bytes over; and
  2. the document budget was charged for what was decoded, and only for that: the bytes of a
     stream nothing looked into, or one a later revision replaced, are not on the ledger.

The cases: the two orders of a lookup that fails and one that works; an object stream whose own
length is an object held in another object stream; an /Extends entry that names a stream no lookup
reaches; a member replaced by a later revision; a member moved to another place by a later revision.

Every document is built here. Two widgets name the same decode parameter object (6), so the first
page walk looks it up and the second would look it up again.
"""
import zlib

from PyPDF2 import PdfReader
from PyPDF2 import filters as pdf_filters

from sunglasses.extractors import pdf as pdf_module
from sunglasses.extractors.pdf import PDFExtractor

SMALL = 4096
LARGE = 1 << 16


def _stream(keys, data):
    return b'<< ' + keys + b' /Length ' + str(len(data)).encode() + b' >>\nstream\n' + data + b'\nendstream'


def _form(parms):
    return _stream(b'/Type /XObject /Subtype /Form /BBox [0 0 1 1] /Filter [/FlateDecode /FlateDecode] '
                   b'/DecodeParms ' + parms + b' 0 R', zlib.compress(zlib.compress(bytes(512))))


def _objstm(members, pad, extra=b'', length=None):
    """A compressed object stream holding `members` {number: body}, then `pad` blanks, as (keys, data)."""
    header, body = b'', b''
    for number, text in members.items():
        header += str(number).encode() + b' ' + str(len(body)).encode() + b' '
        body += text + b' '
    data = zlib.compress(header + body + b' ' * pad)
    keys = (b'/Type /ObjStm /N ' + str(len(members)).encode() + b' /First ' + str(len(header)).encode()
            + b' /Filter /FlateDecode ' + extra)
    if length is None:
        return _stream(keys, data)
    return b'<< ' + keys + b' /Length ' + length + b' >>\nstream\n' + data + b'\nendstream'


def _pages():
    return {
        1: b'<< /Type /Catalog /Pages 2 0 R >>',
        2: b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        3: b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] /Resources << >> /Annots [9 0 R 11 0 R] >>',
        5: _form(b'6'),
        9: b'<< /Type /Annot /Subtype /Widget /Rect [0 0 1 1] /AP << /N 5 0 R >> >>',
        10: _form(b'12'),
        11: b'<< /Type /Annot /Subtype /Widget /Rect [0 0 1 1] /AP << /N 10 0 R >> >>',
    }


def _revision(data, objects, compressed, xref_number, size, previous=None):
    """Append `objects` {number: body} as plain objects, then a cross reference stream whose entries
    for `compressed` {number: (stream number, index)} point into object streams. Returns the bytes
    and the cross reference stream's offset."""
    offsets = {}
    for number, body in sorted(objects.items()):
        offsets[number] = len(data)
        data += str(number).encode() + b' 0 obj\n' + body + b'\nendobj\n'
    offsets[xref_number] = len(data)
    entries, index = [], []
    wanted = sorted(set(offsets) | set(compressed))
    for number in wanted:
        if number in compressed:
            kind, a, b = 2, compressed[number][0], compressed[number][1]
        else:
            kind, a, b = 1, offsets[number], 0
        entries.append(bytes([kind]) + a.to_bytes(4, 'big') + b.to_bytes(2, 'big'))
        index += [number, 1]
    keys = (b'/Type /XRef /Root 1 0 R /Size ' + str(size).encode() + b' /W [1 4 2] /Index ['
            + b' '.join(str(i).encode() for i in index) + b']'
            + (b' /Prev ' + str(previous).encode() if previous is not None else b''))
    data += (str(xref_number).encode() + b' 0 obj\n' + _stream(keys, b''.join(entries))
             + b'\nendobj\nstartxref\n' + str(offsets[xref_number]).encode() + b'\n%%EOF\n')
    return data, offsets[xref_number]


def _document(plain, compressed, size=20, xref_number=8):
    data, _ = _revision(b'%PDF-1.5\n', plain, compressed, xref_number, size)
    return data


def _run(tmp_path, monkeypatch, data, budget=1 << 22):
    path = tmp_path / 'case.pdf'
    path.write_bytes(data)
    monkeypatch.setattr(pdf_module._ReadBudget, 'MAX_BYTES', budget)
    native = []
    real = pdf_filters.FlateDecode.decode

    def spy(data, decode_parms=None, **kwargs):
        out = real(data, decode_parms, **kwargs)
        native.append(len(out))
        return out

    monkeypatch.setattr(pdf_filters.FlateDecode, 'decode', staticmethod(spy))
    extractor = PDFExtractor()
    extractor.extract(str(path))
    return extractor, native


def _two_members(pad_first=SMALL, pad_second=0):
    """Objects 6 and 12 in one stream (7): the two decode parameter objects of the two widgets."""
    plain = _pages()
    plain[7] = _objstm({6: b'<< /Predictor 1 >>', 12: b'<< /Predictor 1 >>'}, pad_first)
    return plain, {6: (7, 0), 12: (7, 1)}


def _length_stream():
    """Stream 7 holds the decode parameters and its /Length is object 13, a number held in stream 14,
    so reading 7 looks into 14 first. The number is the real length of 7's data."""
    body = {6: b'<< /Predictor 1 >>', 12: b'<< /Predictor 1 >>'}
    sized = _objstm(body, SMALL, length=b'0')
    length = len(sized.split(b'stream\n', 1)[1].rsplit(b'\nendstream', 1)[0])
    plain = _pages()
    plain[7] = _objstm(body, SMALL, length=b'13 0 R')
    plain[14] = _objstm({13: str(length).encode()}, SMALL)
    return plain, {6: (7, 0), 12: (7, 1), 13: (14, 0)}


def _breaking_on(number, when):
    """A reader whose lookup of object `number` raises as a call stack that is too deep does, on the
    calls `when` (counted from 1, among the lookups of that number) says should fail. Returns the
    replacement accessor and the list of outcomes, True for a lookup that was made to fail."""
    real = PdfReader.get_object
    outcomes = []

    def get_object(self, indirect_reference):
        found = getattr(indirect_reference, 'idnum', indirect_reference)
        if found == number:
            failed = bool(when(len(outcomes) + 1))
            outcomes.append(failed)
            if failed:
                raise RecursionError('too deep')
        return real(self, indirect_reference)

    return get_object, outcomes


def _ordinary(tmp_path, monkeypatch):
    plain, compressed = _two_members()
    return _run(tmp_path, monkeypatch, _document(plain, compressed))


def test_a_lookup_that_works_and_then_fails_deep_leaves_no_stream_to_the_reader(tmp_path, monkeypatch):
    # the reverse of round 17: the first lookups of the object stream work (the guard's own, and the
    # identity check after it), the lookup made for the other widget's member fails as a deep call
    # stack does; the guard holds the decoded stream, so the reader must not be asked to decode it,
    # and the stream is on the ledger once
    plain, compressed = _two_members()
    get_object, outcomes = _breaking_on(7, lambda n: n >= 3)
    monkeypatch.setattr(PdfReader, 'get_object', get_object)
    extractor, native = _run(tmp_path, monkeypatch, _document(plain, compressed))
    assert outcomes[:2] == [False, False] and True in outcomes[2:], outcomes
    assert native == [], native
    assert SMALL <= extractor.budget.read < 2 * SMALL, extractor.budget.read


def test_a_lookup_that_fails_deep_on_every_call_never_reaches_the_readers_decode(tmp_path, monkeypatch):
    # no lookup of the object stream works, so nothing is decoded, natively or on the ledger, and
    # the page is reported as not checked
    plain, compressed = _two_members()
    get_object, outcomes = _breaking_on(7, lambda n: True)
    monkeypatch.setattr(PdfReader, 'get_object', get_object)
    extractor, native = _run(tmp_path, monkeypatch, _document(plain, compressed))
    assert outcomes and all(outcomes), outcomes
    assert native == [], native
    assert extractor.budget.read < SMALL, extractor.budget.read
    assert extractor.failures, 'the page was not reported as not checked'


def test_an_object_stream_reached_through_the_length_of_another_is_decoded_once_and_charged(tmp_path, monkeypatch):
    # reading stream 7 looks into stream 14 first, inside the guard's own lookup of 7: both are
    # decoded by the guard, once each, and both are on the ledger
    plain, compressed = _length_stream()
    extractor, native = _run(tmp_path, monkeypatch, _document(plain, compressed))
    assert native == [], native
    assert 2 * SMALL <= extractor.budget.read < 3 * SMALL, extractor.budget.read
    assert extractor.failures == [], extractor.failures


def test_a_lookup_of_the_stream_that_holds_a_length_that_fails_leaves_nothing_to_the_reader(tmp_path, monkeypatch):
    # the same shape, with the one lookup of stream 14 failing deep inside the lookup of stream 7:
    # stream 7 cannot be read, so nothing in it is resolved and neither stream is decoded natively
    plain, compressed = _length_stream()
    get_object, outcomes = _breaking_on(14, lambda n: n == 1)
    monkeypatch.setattr(PdfReader, 'get_object', get_object)
    extractor, native = _run(tmp_path, monkeypatch, _document(plain, compressed))
    assert outcomes[:1] == [True], outcomes
    assert native == [], native
    assert extractor.budget.read < SMALL, extractor.budget.read
    assert extractor.failures, 'the page was not reported as not checked'


def test_an_extends_entry_names_a_stream_no_lookup_reaches_so_it_is_not_inflated(tmp_path, monkeypatch):
    # /Extends is not followed by the reader: the lookup goes by the cross reference table. A large
    # stream named there is neither decoded natively nor put on the ledger.
    plain = _pages()
    plain[7] = _objstm({6: b'<< /Predictor 1 >>', 12: b'<< /Predictor 1 >>'}, SMALL, extra=b'/Extends 15 0 R')
    plain[15] = _objstm({16: b'null'}, LARGE)
    compressed = {6: (7, 0), 12: (7, 1), 16: (15, 0)}
    extractor, native = _run(tmp_path, monkeypatch, _document(plain, compressed))
    assert native == [], native
    assert SMALL <= extractor.budget.read < LARGE // 2, extractor.budget.read
    assert extractor.failures == [], extractor.failures


def test_an_extends_entry_names_a_stream_that_holds_a_member_the_page_uses(tmp_path, monkeypatch):
    # the stream named by /Extends does hold object 12, and the cross reference table says so: that
    # lookup goes to it as a stream of its own, decoded once and charged, and 7 is charged for 6 only
    plain = _pages()
    plain[7] = _objstm({6: b'<< /Predictor 1 >>'}, SMALL, extra=b'/Extends 15 0 R')
    plain[15] = _objstm({12: b'<< /Predictor 1 >>'}, SMALL)
    compressed = {6: (7, 0), 12: (15, 0)}
    extractor, native = _run(tmp_path, monkeypatch, _document(plain, compressed))
    assert native == [], native
    assert 2 * SMALL <= extractor.budget.read < 3 * SMALL, extractor.budget.read
    assert extractor.failures == [], extractor.failures


def test_an_incremental_update_that_replaces_a_member_charges_the_new_stream_and_not_the_old(tmp_path, monkeypatch):
    # revision one holds 6 and 12 in a large stream (7); an update puts both in a small new one (9)
    plain = _pages()
    plain[7] = _objstm({6: b'<< /Predictor 1 >>', 12: b'<< /Predictor 1 >>'}, LARGE)
    first, previous = _revision(b'%PDF-1.5\n', plain, {6: (7, 0), 12: (7, 1)}, 8, 20)
    data, _ = _revision(first, {9: b'<< /Type /Annot /Subtype /Widget /Rect [0 0 1 1] /AP << /N 5 0 R >> >>',
                                17: _objstm({6: b'<< /Predictor 1 >>', 12: b'<< /Predictor 1 >>'}, SMALL)},
                        {6: (17, 0), 12: (17, 1)}, 18, 20, previous=previous)
    extractor, native = _run(tmp_path, monkeypatch, data)
    assert native == [], native
    assert SMALL <= extractor.budget.read < LARGE // 2, extractor.budget.read
    assert extractor.failures == [], extractor.failures


def test_an_incremental_update_that_moves_a_member_in_its_stream_charges_the_stream_it_reads(tmp_path, monkeypatch):
    # revision one: 6 at index 0 of a large stream 7. The update writes stream 7 again, small, with 12
    # first and 6 second, and says so in its cross reference stream: the old bytes are not on the ledger
    plain = _pages()
    plain[7] = _objstm({6: b'<< /Predictor 1 >>', 12: b'<< /Predictor 1 >>'}, LARGE)
    first, previous = _revision(b'%PDF-1.5\n', plain, {6: (7, 0), 12: (7, 1)}, 8, 20)
    data, _ = _revision(first, {7: _objstm({12: b'<< /Predictor 1 >>', 6: b'<< /Predictor 1 >>'}, SMALL)},
                        {6: (7, 1), 12: (7, 0)}, 18, 20, previous=previous)
    extractor, native = _run(tmp_path, monkeypatch, data)
    assert native == [], native
    assert SMALL <= extractor.budget.read < LARGE // 2, extractor.budget.read
    assert extractor.failures == [], extractor.failures


def test_the_ordinary_two_member_stream_is_charged_once_for_two_lookups(tmp_path, monkeypatch):
    # the control for the ledger bounds above
    extractor, native = _ordinary(tmp_path, monkeypatch)
    assert native == [], native
    assert SMALL <= extractor.budget.read < 2 * SMALL, extractor.budget.read
