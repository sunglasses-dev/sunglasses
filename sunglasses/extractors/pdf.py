"""
SUNGLASSES PDF Extractor — Scans PDFs for hidden prompt injection.

Extracts text from PDFs using multiple methods:
1. Page text — visible text content on each page
2. Metadata — document properties (title, author, subject, keywords, creator)
3. Annotations — comment text and author
4. Form field values — /V, /DV, /RV, /TU and /Opt of the AcroForm fields, and /V
   of widgets outside /AcroForm (XFA form data is reported as not inspected)
5. JavaScript — /OpenAction, /AA and /Names /JavaScript actions of the document,
   its pages, annotations and fields (bounded, see MAX_ACTIONS)
6. Embedded files — text attachments up to MAX_ATTACHMENT_BYTES (raw, or decoded by
   a bounded chain of Flate, ASCII85 and LZW stages) are read; other attachments,
   including PDF, PostScript and binary files, are reported as not inspected

Decoded content of one document is read from a single _ReadBudget, and the part
that a bound leaves unread is recorded in `failures`.

Usage:
    from sunglasses.extractors.pdf import scan_pdf
    result = scan_pdf("/path/to/document.pdf")

Install: pip install sunglasses[pdf]  (requires PyPDF2)
"""

import contextlib
import os
import re
import zlib
from typing import List, Optional, Tuple


def _check_deps():
    """Check that PDF scanning dependencies are installed."""
    try:
        import PyPDF2  # noqa: F401
    except ImportError:
        raise ImportError(
            "PDF scanning requires PyPDF2. "
            "Install with: pip install sunglasses[pdf]"
        )


class _WalkBudget(Exception):
    """The document holds more decoded content than the checks will read."""


# The bytes of the document budget that one visit of an annotation, a state, a stream or an
# entry costs besides the content it reads. Both walks of this module charge it.
_VISIT_COST = 32


class _ReadBudget:
    """Decoded bytes read from one document. Every check that decodes a stream
    spends from the same budget, so the cost of a document is bounded once and
    not once per check."""

    MAX_BYTES = 64 << 20

    def __init__(self):
        self.read = 0

    def remaining(self) -> int:
        return max(0, self.MAX_BYTES - self.read)

    def spend(self, size: int) -> None:
        """Charge a read. A read that does not fit spends the rest of the budget
        and raises, so later reads find nothing left."""
        if size > self.remaining():
            self.read = self.MAX_BYTES
            raise _WalkBudget()
        self.read += size


def _lzw_length(data: bytes, limit: int) -> Optional[int]:
    """The length PyPDF2's LZW decoder would produce, counted without building the
    output and stopped as soon as it passes `limit`. None when the code stream is not
    one the decoder reads."""
    lengths = [1] * 256 + [0] * (4096 - 256)
    total, pos, bits, dictlen, code = 0, 0, 9, 258, 256
    nbits = len(data) * 8
    while True:
        previous = code
        if pos + bits > nbits:
            return None
        window = int.from_bytes(data[pos >> 3:(pos >> 3) + 3].ljust(3, b"\0"), "big")
        code = (window >> (24 - (pos & 7) - bits)) & ((1 << bits) - 1)
        pos += bits
        if code == 257:
            return total
        if code == 256:
            dictlen, bits = 258, 9
            continue
        if previous == 256:
            total += lengths[code]
        else:
            if dictlen >= 4096:
                return None
            if code < dictlen:
                total += lengths[code]
                lengths[dictlen] = lengths[previous] + 1
            else:
                lengths[dictlen] = lengths[previous] + 1
                total += lengths[dictlen]
            dictlen += 1
            if dictlen >= (1 << bits) - 1 and bits < 12:
                bits += 1
        if total > limit:
            return total


class _Decoded:
    """The result of one bounded decode: the data (None when it was refused), the bytes
    produced by every stage, and why it was refused."""

    __slots__ = ("data", "spent", "state", "detail", "notes", "made")

    def __init__(self, data=None, spent=0, state="ok", detail="", notes=()):
        self.data = data
        self.made = 0         # what the stages produced; a cap on the output is measured against it
        self.spent = spent
        self.state = state    # ok | big | unsized | error
        self.detail = detail
        self.notes = list(notes)


_ASCII85_SKIP = bytes(b for b in range(256) if not 33 <= b <= 117)
_FLATE = ('/FlateDecode', '/Fl')
_ASCII85 = ('/ASCII85Decode', '/A85')
_LZW = ('/LZWDecode', '/LZW')
# One inflate call is asked for no more than this. A call that fails returns nothing, so the
# most it can have made is charged to the stream (see _decode_bounded).
_INFLATE_STEP = 1 << 16
# The longest filter chain, or list of decode parameters, that the decoder reads.
_MAX_CHAIN = 16
# The longest filter name the decoder turns into text. The longest real one is /RunLengthDecode.
_MAX_NAME = 64
# The longest text or byte value read as a number: no number written in a PDF has more digits.
_MAX_NUMBER = 32


def _deref(obj):
    return obj.get_object() if hasattr(obj, 'get_object') else obj


def _entries_of(seq, charge):
    """The entries of an array the decoder is about to read, one at a time. `charge` is called
    before each is handed over, so no entry is resolved that was not paid for, and an array
    longer than any real chain is refused before the first one. This is the one place the
    decoder touches the entries of an array in its setup."""
    if len(seq) > _MAX_CHAIN:
        raise ValueError(f"more than {_MAX_CHAIN} entries")
    for entry in seq:
        charge()
        yield entry


def _name_text(name):
    """A filter name as text. Nothing longer than any real name is converted, and a value that
    is not a name at all is not either; both come back as a name no filter has, so the chain
    is refused as not sized."""
    if isinstance(name, (str, bytes)) and len(name) <= _MAX_NAME:
        return str(name)
    return "/?"


def _filters_of(stream, charge):
    """The filter names of a stream, in order, or None when it names more than _MAX_CHAIN."""
    if '/Filter' not in stream:
        return []
    names = _deref(stream.get('/Filter'))
    if isinstance(names, (list, tuple)):
        if len(names) > _MAX_CHAIN:
            return None
        return [_name_text(_deref(n)) for n in _entries_of(names, charge)]
    return [] if names is None else [_name_text(names)]


def _inflate(data: bytes, room: int):
    """Inflate a zlib or gzip stream, no further than `room` bytes. The header is read
    here and the checksum is not checked, so data whose only fault is a bad checksum is
    kept, as PyPDF2 keeps it. Returns (output, reached_end, data_after_end, damaged)."""
    start, trailer = None, 4
    if len(data) >= 2 and data[0] & 0x0f == 8 and (data[0] << 8 | data[1]) % 31 == 0 \
            and not data[1] & 0x20:
        start = 2
    elif data[:3] == b"\x1f\x8b\x08" and len(data) >= 10:
        flags, pos, trailer = data[3], 10, 8
        if flags & 4:
            pos += 2 + int.from_bytes(data[pos:pos + 2], "little")
        for bit in (8, 16):
            if flags & bit:
                end = data.find(b"\0", pos)
                pos = len(data) if end < 0 else end + 1
        if flags & 2:
            pos += 2
        if pos <= len(data):
            start = pos
    if start is None:
        raise ValueError("not a zlib or gzip stream")
    inflater = zlib.decompressobj(-zlib.MAX_WBITS)
    chunks, total, pos, pending, damaged = [], 0, start, b"", False
    while True:
        if not pending:
            if pos >= len(data) or inflater.eof:
                break
            pending, pos = data[pos:pos + 65536], pos + 65536
        try:
            out = inflater.decompress(pending, min(room + 1 - total, _INFLATE_STEP))
        except zlib.error:
            damaged = True
            break
        rest = inflater.unconsumed_tail
        if not out and len(rest) == len(pending):
            break
        pending = rest
        chunks.append(out)
        total += len(out)
        if total > room or inflater.eof:
            break
    # At the end of the stream the bytes the call did not use are in unused_data and also in
    # unconsumed_tail, so `pending` is not added a second time.
    after = (inflater.unused_data + data[pos:])[trailer:] if inflater.eof else b""
    return b"".join(chunks), inflater.eof, after, damaged


def _ascii85_length(data: bytes) -> int:
    """The length ASCII85 decoding produces, counted without decoding."""
    body = data.split(b"~", 1)[0]
    digits = len(body.translate(None, _ASCII85_SKIP))
    return (digits // 5) * 4 + max(0, digits % 5 - 1) + 4 * body.count(b"z")


def _whole(value):
    """A decode parameter as a whole number. A text or byte value longer than any number is not
    converted; it is refused the way a value that is not a number is, so the stream is reported
    as an error."""
    if not isinstance(value, (str, bytes)) or len(value) <= _MAX_NUMBER:
        return int(value)
    raise ValueError("not a number")


def _predictor_of(params, charge):
    """(predictor, columns, bits per component) the way PyPDF2 reads them. A list of
    parameters is charged entry by entry."""
    resolve = _deref
    params = resolve(params)
    predictor, columns, bits = 1, 1, 8
    entries = _entries_of(params, charge) if isinstance(params, (list, tuple)) else [params]
    for entry in entries:
        entry = resolve(entry)
        if not hasattr(entry, 'get'):
            continue
        predictor = resolve(entry.get('/Predictor', predictor))
        columns = resolve(entry.get('/Columns', columns))
        bits = resolve(entry.get('/BitsPerComponent', bits))
    return _whole(predictor), _whole(columns), _whole(bits)


def _decode_bounded(stream, room: int, charge=lambda: 0, left=None, commit=None, cap=None) -> "_Decoded":
    """Decode a stream's filter chain one stage at a time, so that no stage runs past what
    is left of the budget and nothing is decoded twice. Every stage's output, the
    intermediate ones included, is added to `spent`, and the chain is refused (state
    "big") as soon as that sum passes `room`. A Flate stage is inflated no further than
    `room` and gzip is read as well as zlib. ASCII85 and LZW are counted before they are
    decoded, and the input they read to count is charged first when it is the stream's own. A predictor is applied to the bounded output. A chain with a filter that is
    not sized here (hex, run length, an image filter, /Crypt, LZW that is not the last
    filter) is refused with state "unsized", and a stage that fails with "error". The
    reader's own get_data() is never called. `charge` is called before every entry of the
    filter list and of the decode parameters is resolved, and raises _WalkBudget when the
    document budget is gone; that exception is not caught here. It returns the bytes it
    charged, and they come off `room` as soon as they are spent, so the stages are sized
    against what is left and not against what was left when the call began. A dereference in
    the setup can spend the document budget directly (it can inflate an object stream), and
    that is not in what `charge` returns; `left`, when given, returns what the budget has
    left, and the allowance is brought down to it before each stage and after the decode
    parameters are read.

    A dereference can also decode, and the decode it starts is sized against the document
    budget. `commit`, when given, puts what this decoder has spent so far on that budget
    (and raises _WalkBudget if it does not fit) before the decode parameters are resolved, so
    the nested decode sees it. What is returned in `spent` is then only the part not yet
    committed, and a caller that charges it has charged the whole once.

    `cap`, when given, limits what the stages produce, apart from the allowance: the stream's
    own input counts toward the allowance and not toward the cap. A chain refused for the cap
    comes back with state "big" and detail "cap"."""
    committed = [0]
    result = _decode_stages(stream, room, charge, left, commit, cap, committed)
    result.spent = max(0, result.spent - committed[0])
    return result


def _decode_stages(stream, room, charge, left, commit, cap, committed) -> "_Decoded":
    from PyPDF2 import filters as pdf_filters

    made = 0   # what the stages have produced; the stream's own input is not in it

    def paid():
        nonlocal room
        room -= charge() or 0

    def synced():
        # The allowance is what the budget has left, and what this decode has already put on
        # the budget is part of what it may use.
        nonlocal room
        if left is not None:
            room = min(room, left() + committed[0])

    def settle():
        if commit is not None and out.spent > committed[0]:
            commit(out.spent - committed[0])
            committed[0] = out.spent

    def produce(size, extra=0):
        nonlocal made
        made += size
        out.spent += size + extra

    def over_cap():
        return cap is not None and made > cap

    def refuse():
        # Past the allowance: charged as everything that is left, so the budget is gone.
        # Past the cap alone: charged what was read and made.
        if out.spent > room:
            return _Decoded(spent=max(room, 0) + 1, state="big")
        return _Decoded(spent=out.spent, state="big", detail="cap")

    def stage_room():
        return room - out.spent if cap is None else min(room - out.spent, cap - made)

    names = _filters_of(stream, paid)
    if names is None:
        return _Decoded(state="unsized", detail=f"a chain of more than {_MAX_CHAIN} filters")
    data = getattr(stream, '_data', None) or b""
    out = _Decoded(data=data)
    if not data:
        return out
    def over():
        # A charge can come after a stage (the decode parameters are charged once the stage has run),
        # so what is left is worked out again before each stage, and a stage is never started on
        # nothing: a zero limit means "no limit" to zlib.
        return out.spent >= room or (cap is not None and made >= cap)
    try:
        for i, name in enumerate(names):
            synced()
            if out.spent >= room:
                return _Decoded(spent=max(room, 0) + 1, state="big")
            if over():
                return _Decoded(spent=out.spent, state="big", detail="cap")
            if name in _FLATE:
                # The stream's own input is read whole, so it is paid for before it is read (a
                # later stage's input is the stage before's output, charged already).
                # Nothing is left to inflate into when it is all gone: a zero limit means "no
                # limit" to zlib.
                if i == 0:
                    out.spent += len(data)
                    if out.spent >= room:
                        return _Decoded(spent=max(room, 0) + 1, state="big")
                data, reached_end, after, damaged = _inflate(data, stage_room())
                produce(len(data), _INFLATE_STEP if damaged else 0)
                if out.spent > room or over_cap():
                    return refuse()
                if damaged or not reached_end:
                    out.notes.append("compressed data ends before its stream does; "
                                     "the rest was not inspected")
                elif after.strip(b"\x00\t\n\x0c\r "):
                    out.notes.append("holds data after the end of its compressed stream; "
                                     "that data was not inspected")
                # Resolving the decode parameters can decode again, so what has been spent so
                # far is on the budget before it is resolved.
                settle()
                predictor, columns, bits = _predictor_of(stream.get('/DecodeParms'), paid)
                synced()
                if out.spent > room:
                    return _Decoded(spent=max(room, 0) + 1, state="big")
                if predictor != 1:
                    if not 10 <= predictor <= 15:
                        raise ValueError("unsupported predictor")
                    if columns < 1 or bits < 1:
                        raise ValueError("unsupported predictor dimensions")
                    rowlength = -(-columns * bits // 8) + 1
                    # The reader's predictor keeps one row of the declared length even when
                    # there is nothing to predict, and makes its output before anyone asks
                    # whether it fits, so both are settled here against what is left.
                    if data:
                        if rowlength > room - out.spent or out.spent + len(data) > room:
                            return _Decoded(spent=room + 1, state="big")
                        if cap is not None and made + len(data) > cap:
                            return _Decoded(spent=out.spent, state="big", detail="cap")
                        # The output is at most as long as the input. It is reserved before the
                        # reader runs, so a predictor that fails after it has made rows is still
                        # charged for them, and the charge is trued up when it succeeds.
                        reserved = len(data)
                        produce(reserved)
                        data = pdf_filters.FlateDecode._decode_png_prediction(data, columns, rowlength)
                        produce(len(data) - reserved)
            elif name in _ASCII85:
                # Sizing reads every input byte, so the input is paid for before it is read
                # (a later stage's input is the stage before's output, charged already).
                if i == 0:
                    out.spent += len(data)
                if out.spent > room:
                    return _Decoded(spent=room + 1, state="big")
                size = _ascii85_length(data)
                produce(size)
                if out.spent > room or over_cap():
                    return refuse()
                data = pdf_filters.ASCII85Decode.decode(data)
            elif name in _LZW and i == len(names) - 1:
                # The same for the code stream: it is charged before it is scanned, and the
                # charge stays on the "unsized" return below.
                if i == 0:
                    out.spent += len(data)
                if out.spent > room:
                    return _Decoded(spent=room + 1, state="big")
                size = _lzw_length(data, stage_room())
                if size is None:
                    return _Decoded(spent=out.spent, state="unsized", detail=name)
                produce(size)
                if out.spent > room or over_cap():
                    return refuse()
                data = pdf_filters.LZWDecode.decode(data)
                if len(data) > size:
                    return _Decoded(spent=room + 1, state="big")
            else:
                return _Decoded(spent=out.spent, state="unsized", detail=name)
    except _WalkBudget:
        raise
    except Exception as exc:
        return _Decoded(spent=out.spent, state="error", detail=exc.__class__.__name__)
    if isinstance(data, str):
        data = data.encode('latin-1', 'replace')
    out.data = data
    out.made = made
    if not names:
        out.spent = len(data)
    return out



# The tail the PDF reader needs to find the cross reference table. The reader searches the
# whole data backwards for %%EOF and reads the line in front of it: either an offset (taken
# with int(), so a sign and digit separators are accepted) with a line that starts with
# "startxref" before that, which may carry other text after the keyword, or one line that
# starts with "startxref" and holds the offset after it. It does not care what follows
# %%EOF, so the tail is looked for anywhere.
_XREF_OFFSET = rb'[+-]?\d[\d_]*'
_XREF_TAIL = re.compile(
    rb'startxref(?:[^\r\n]*[\r\n]+\s*' + _XREF_OFFSET + rb'|\s*' + _XREF_OFFSET + rb')\s*%%EOF')

# Bytes that may appear in text; a file with others in its first 8 KiB is binary.
_TEXT_BYTES = bytes([9, 10, 11, 12, 13, 27]) + bytes(range(32, 127)) + bytes(range(128, 256))
_FORMAT_MAGIC = (
    (b'%!PS', 'PostScript'),
    (b'PK\x03\x04', 'zip'),
    (b'PK\x05\x06', 'zip'),
    (b'\x1f\x8b', 'gzip'),
    (b'\x7fELF', 'ELF'),
    (b'\x89PNG', 'PNG'),
    (b'GIF8', 'GIF'),
    (b'\xff\xd8\xff', 'JPEG'),
)

# A bounded lexer over decoded content. Comments, literal strings, hex strings and the
# binary data of an inline image are skipped, so only an operator that the content really
# carries is read. Each step moves forward, so a document costs one pass over its bytes.
_REG = rb"[^\s\x00/\[\]()<>{}%]"
_TOKEN = re.compile(
    rb"(?P<comment>%[^\r\n]*)"
    rb"|(?P<string>\()"
    rb"|(?P<punct><<|>>|[\[\]{}])"
    rb"|(?P<hex><[^>]*>?)"
    rb"|(?P<name>/" + _REG + rb"*)"
    rb"|(?P<op>(?:Do|BI|ID|Tf|gs)(?!" + _REG + rb"))"
    rb"|(?P<other>" + _REG + rb"+)")
_STRING_EDGE = re.compile(rb"[()\\]")
_END_IMAGE = re.compile(rb"[\s\x00]EI(?!" + _REG + rb")")
_NAME_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")


def _name(raw: bytes) -> str:
    """A name operand read the way PyPDF2 reads the keys of a resource dictionary:
    the #xx escapes are undone first, then the bytes are read as UTF-8, then as GBK,
    and what neither reads is mapped one byte to one character. The slash is kept."""
    data = _NAME_ESCAPE.sub(lambda m: bytes([int(m.group(1), 16)]), raw)
    for encoding in ("utf-8", "gbk"):
        try:
            return "/" + data.decode(encoding)
        except UnicodeDecodeError:
            pass
    return "/" + data.decode("latin-1")


def _skip_string(data: bytes, pos: int) -> int:
    depth = 1
    while depth:
        edge = _STRING_EDGE.search(data, pos)
        if not edge:
            return len(data)
        char = edge.group(0)
        if char == b"\\":
            pos = edge.end() + 1
        else:
            depth += 1 if char == b"(" else -1
            pos = edge.end()
    return pos


def _drawn_operations(data: bytes):
    """Return the number of inline images, the names a Do operator draws, the
    names a Tf operator selects as the font and the names a gs operator selects as
    the graphics state."""
    if b"Do" not in data and b"BI" not in data and b"Tf" not in data and b"gs" not in data:
        return 0, [], [], []
    inline, names, fonts, states = 0, [], [], []
    last, font, pos, in_dict = None, None, 0, False
    while pos < len(data):
        match = _TOKEN.search(data, pos)
        if not match:
            break
        kind, pos = match.lastgroup, match.end()
        if kind == "comment":
            continue
        if kind == "name":
            last = font = match.group(0)[1:]
            continue
        if kind == "string":
            pos = _skip_string(data, pos)
        elif kind == "op":
            token = match.group(0)
            if token == b"Do" and not in_dict and last is not None:
                names.append(last)
            elif token == b"gs" and not in_dict and last is not None:
                states.append(last)
            elif token == b"Tf" and not in_dict and font is not None:
                fonts.append(font)
                font = None
            elif token == b"BI" and not in_dict:
                inline += 1
                in_dict = True
            elif token == b"ID" and in_dict:
                end = _END_IMAGE.search(data, pos)
                pos = end.end() if end else len(data)
                in_dict = False
        last = None
    return inline, names, fonts, states


_FAR = 1 << 30


class _ImageWalk:
    """One bounded visit of a document's painted pictures. A picture counts only
    where a Do operator draws it (or an inline image sits in the content), so an
    unused resource entry does not. A form is read once and its count is kept, so
    pages that share forms or resources cost one visit, and the decoded content
    read over the whole document is capped. Content is decoded stage by stage by
    `_decode_bounded`, which charges every stage (the intermediate output of a chain
    too) and refuses a chain it cannot size; the reader's own decode is not used. A
    Type3 font held as a direct dictionary is keyed by the identity of that dictionary,
    and every stream visit is charged `VISIT_COST` besides its content. An annotation
    with the Hidden or NoView flag draws nothing and is not visited.

    A name is looked up in the resources of the form or group that draws it and then
    in the resources of whatever encloses it, the way a renderer does, so a form with
    resources of its own can still draw a name that only the page holds.

    Every count is a triple: pictures drawn, Type3 fonts in use whose glyph
    procedures paint pictures, and drawing operators whose resource name could not
    be matched (a name that is not plain ASCII). The last two are not pictures this check
    counted, so they are reported as content that was not inspected."""

    MAX_FORM_DEPTH = 8
    MAX_GLYPHS = 512
    MAX_APPEARANCES = 64
    VISIT_COST = _VISIT_COST   # bytes of the document budget for each annotation, state and stream visited

    def __init__(self, budget):
        self.budget = budget
        self.stopped = False
        self.notes = []      # what the decoder said about streams it read only in part
        self.cache = {}
        self.appearances = {}
        self.open = []       # keys of the forms and fonts being read, outermost first
        self.low = _FAR      # the lowest place in `open` that a revisit cut, below the node read now
        self.reach = _FAR    # the lowest level of resources consulted below the node read now

    @staticmethod
    def _sum(*parts):
        return tuple(sum(p[i] for p in parts) for i in range(3))

    def _visit(self) -> int:
        """Charge one visit to the document budget and return what was charged."""
        self.budget.spend(self.VISIT_COST)
        return self.VISIT_COST

    def _open(self, ref):
        """The object a reference stands for, resolved after its visit is charged. Every
        object the walk reaches by iterating something the document supplies (the entries
        of an array, the names a content stream draws, the keys of a dictionary) comes
        through here, so no resolution is made that was not paid for."""
        self._visit()
        return _resolve(ref)

    def painted_images(self, holder, depth):
        self._visit()   # the page; its own resources and content are looked up under this visit
        resources = _resolve(holder.get('/Resources')) if hasattr(holder, 'get') else None
        scope = (resources,) if resources else ()
        return self._sum(self._count(holder, scope, depth),
                         self._appearances(holder, scope))

    def _find(self, scope, kind, name):
        """The entry `name` of the resource table `kind`, looked up in the innermost
        resources first and then outward. None when no resources hold it."""
        for i, resources in enumerate(scope):
            level = len(scope) - 1 - i
            if level < self.reach:
                self.reach = level
            table = _resolve(resources.get(kind)) if hasattr(resources, 'get') else None
            if hasattr(table, 'raw_get') and name in table:
                return table.raw_get(name)
        return None

    @staticmethod
    def _not_shown(annot) -> bool:
        """An annotation whose flags set Hidden (bit 2) or NoView (bit 6) is not drawn. A flag
        field that is not a number is not read as a flag."""
        flags = _resolve(annot.get('/F')) if hasattr(annot, 'get') else None
        return isinstance(flags, int) and not isinstance(flags, bool) and bool(flags & 0b100010)

    def _appearances(self, page, scope):
        """Pictures drawn by the normal appearance of each annotation on the page.
        Pages that share an annotation list under the same resources share one visit,
        and every annotation and state that is visited is charged."""
        annots = _resolve(page.get('/Annots')) if hasattr(page, 'get') else None
        if not isinstance(annots, list):
            return (0, 0, 0)
        key = (id(annots), tuple(id(r) for r in scope))
        if key in self.appearances:
            return self.appearances[key][0]
        from PyPDF2.generic import NameObject
        parts = []
        for annot in annots:
            annot = self._open(annot)
            if self._not_shown(annot):
                continue
            appearance = _resolve(annot.get('/AP')) if hasattr(annot, 'get') else None
            if not hasattr(appearance, 'raw_get') or '/N' not in appearance:
                continue
            ref = appearance.raw_get('/N')
            normal = _resolve(ref)
            if hasattr(normal, 'get_data'):
                states = [(ref, normal)]    # already read by the visit of the annotation
            elif hasattr(normal, 'raw_get'):
                if len(normal) > self.MAX_APPEARANCES:
                    raise ValueError(
                        f"more than {self.MAX_APPEARANCES} appearance states on one annotation")
                # The selected state is the one the annotation's /AS names. With no
                # /AS (or one that is not a name) every state is read, as the state a
                # viewer would pick is not known.
                chosen = _resolve(annot.get('/AS'))
                keys = [chosen] if isinstance(chosen, NameObject) else list(normal)
                # Each state is resolved after it is charged, not before (see _open).
                states = [(normal.raw_get(key), None) for key in keys if key in normal]
            else:
                continue
            for state_ref, stream in states:
                if stream is None:
                    stream = self._open(state_ref)
                else:
                    self._visit()
                if hasattr(stream, 'get_data'):
                    parts.append(self._form(stream, getattr(state_ref, 'idnum', None),
                                            scope, 1))
        found = self._sum((0, 0, 0), *parts)
        self.appearances[key] = (found, annots, scope)
        return found

    def _count(self, holder, scope, depth):
        data = self._content(holder)
        if not data:
            return (0, 0, 0)
        total, names, selected, states = _drawn_operations(data)
        glyphs = unmatched = 0
        seen = set()
        for raw in names:
            name = _name(raw)
            if name in seen:
                continue
            seen.add(name)
            ref = self._find(scope, '/XObject', name)
            if ref is None:
                # A plain name no resources hold draws nothing. A name that is not
                # plain ASCII is the case where two readings of the same bytes can
                # disagree, so a miss there is reported and not taken as nothing drawn.
                if not name.isascii():
                    unmatched += 1
                continue
            ident = getattr(ref, 'idnum', None)
            obj = self._open(ref)
            kind = obj.get('/Subtype') if hasattr(obj, 'get') else None
            if kind == '/Image':
                total += 1
            elif kind == '/Form':
                found = self._form(obj, ident, scope, depth + 1)
                total += found[0]
                glyphs += found[1]
                unmatched += found[2]
        for raw in states:
            name = _name(raw)
            if ("state", name) in seen:
                continue
            seen.add(("state", name))
            ref = self._find(scope, '/ExtGState', name)
            if ref is None:
                unmatched += 0 if name.isascii() else 1
                continue
            found = self._state(ref, scope, depth)
            total += found[0]
            glyphs += found[1]
            unmatched += found[2]
        for raw in selected:
            name = _name(raw)
            if ("font", name) in seen:
                continue
            seen.add(("font", name))
            ref = self._find(scope, '/Font', name)
            if ref is None:
                continue
            found = self._font(ref, scope, depth)
            glyphs += found[1]
            unmatched += found[2]
        return (total, glyphs, unmatched)

    def _font(self, ref, scope, depth):
        """A font in use: a Type3 font counts when any of its glyph procedures paints
        a picture. Which glyphs a page shows is not read."""
        font = self._open(ref)
        if not (hasattr(font, 'get') and font.get('/Subtype') == '/Type3'):
            return (0, 0, 0)
        found = self._type3(font, getattr(ref, 'idnum', None), scope, depth + 1)
        return (0, found[1] + (1 if found[0] else 0), found[2])

    def _state(self, ref, scope, depth):
        """What a graphics state selected with gs paints: the pictures of its soft-mask
        group (a form, read under the same walk and budget as any other form) and the
        glyph procedures of the Type3 font it sets in /Font. A state without a mask or
        a font, and a mask set to None, paint nothing. A mask whose group cannot be read
        is reported as content that was not inspected."""
        state = self._open(ref)
        if not hasattr(state, 'get'):
            return (0, 0, 0)
        parts = []
        mask = _resolve(state.get('/SMask'))
        if hasattr(mask, 'raw_get'):
            group_ref = mask.raw_get('/G') if '/G' in mask else None
            group = self._open(group_ref) if group_ref is not None else None
            if hasattr(group, 'get_data'):
                parts.append(self._form(group, getattr(group_ref, 'idnum', None), scope, depth + 1))
            else:
                parts.append((0, 0, 1))
        font = _resolve(state.get('/Font'))
        if isinstance(font, list) and font:
            parts.append(self._font(font[0], scope, depth))
        return self._sum((0, 0, 0), *parts)

    def _run(self, open_key, floor, own_key, scoped_key, scope, compute):
        """Read one form or font once. A node that is already being read ends the walk
        there (a cycle). A result is kept under `own_key` when nothing outside the node's
        own resources was consulted, under `scoped_key` (the exact chain of resources)
        otherwise, and not at all when a cycle through a node above it was cut inside it,
        because that result lacks what the cut part would have added."""
        if open_key is None:
            return compute()
        if open_key in self.open:
            self.low = min(self.low, self.open.index(open_key))
            return (0, 0, 0)
        for key in (own_key, scoped_key):
            if key is not None and key in self.cache:
                return self.cache[key][0]
        index = len(self.open)
        self.open.append(open_key)
        saved = (self.low, self.reach)
        self.low = self.reach = _FAR
        try:
            found = compute()
            low, reach = self.low, self.reach
        finally:
            self.open.pop()
            self.low, self.reach = saved
        if low < index:
            self.low = min(self.low, low)
        self.reach = min(self.reach, reach)
        if low < index:
            return found
        key = own_key if own_key is not None and reach >= floor else scoped_key
        if key is not None:
            self.cache[key] = (found, scope)
        return found

    def _type3(self, font, ident, parent_scope, depth):
        """The pictures the glyph procedures of a Type3 font paint. Which glyphs a
        page shows is not read, so a font in use counts as painting pictures when
        any of its procedures does."""
        if depth > self.MAX_FORM_DEPTH:
            raise ValueError(f"form nesting deeper than {self.MAX_FORM_DEPTH}")
        own = _resolve(font.get('/Resources'))
        scope = (own,) + parent_scope if own else parent_scope

        def compute():
            procs = _resolve(font.get('/CharProcs'))
            if not hasattr(procs, 'raw_get'):
                return (0, 0, 0)
            if len(procs) > self.MAX_GLYPHS:
                raise ValueError(f"more than {self.MAX_GLYPHS} glyph procedures in one font")
            parts = []
            for glyph in procs:
                stream = self._open(procs.raw_get(glyph))
                if hasattr(stream, 'get_data'):
                    parts.append(self._count(stream, scope, depth))
            return self._sum((0, 0, 0), *parts)

        # A font held as a direct dictionary has no object number. It is keyed by the
        # identity of the parsed dictionary, which the reader keeps for the whole walk.
        if ident is None:
            ident = ("direct", id(font))
        return self._run(*self._keys("type3", ident, own, parent_scope, scope), scope, compute)

    def _form(self, form, ident, parent_scope, depth):
        if depth > self.MAX_FORM_DEPTH:
            raise ValueError(f"form nesting deeper than {self.MAX_FORM_DEPTH}")
        own = _resolve(form.get('/Resources'))
        scope = (own,) + parent_scope if own else parent_scope
        return self._run(*self._keys("form", ident, own, parent_scope, scope), scope,
                         lambda: self._count(form, scope, depth))

    @staticmethod
    def _keys(kind, ident, own, parent_scope, scope):
        """(open key, level of the node's own resources, key when it reads the same
        under every page, key for this exact chain of resources)."""
        if ident is None:
            return None, _FAR, None, None
        return ((kind, ident), len(parent_scope) if own else _FAR,
                (kind, ident, "own") if own else None,
                (kind, ident, tuple(id(r) for r in scope)))

    def _content(self, holder) -> bytes:
        """The decoded content of a page (one stream or an array) or a form. Each stream
        goes through the bounded decoder: every stage is charged to the budget, the reader's
        own decode is never used, and a stream whose filters cannot be sized is not decoded."""
        paid = False   # a single stream is paid for by the visit that brought us here
        if hasattr(holder, 'get_data'):
            entries = [holder]
        else:
            contents = _resolve(holder.get('/Contents'))
            if contents is None:
                return b""
            if isinstance(contents, list):
                entries, paid = contents, True
            else:
                entries = [contents]
        out = []
        for entry in entries:
            # An entry of an array is paid for before it is resolved or decoded, so an
            # array of streams that decode to nothing costs the budget and stops at it.
            stream = self._open(entry) if paid else _resolve(entry)
            if not hasattr(stream, 'get_data'):
                continue
            # The decoder puts what it has spent on the budget before it resolves a decode
            # parameter (a dereference can decode too), and returns only the rest.
            result = _decode_bounded(stream, self.budget.remaining(), self._visit,
                                     self.budget.remaining, self.budget.spend)
            # What was decoded is charged whatever the chain's state, so a chain that is
            # refused after its first stages cannot be repeated for free on every page.
            self.budget.spend(result.spent)
            if result.state == "unsized":
                raise ValueError(f"a content stream with the filter {result.detail} cannot be sized, "
                                 f"so it was not decoded")
            if result.state != "ok":
                raise ValueError(f"a content stream could not be decoded ({result.detail})")
            self.notes.extend(result.notes)
            out.append(result.data)
        return b"\n".join(out)


def _resolve(obj):
    return obj.get_object() if hasattr(obj, 'get_object') else obj


class PDFExtractor:
    """Extract text from PDFs for SUNGLASSES scanning."""

    # Populated when a sub-parser could not finish. The caller MUST treat a
    # non-empty list as incomplete coverage: a PDF whose annotations we abandoned
    # halfway is not a PDF we read.
    failures: List[str] = []

    # Bounds for the containers added for finding A3 (form values, scripts,
    # attachments). Passing a bound is RECORDED in `failures`, not silent.
    MAX_FORM_FIELDS = 10_000
    MAX_ACTIONS = 256
    MAX_ATTACHMENTS = 64
    MAX_ATTACHMENT_BYTES = 1 << 20
    MAX_ARRAY_MEMBERS = 4096
    MAX_ARRAY_DEPTH = 16
    MAX_OUTLINE_ITEMS = 4096
    MAX_PARENT_DEPTH = 32
    # Charged to the document budget for every member, annotation or outline item
    # that is visited, whatever it holds, so walk work is bounded by the budget.
    VISIT_COST = _VISIT_COST
    _FIELD_TEXT_KEYS = ('/V', '/DV', '/RV', '/TU', '/Opt')
    _EF_KEYS = ('/UF', '/F', '/DOS', '/Mac', '/Unix')

    def __init__(self):
        _check_deps()
        self.failures = []
        self._reset_document_state()

    def _reset_document_state(self) -> None:
        """Everything that must not leak from one document into the next."""
        self.budget = _ReadBudget()
        self._seen_values = set()
        self._visited = set()
        self._fields_visited = set()
        self._kid_arrays = set()
        self._files_seen = set()
        self._stream_cache = {}
        self._decoded_size = 0
        self._text_cache = {}
        self._annots_seen = set()
        self._annot_arrays_seen = set()
        self._parents_seen = set()
        self._outline_items = 0
        self._attachments_read = 0
        self._actions_seen = 0
        self._actions_capped = False

    def extract(self, pdf_path: str) -> List[Tuple[str, str]]:
        """
        Extract all text from a PDF file.

        Returns list of (source_label, extracted_text) tuples.
        """
        import PyPDF2

        if not os.path.exists(pdf_path):
            raise FileNotFoundError(f"PDF not found: {pdf_path}")

        results = []
        # Reset per call: a failure from a previous document must never be
        # reported against this one.
        self.failures = []
        # One budget and one set of seen objects per document, created before the
        # first check reads anything so every later check charges the same budget.
        self._reset_document_state()

        with open(pdf_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)

            # The guard on compressed object streams stands before the first read
            # of an object, so no check below can force a large inflation through
            # a dereference that the guard would have refused.
            with self._bounded_object_streams(reader):
                # The page tree and the page text are read first, before the metadata,
                # so a metadata object stream that uses up the budget cannot keep the
                # page tree from being resolved. They are reported in the order they
                # always had: metadata, then page text.
                try:
                    pages = list(reader.pages)
                except Exception as exc:
                    pages = []
                    self.failures.append(
                        f"pages not read ({exc.__class__.__name__}: {exc})")

                # 2. Page text
                page_results = []
                for i, page in enumerate(pages):
                    try:
                        text = page.extract_text()
                    except Exception as exc:
                        self.failures.append(
                            f"page {i+1} text not read ({exc.__class__.__name__}: {exc})")
                        continue
                    if text and text.strip():
                        page_results.append((f"page:{i+1}", text.strip()))

                # 1. Metadata
                meta_texts = self._extract_metadata(reader)
                for field, text in meta_texts:
                    if text.strip():
                        results.append((f"metadata:{field}", text))
                results.extend(page_results)

                # 3. Annotations (comments, notes)
                for i, page in enumerate(pages):
                    annot_texts = self._extract_annotations(page)
                    for label, text in annot_texts:
                        if text.strip():
                            results.append((f"page:{i+1}:{label}", text))

                # 4-6. Content outside the page text (finding A3): form field
                # values, JavaScript actions and embedded files. Appended after the
                # three groups above so a PDF without them is reported exactly as
                # before. Each reader records what it could not read.
                extras = []
                extras.extend(self._extract_form_fields(reader))
                extras.extend(self._extract_document_scripts(reader))
                extras.extend(self._extract_outlines(reader))
                extras.extend(self._extract_associated_files(reader))
                for i, page in enumerate(pages):
                    extras.extend(self._extract_page_extras(page, i + 1))
                extras.extend(self._extract_attachments(reader))
                for label, text in extras:
                    if text.strip():
                        results.append((label, text))

                # 7. Pictures. Judged apart from the text: a page that paints a picture has
                # words this extractor does not read (no OCR runs by default), whatever else
                # the page holds, so the page is named as not inspected even when some text
                # was found. The walk runs after every other check, so the decoded content
                # it charges to the shared budget cannot keep a page tree, an annotation or
                # an attachment from being read.
                walk = _ImageWalk(self.budget)
                for i, page in enumerate(pages):
                    self._note_unread_images(page, i + 1, walk)

        return results

    # ----- A3 helpers: form values, scripts, attachments ------------------

    _resolve = staticmethod(_resolve)

    @staticmethod
    def _identity(obj):
        idnum = getattr(obj, 'idnum', None)
        if idnum is not None:
            return ('ref', idnum, getattr(obj, 'generation', 0))
        return ('obj', id(obj))

    def _bytes_text(self, value: bytes) -> str:
        """Text of a PDF byte string. One that starts with a UTF-16 byte order mark
        and does not decode is read with replacement, and the undecodable part is
        recorded as not inspected."""
        if value.startswith((b'\xff\xfe', b'\xfe\xff')):
            try:
                return value.decode('utf-16')
            except UnicodeDecodeError:
                self._note("a string value is not valid UTF-16; the bytes that do not "
                           "decode were not inspected")
                return value.decode('utf-16', 'replace')
        return value.decode('utf-8', 'replace')

    def _as_text(self, value) -> str:
        """A PDF string, name or (nested) array of them as one text; else ''.
        An array is read by identity, so a member that several arrays share is
        read once, an array that several keys share is read once for the document,
        and every entry of an array is counted and charged to the document budget
        before it is looked at, whatever it holds and whether or not it was seen
        before. It is bounded by member count, depth and that budget. What is left
        unread is recorded."""
        top = value
        value = self._resolve(value)
        if isinstance(value, (bytes, str)):
            return self._charged_text(value) or ''
        if not isinstance(value, (list, tuple)):
            return ''
        ident = self._identity(top)
        if ident in self._text_cache:
            return ''
        # The array is kept with its key so that the identity cannot be reused.
        self._text_cache[ident] = value
        parts: List[str] = []
        seen = set()
        members = 0
        stack = [(value, 0)]
        while stack:
            node, depth = stack.pop()
            if depth >= self.MAX_ARRAY_DEPTH:
                self._note(f"a value array nested deeper than {self.MAX_ARRAY_DEPTH} levels; "
                           f"the rest was not inspected")
                continue
            # The array is read from its end by index, so it is not copied in front of
            # its first check, and each entry is counted and paid for before anything
            # about it is looked at: an entry that repeats one already seen costs the same.
            for k in range(len(node) - 1, -1, -1):
                members += 1
                if members > self.MAX_ARRAY_MEMBERS:
                    self._note(f"a value array of more than {self.MAX_ARRAY_MEMBERS} members; "
                               f"the rest was not inspected")
                    stack.clear()
                    break
                if not self._spend(self.VISIT_COST):
                    stack.clear()
                    break
                item = node[k]
                ident = self._identity(item)
                if ident in seen:
                    continue
                seen.add(ident)
                item = self._resolve(item)
                if isinstance(item, (list, tuple)):
                    stack.append((item, depth + 1))
                    continue
                if isinstance(item, (bytes, str)):
                    text = self._charged_text(item, 1 if parts else 0)
                    if text is None:
                        stack.clear()
                        break
                    if text:
                        parts.append(text)
        return ' '.join(parts)

    def _charged_text(self, raw, separator: int = 0):
        """The text of a byte string or string, or None once the document budget is gone.
        Its length is charged before it is converted, and the encoded size of the text
        beyond that (with `separator` bytes for the joint when there is text) after."""
        if not self._spend(len(raw)):
            return None
        text = self._bytes_text(raw) if isinstance(raw, bytes) else str(raw)
        more = len(text.encode('utf-8', 'replace')) + (separator if text else 0) - len(raw)
        if more > 0 and not self._spend(more):
            return None
        return text

    def _note(self, message: str) -> None:
        """Record a failure once per document."""
        if message not in self.failures:
            self.failures.append(message)

    def _spend(self, size: int) -> bool:
        """Charge decoded bytes to the document budget; False once it is spent."""
        try:
            self.budget.spend(size)
        except _WalkBudget:
            self._note(
                f"decoded content passed the {self.budget.MAX_BYTES >> 20} MiB limit "
                f"of the document; the rest was not inspected")
            return False
        return True

    @contextlib.contextmanager
    def _bounded_object_streams(self, reader):
        """Inflate a compressed object stream only if it fits what is left of the
        document budget, once per stream. PyPDF2 decodes a whole object stream to read one
        object out of it, so a small file could otherwise force a large inflation
        through any dereference. Objects in a stream that does not fit are not
        resolved, and the stream is recorded as not inspected."""
        original = reader._get_object_from_stream
        verdicts = {}

        def guarded(indirect_reference):
            stmnum = reader.xref_objStm[indirect_reference.idnum][0]
            if stmnum not in verdicts:
                verdicts[stmnum] = self._object_stream_fits(reader, stmnum)
            if not verdicts[stmnum]:
                raise ValueError(f"object stream {stmnum} was not inflated")
            return original(indirect_reference)

        reader._get_object_from_stream = guarded
        try:
            yield
        finally:
            del reader._get_object_from_stream

    def _object_stream_fits(self, reader, stmnum: int) -> bool:
        from PyPDF2.generic import IndirectObject
        try:
            stream = IndirectObject(stmnum, 0, reader).get_object()
        except Exception:
            return True  # PyPDF2 raises the same error itself
        if not hasattr(stream, 'get_data'):
            return True
        # An object stream is bounded by what is left of the document budget and not
        # by the attachment bound, because it can hold the page tree and the page
        # text. It is inflated here once, charged, and handed to the reader, so the
        # reader's own decode of the same stream is not a second, uncharged one.
        data = self._bounded_stream_bytes(stream, f"object stream {stmnum}",
                                          cap=self.budget.MAX_BYTES)
        if data is None:
            return False
        if getattr(stream, 'decoded_self', 0) is None:
            from PyPDF2.generic import DecodedStreamObject
            decoded = DecodedStreamObject()
            decoded._data = data
            stream.decoded_self = decoded
        return True

    @staticmethod
    def _container_kind(data: bytes) -> Optional[str]:
        """Name of a non text format by its magic or its bytes, else None. Bytes
        that happen to decode as UTF-8 do not make a file text. A UTF-16 byte
        order mark in front is skipped for the format check, so a PDF or another
        container behind a mark is still named, and the byte check is left out
        for UTF-16 text, which holds zero bytes. A PDF is named by its header in
        the first KiB, or by a header anywhere together with a startxref marker,
        because the reader opens a PDF that has any amount of data in front."""
        utf16 = data.startswith((b'\xff\xfe', b'\xfe\xff'))
        body = data[2:] if utf16 else data
        head = body[:1024]
        if b'%PDF-' in head:
            return 'PDF'
        for magic, kind in _FORMAT_MAGIC:
            if head.startswith(magic):
                return kind
        # The PDF reader finds its cross reference table from the end of the data,
        # so it opens a PDF behind any run of leading bytes. A header further in
        # than the first KiB counts when the data also holds a startxref marker.
        if b'%PDF-' in body and b'startxref' in body:
            return 'PDF'
        # The header is not needed either: outside strict mode the reader opens any
        # data that holds the cross reference tail, whatever stands before or after
        # it, so data with "startxref", an offset and "%%EOF" together is named a PDF.
        if _XREF_TAIL.search(body):
            return 'PDF'
        if not utf16 and data[:8192].translate(None, _TEXT_BYTES):
            return 'binary'
        return None

    @staticmethod
    def _decode_text(data: bytes, strict: bool) -> Optional[str]:
        if data.startswith((b'\xff\xfe', b'\xfe\xff')):
            try:
                return data.decode('utf-16')
            except UnicodeDecodeError:
                return None
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            return None if strict else data.decode('utf-8', 'replace')

    def _bounded_stream_bytes(self, stream, name: str, cap: Optional[int] = None) -> Optional[bytes]:
        """Decoded bytes of a stream, or None (recorded) when that is not cheap
        and bounded. The chain is decoded by _decode_bounded, one stage at a time,
        within what is left of the document budget and `cap`, and every stage is
        charged as it is produced, so a small compressed object cannot expand
        without limit and nothing is decoded by the reader's own, unbounded
        decode. A stream read before is not decoded again."""
        key = id(stream)
        if key in self._stream_cache:
            data, size = self._stream_cache[key]
            if data is None:
                return None
            # The stream was decoded for another caller, under that caller's cap. This caller's
            # cap is applied to what the stages produced, and the refusal is recorded as a
            # decode would record it, without decoding again.
            limit = cap or self.MAX_ATTACHMENT_BYTES
            if size > limit:
                self.failures.append(f"{name} larger than {limit} bytes; not inspected")
                return None
            return data if self._spend(len(data)) else None
        data = self._decode_stream(stream, name, cap)
        # What the stages produced is set by the decode that returned the bytes (a decode
        # nested inside it has set and finished with it before that). The bytes themselves
        # are the least it can be.
        size = max(self._decoded_size, len(data)) if data is not None else 0
        self._stream_cache[key] = (data, size)
        return data

    def _decode_stream(self, stream, name: str, cap: Optional[int] = None) -> Optional[bytes]:
        cap = cap or self.MAX_ATTACHMENT_BYTES
        raw = getattr(stream, '_data', None) or b''
        try:
            filters = _filters_of(stream, self._charge_visit)
        except _WalkBudget:
            self._spend(1)  # records that the document limit stopped the read
            return None
        if filters is None:
            self.failures.append(f"{name} names more than {_MAX_CHAIN} filters; not inspected")
            return None
        if not filters:
            if len(raw) > cap:
                self.failures.append(f"{name} larger than {cap} bytes; not inspected")
                return None
            self._decoded_size = len(raw)
            return raw if self._spend(len(raw)) else None
        room = self.budget.remaining()
        if room <= 0:
            self._spend(1)  # records that the document limit stopped the read
            return None
        # The chain is decoded here, stage by stage, within the room the document has left,
        # and every stage is charged as it is produced. The document budget bounds the work,
        # the encoded input included; the cap bounds only what the stages produce, so an
        # attachment is not refused because its input and its output together pass it. What
        # the decoder has spent is put on the shared budget before any decode parameter is
        # resolved (a dereference can decode too), and `spent` is the part not yet put there.
        # The reader's own decode is never used.
        try:
            result = _decode_bounded(stream, room, self._charge_visit, self.budget.remaining,
                                     self.budget.spend, cap)
        except _WalkBudget:
            self._spend(1)  # records that the document limit stopped the read
            return None
        # What was produced is charged whether or not it is kept, so a run of streams
        # that are each too large cannot decode without the bound.
        charged = self._spend(result.spent)
        if result.state == "big":
            if result.detail == "cap" and charged:
                self.failures.append(f"{name} larger than {cap} bytes; not inspected")
            return None
        if result.state == "unsized":
            self.failures.append(f"{name} uses filter {result.detail}; not inspected")
            return None
        if result.state == "error":
            self.failures.append(
                f"{name} could not be decoded ({result.detail}); not inspected")
            return None
        if not charged:
            return None
        self._decoded_size = result.made
        for note in result.notes:
            self.failures.append(f"{name} {note}")
        return result.data

    def _charge_visit(self) -> int:
        """One visit charged to the document budget, and what was charged; raises _WalkBudget
        when it is gone."""
        self.budget.spend(self.VISIT_COST)
        return self.VISIT_COST

    def _name_tree(self, node, what: str, cap: int) -> List[Tuple[str, object]]:
        """(key, value) pairs of a PDF name tree (/Names and /Kids), bounded."""
        out: List[Tuple[str, object]] = []
        stack = [(node, 0)]
        seen = set()
        arrays = set()
        while stack and len(out) <= cap:
            node, depth = stack.pop()
            ident = self._identity(node)
            if ident in seen:
                continue
            if depth > 32:
                self._note(f"{what} nested deeper than 32 levels; the part below not inspected")
                continue
            seen.add(ident)
            node = self._resolve(node)
            if not hasattr(node, 'get'):
                continue
            names = self._resolve(node.get('/Names')) if '/Names' in node else None
            if names:
                for i in range(0, len(names) - 1, 2):
                    # Each pair is charged before its key is looked at, so a budget that is
                    # spent ends the walk with the rest of the pairs unread.
                    if not self._spend(self.VISIT_COST):
                        stack.clear()
                        break
                    out.append((self._as_text(names[i]), names[i + 1]))
                    if len(out) > cap:
                        break
            kids = self._resolve(node.get('/Kids')) if '/Kids' in node else None
            if kids and self._identity(node.get('/Kids')) in arrays:
                kids = None  # a /Kids array that was walked under another node
            elif kids:
                arrays.add(self._identity(node.get('/Kids')))
            for kid in kids or ():
                # Each kid is charged, and one already seen is not pushed, so nodes
                # that share an array cost the budget and not a square.
                if not self._spend(self.VISIT_COST):
                    stack.clear()
                    break
                if self._identity(kid) not in seen:
                    stack.append((kid, depth + 1))
        if len(out) > cap:
            self.failures.append(f"{what} beyond {cap} not inspected")
            out = out[:cap]
        return out

    def _scripts_in(self, action, where: str, table: bool = False) -> List[Tuple[str, str]]:
        """The /JS text carried by an action, an action chain (/Next) or, with
        table=True, an /AA table (trigger name -> action), as (label, script).
        A destination array ("/OpenAction [3 0 R /Fit]") holds no action and is
        skipped. Bounded by MAX_ACTIONS real actions across the document."""
        out: List[Tuple[str, str]] = []
        stack = [(action, table)]
        while stack:
            obj, is_table = stack.pop()
            ident = self._identity(obj)
            if ident in self._visited:
                continue
            self._visited.add(ident)
            try:
                obj = self._resolve(obj)
                if isinstance(obj, (list, tuple)):
                    # /Next may be an array of actions; a destination array is
                    # a page reference plus a view name, neither is an action.
                    for item in obj:
                        # Each entry is paid for before it is resolved or queued, so an
                        # array of repeats costs the budget and not an unbounded walk.
                        if not self._spend(self.VISIT_COST):
                            stack.clear()
                            break
                        target = self._resolve(item)
                        if hasattr(target, 'get') and ('/S' in target or '/JS' in target):
                            stack.append((item, False))
                    continue
                if not hasattr(obj, 'get'):
                    continue
                if is_table:
                    for value in obj.values():
                        if not self._spend(self.VISIT_COST):
                            stack.clear()
                            break
                        stack.append((value, False))
                    continue
                if '/S' not in obj and '/JS' not in obj:
                    continue  # not an action
                if self._actions_seen >= self.MAX_ACTIONS:
                    if not getattr(self, '_actions_capped', False):
                        self._actions_capped = True
                        self.failures.append(
                            f"actions beyond {self.MAX_ACTIONS} not inspected")
                    break
                self._actions_seen += 1
                if '/JS' in obj:
                    text = self._text_of(obj['/JS'], f"script at {where}", strict=False)
                    if text and text.strip():
                        out.append((f"javascript:{where}", text))
                if '/Next' in obj:
                    # The link is charged before it is queued, so a chain costs the budget at
                    # every step and not once per action it is allowed to hold.
                    if not self._spend(self.VISIT_COST):
                        stack.clear()
                        break
                    stack.append((obj['/Next'], False))
            except Exception as exc:
                self.failures.append(
                    f"script at {where} not read ({exc.__class__.__name__}: {exc})")
        return out

    def _text_of(self, value, name: str, strict: bool) -> str:
        """Text of a string, name, array or (bounded) stream value."""
        value = self._resolve(value)
        if hasattr(value, 'get_data'):
            data = self._bounded_stream_bytes(value, name)
            if data is None:
                return ''
            text = self._decode_text(data, strict=strict)
            if text is None and data.startswith((b'\xff\xfe', b'\xfe\xff')):
                # A UTF-16 value with units that do not decode: read what does, and
                # say that the rest was not, instead of turning it into nothing.
                self._note(f"{name} is not valid UTF-16; the bytes that do not decode "
                           f"were not inspected")
                text = data.decode('utf-16', 'replace')
            return text or ''
        return self._as_text(value)

    def _extract_form_fields(self, reader) -> List[Tuple[str, str]]:
        """Values of the AcroForm fields (/V, /DV, /RV, /TU, /Opt) and the
        scripts in field /AA tables. XFA data is recorded as not inspected."""
        out: List[Tuple[str, str]] = []
        try:
            root = self._resolve(reader.trailer['/Root'])
            acroform = self._resolve(root.get('/AcroForm')) if '/AcroForm' in root else None
            if acroform is None or not hasattr(acroform, 'get'):
                return out
            if '/XFA' in acroform:
                self.failures.append("XFA form data not inspected (XFA streams are not parsed)")
            fields = self._resolve(acroform.get('/Fields')) if '/Fields' in acroform else None
        except Exception as exc:
            self.failures.append(f"form fields not read ({exc.__class__.__name__}: {exc})")
            return out
        if fields:
            self._walk_fields(fields, '', 0, [0], out)
        return out

    def _walk_fields(self, fields, prefix: str, depth: int, counter: List[int], out) -> None:
        for ref in fields:
            # Every reference that is iterated is charged, also one that was visited
            # before, so a /Kids array that many parents list is bounded by the budget.
            if not self._spend(self.VISIT_COST):
                return
            ident = self._identity(ref)
            if ident in self._fields_visited:
                continue
            self._fields_visited.add(ident)
            if counter[0] >= self.MAX_FORM_FIELDS:
                if counter[0] == self.MAX_FORM_FIELDS:
                    counter[0] += 1
                    self.failures.append(
                        f"form fields beyond {self.MAX_FORM_FIELDS} not inspected")
                return
            counter[0] += 1
            name = f"#{counter[0]}"
            try:
                field = self._resolve(ref)
                if not hasattr(field, 'get'):
                    continue
                own = self._as_text(field.get('/T', '')) if '/T' in field else ''
                name = f"{prefix}.{own}" if prefix and own else (own or prefix or name)
                for key in self._FIELD_TEXT_KEYS:
                    if key in field:
                        text = self._text_of(field[key], f"field {name!r} {key}", strict=False)
                        if text.strip():
                            self._seen_values.add(text)
                            out.append((f"form:{name}:{key[1:]}", text))
                if '/AA' in field:
                    out.extend(self._scripts_in(field['/AA'], f"field:{name}", table=True))
                kids = self._resolve(field['/Kids']) if '/Kids' in field else None
                if kids and self._identity(field.get('/Kids')) in self._kid_arrays:
                    kids = None  # this array was walked under another parent
                elif kids:
                    self._kid_arrays.add(self._identity(field.get('/Kids')))
                if kids and depth >= 32:
                    self._note("form fields nested deeper than 32 levels; the fields below not inspected")
                elif kids:
                    self._walk_fields(kids, name, depth + 1, counter, out)
            except Exception as exc:
                self.failures.append(
                    f"form field {name!r} not read ({exc.__class__.__name__}: {exc})")

    def _extract_document_scripts(self, reader) -> List[Tuple[str, str]]:
        """/OpenAction, the catalog /AA table and the /Names /JavaScript tree."""
        out: List[Tuple[str, str]] = []
        try:
            root = self._resolve(reader.trailer['/Root'])
            if '/OpenAction' in root:
                out.extend(self._scripts_in(root['/OpenAction'], 'OpenAction'))
            if '/AA' in root:
                out.extend(self._scripts_in(root['/AA'], 'document:aa', table=True))
            names = self._resolve(root.get('/Names')) if '/Names' in root else None
            if names is not None and hasattr(names, 'get') and '/JavaScript' in names:
                tree = self._name_tree(names['/JavaScript'], "document scripts", self.MAX_ACTIONS)
                for key, action in tree:
                    out.extend(self._scripts_in(action, f"names:{key}"))
        except Exception as exc:
            self.failures.append(
                f"document scripts not read ({exc.__class__.__name__}: {exc})")
        return out

    def _extract_page_extras(self, page, index: int) -> List[Tuple[str, str]]:
        """Page /AA scripts; per annotation: widget values not reached through
        /AcroForm, /A and /AA scripts, and /FileAttachment file specs."""
        out: List[Tuple[str, str]] = []
        label = f"page:{index}"
        try:
            if '/AA' in page:
                out.extend(self._scripts_in(page['/AA'], f"{label}:aa", table=True))
            if '/AF' in page:
                out.extend(self._associated_files(page['/AF'], f"{label}:af"))
            annots = self._resolve(page['/Annots']) if '/Annots' in page else []
        except Exception as exc:
            self.failures.append(
                f"page {index} actions not read ({exc.__class__.__name__}: {exc})")
            return out
        if annots:
            # An /Annots array that an earlier page listed is read once for the document.
            if id(annots) in self._annot_arrays_seen:
                return out
            self._annot_arrays_seen.add(id(annots))
        for i, annot in enumerate(annots or []):
            try:
                # Every entry that is iterated is charged before it is looked at, also one
                # that is listed again, so the walk over a list of repeats is bounded by
                # the budget. An annotation listed twice is read once for the document.
                if not self._spend(self.VISIT_COST):
                    break
                ident = self._identity(annot)
                if ident in self._annots_seen:
                    continue
                self._annots_seen.add(ident)
                a = self._resolve(annot)
                if not hasattr(a, 'get'):
                    continue  # recorded by _extract_annotations already
                subtype = a.get('/Subtype')
                if subtype == '/Widget' and '/V' in a:
                    text = self._text_of(a['/V'], f"widget {i} on page {index} /V", strict=False)
                    if text.strip() and text not in self._seen_values:
                        self._seen_values.add(text)
                        out.append((f"{label}:widget:{i}:V", text))
                if subtype == '/Widget' and '/Parent' in a:
                    out.extend(self._parent_values(a['/Parent'], f"{label}:widget:{i}"))
                if '/AF' in a:
                    out.extend(self._associated_files(a['/AF'], f"{label}:annotation:{i}:af"))
                if '/A' in a:
                    out.extend(self._scripts_in(a['/A'], f"{label}:annotation:{i}"))
                if '/AA' in a:
                    out.extend(self._scripts_in(a['/AA'], f"{label}:annotation:{i}", table=True))
                if subtype == '/FileAttachment' and '/FS' in a:
                    out.extend(self._read_filespec(a['/FS'], f"{label}:annotation:{i}"))
            except Exception as exc:
                self.failures.append(
                    f"annotation {i} on page {index} actions not read "
                    f"({exc.__class__.__name__}: {exc})")
        return out

    def _parent_values(self, parent, where: str) -> List[Tuple[str, str]]:
        """The /V of the field chain above a widget that is not listed in /AcroForm.
        The value of a widget can sit on its /Parent. A parent that the form walk
        already read is skipped, and the chain is bounded by depth and visited
        by identity."""
        out: List[Tuple[str, str]] = []
        node = parent
        for _ in range(self.MAX_PARENT_DEPTH):
            ident = self._identity(node)
            if ident in self._fields_visited or ident in self._parents_seen:
                return out
            self._parents_seen.add(ident)
            if not self._spend(self.VISIT_COST):
                return out
            field = self._resolve(node)
            if not hasattr(field, 'get'):
                return out
            if '/V' in field:
                text = self._text_of(field['/V'], f"{where} parent /V", strict=False)
                if text.strip() and text not in self._seen_values:
                    self._seen_values.add(text)
                    out.append((f"{where}:parentV", text))
            if '/Parent' not in field:
                return out
            node = field['/Parent']
        self._note(f"a field chain above {where} nested deeper than "
                   f"{self.MAX_PARENT_DEPTH} levels; the fields above were not inspected")
        return out

    def _associated_files(self, files, where: str) -> List[Tuple[str, str]]:
        """The file specifications of an /AF array, read like any other embedded
        file under the same attachment cap, visited set and budget."""
        out: List[Tuple[str, str]] = []
        array = self._resolve(files)
        if not isinstance(array, (list, tuple)):
            return out
        for n, spec in enumerate(array):
            if n >= self.MAX_ARRAY_MEMBERS:
                self._note(f"an /AF array of more than {self.MAX_ARRAY_MEMBERS} members; "
                           f"the rest was not inspected")
                break
            if not self._spend(self.VISIT_COST):
                break
            out.extend(self._read_filespec(spec, f"{where}:{n}"))
        return out

    def _extract_associated_files(self, reader) -> List[Tuple[str, str]]:
        """Embedded files listed in the catalog /AF array."""
        try:
            root = self._resolve(reader.trailer['/Root'])
            if '/AF' not in root:
                return []
            return self._associated_files(root['/AF'], 'catalog:af')
        except Exception as exc:
            self.failures.append(
                f"associated files not read ({exc.__class__.__name__}: {exc})")
            return []

    def _extract_outlines(self, reader) -> List[Tuple[str, str]]:
        """Script actions on outline (bookmark) items, walked by identity and
        bounded by MAX_OUTLINE_ITEMS, the action cap and the budget."""
        out: List[Tuple[str, str]] = []
        try:
            root = self._resolve(reader.trailer['/Root'])
            if '/Outlines' not in root:
                return out
            outlines = self._resolve(root['/Outlines'])
            if not hasattr(outlines, 'get') or '/First' not in outlines:
                return out
            stack = [outlines['/First']]
            seen = set()
            while stack:
                node = stack.pop()
                ident = self._identity(node)
                if ident in seen:
                    continue
                seen.add(ident)
                if self._outline_items >= self.MAX_OUTLINE_ITEMS:
                    self._note(f"outline items beyond {self.MAX_OUTLINE_ITEMS} not inspected")
                    break
                self._outline_items += 1
                if not self._spend(self.VISIT_COST):
                    break
                item = self._resolve(node)
                if not hasattr(item, 'get'):
                    continue
                if '/A' in item:
                    out.extend(self._scripts_in(item['/A'], f"outline:{self._outline_items}"))
                if '/Next' in item:
                    stack.append(item['/Next'])
                if '/First' in item:
                    stack.append(item['/First'])
        except Exception as exc:
            self.failures.append(f"outlines not read ({exc.__class__.__name__}: {exc})")
        return out

    def _read_filespec(self, spec, key: str) -> List[Tuple[str, str]]:
        """Text of one embedded file, or a recorded failure naming it."""
        try:
            # One budget for annotation and name tree entry points: a file
            # specification or a stream reached twice is read once.
            ident = self._identity(spec)
            if ident in self._files_seen:
                return []
            self._files_seen.add(ident)
            if self._attachments_read >= self.MAX_ATTACHMENTS:
                self._note(f"attachments beyond {self.MAX_ATTACHMENTS} not inspected")
                return []
            self._attachments_read += 1
            spec = self._resolve(spec)
            if not hasattr(spec, 'get'):
                self.failures.append(f"attachment {key!r} is not a file specification; not inspected")
                return []
            name = ''
            for k in ('/UF', '/F'):
                if k in spec:
                    name = self._as_text(spec[k])
                    if name:
                        break
            name = name or key or 'unnamed'
            ef = self._resolve(spec.get('/EF')) if '/EF' in spec else None
            # A file specification may name a different stream under each of its
            # alternatives. Each distinct stream is read, and one that was read
            # before (shared by several alternatives or specifications) is skipped.
            streams = []
            has_alternative = False
            if ef is not None and hasattr(ef, 'get'):
                for k in self._EF_KEYS:
                    if k not in ef:
                        continue
                    has_alternative = True
                    stream_ident = self._identity(ef[k])
                    if stream_ident in self._files_seen:
                        continue
                    self._files_seen.add(stream_ident)
                    streams.append((k, self._resolve(ef[k])))
            if not streams:
                if not has_alternative:
                    self.failures.append(
                        f"attachment {name!r} has no readable stream; not inspected")
                return []
            out: List[Tuple[str, str]] = []
            for position, (k, stream) in enumerate(streams):
                if position:
                    if self._attachments_read >= self.MAX_ATTACHMENTS:
                        self._note(f"attachments beyond {self.MAX_ATTACHMENTS} not inspected")
                        break
                    self._attachments_read += 1
                label = f"attachment:{name}" if not position else f"attachment:{name}:{k[1:]}"
                out.extend(self._read_embedded(stream, name, label))
            return out
        except Exception as exc:
            self.failures.append(
                f"attachment {key!r} not read ({exc.__class__.__name__}: {exc})")
            return []

    def _read_embedded(self, stream, name: str, label: str) -> List[Tuple[str, str]]:
        """Text of one embedded stream, or a recorded failure naming the file."""
        if not hasattr(stream, 'get'):
            self.failures.append(f"attachment {name!r} has no readable stream; not inspected")
            return []
        data = self._bounded_stream_bytes(stream, f"attachment {name!r}")
        if data is None:
            return []
        kind = self._container_kind(data)
        if kind:
            self.failures.append(
                f"attachment {name!r} ({len(data)} bytes) is a {kind} file; not inspected")
            return []
        text = self._decode_text(data, strict=True)
        if text is None:
            self.failures.append(
                f"attachment {name!r} ({len(data)} bytes) is not text; not inspected")
            return []
        return [(label, text)]

    def _extract_attachments(self, reader) -> List[Tuple[str, str]]:
        """The files in the /Names /EmbeddedFiles tree, bounded."""
        out: List[Tuple[str, str]] = []
        try:
            root = self._resolve(reader.trailer['/Root'])
            names = self._resolve(root.get('/Names')) if '/Names' in root else None
            if names is None or not hasattr(names, 'get') or '/EmbeddedFiles' not in names:
                return out
            tree = self._name_tree(names['/EmbeddedFiles'], "attachments", self.MAX_ATTACHMENTS)
        except Exception as exc:
            self.failures.append(f"attachments not read ({exc.__class__.__name__}: {exc})")
            return out
        for key, spec in tree:
            out.extend(self._read_filespec(spec, key))
        return out

    def _flush_notes(self, walk, number: int) -> None:
        """Report what the decoder said about streams of this page that it read only in part."""
        for note in dict.fromkeys(walk.notes):
            self.failures.append(f"page {number}: content stream {note}")
        walk.notes.clear()

    def _note_unread_images(self, page, number: int, walk) -> None:
        """Record a page that paints pictures this extractor did not read."""
        if walk.stopped:
            return
        try:
            count, glyph_fonts, unmatched = walk.painted_images(page, 0)
            self._flush_notes(walk, number)
        except _WalkBudget:
            self._flush_notes(walk, number)
            walk.stopped = True
            self.failures.append(
                f"page {number} and later pages not checked for images, the page "
                f"content passed the {_ReadBudget.MAX_BYTES >> 20} MiB limit")
            return
        except Exception as exc:
            self._flush_notes(walk, number)
            self.failures.append(
                f"page {number} images not checked ({exc.__class__.__name__}: {exc})")
            return
        if count:
            self.failures.append(
                f"page {number}: {count} image(s) not read, no OCR ran so "
                f"image content was not inspected")
        if glyph_fonts:
            self.failures.append(
                f"page {number}: {glyph_fonts} font(s) paint pictures through glyph "
                f"procedures, so image content was not inspected")
        if unmatched:
            self.failures.append(
                f"page {number}: {unmatched} drawing operator(s) name a resource that "
                f"could not be matched, so image content was not inspected")

    def _extract_metadata(self, reader) -> List[Tuple[str, str]]:
        """Extract text from PDF metadata fields."""
        results = []
        try:
            meta = reader.metadata
        except Exception as exc:
            self.failures.append(
                f"document metadata not read ({exc.__class__.__name__}: {exc})")
            return results
        if meta:
            fields = {
                '/Title': 'title',
                '/Author': 'author',
                '/Subject': 'subject',
                '/Keywords': 'keywords',
                '/Creator': 'creator',
                '/Producer': 'producer',
            }
            for key, label in fields.items():
                value = meta.get(key)
                if value and isinstance(value, str) and len(value) > 3:
                    results.append((label, value))
        return results

    def _extract_annotations(self, page) -> List[Tuple[str, str]]:
        """Extract text from page annotations.

        v0.5.6 round 4 (ASTRA F4). This was one `try` around the WHOLE loop with
        `except Exception: pass`. A structurally valid PDF whose annotation array
        starts with a string instead of a dictionary raised on element 0, the
        `except` swallowed it, and the loop was abandoned -- so the instruction
        sitting in element 1 was never extracted and the CLI reported 0, complete,
        clean, with no warning. One malformed sibling hid every annotation after it.

        Two changes, both narrow: the guard moves INSIDE the loop so one bad
        element costs only itself, and a failure is RECORDED instead of dropped.
        Recovering a malformed annotation is explicitly not required; claiming
        complete coverage after giving up on one is the defect.
        """
        results = []
        try:
            annots = page['/Annots'] if '/Annots' in page else []
        except Exception as exc:
            self.failures.append(
                f"annotations not read ({exc.__class__.__name__}: {exc})")
            return results

        for index, annot in enumerate(annots):
            try:
                annot_obj = annot.get_object() if hasattr(annot, 'get_object') else annot
                # Get annotation content
                contents = annot_obj.get('/Contents', '')
                if contents and isinstance(contents, str) and len(contents) > 3:
                    results.append(('annotation', contents))
                # Get popup text
                t = annot_obj.get('/T', '')
                if t and isinstance(t, str) and len(t) > 3:
                    results.append(('annotation_author', t))
            except Exception as exc:
                self.failures.append(
                    f"annotation {index} not read ({exc.__class__.__name__}: {exc}); "
                    f"its text was not inspected")
        return results


def scan_pdf(pdf_path: str, engine=None) -> dict:
    """
    Convenience function: extract text from a PDF and scan with SUNGLASSES.

    Returns the canonical result document (see ``sunglasses.result``).

    v0.5.6 round 4: like the other four extractor aggregates this built its own
    per-source dictionaries and dropped the child's ``truncated`` /
    ``extraction_complete``, so a PDF whose extracted text ran past the engine's
    cap came back complete and clean. It also ignored ``PDFExtractor.failures``,
    which is how one malformed annotation could hide the next one silently.
    """
    from sunglasses.engine import SunglassesEngine
    from sunglasses.extractors.dispatch import _probe_readable
    from sunglasses.result import aggregate

    if engine is None:
        engine = SunglassesEngine()

    # Invariant B (round 3), extended to these five in round 4. A public entry
    # point probes readability BEFORE it routes, so an unreadable, missing or
    # non-regular path is an OPERATIONAL failure here exactly as it is on
    # `scan_fast`, `scan_deep` and the retained helpers. Without it these returned
    # a partial SCAN DOCUMENT for a file they had never opened -- a verdict-shaped
    # answer to a question that was never asked -- and a FIFO blocked on open.
    _probe_readable(pdf_path)

    # A decoder that gives up costs COVERAGE, never the scan, and never a
    # traceback -- the same contract `dispatch` has applied to these formats since
    # round 3. Until round 4 these five let ImportError and decoder errors escape
    # to the caller, so "no traceback on any supported path" had an exemption for
    # the public API a user is most likely to call first.
    try:
        extractor = PDFExtractor()
        texts = extractor.extract(pdf_path)
        _failed = None
    except ImportError as exc:
        extractor, texts, _failed = None, [], (
            f"PDF scanning requires: pip install sunglasses[pdf] — nothing in "
            f"{os.path.basename(pdf_path)} was inspected. ({exc})")
    except Exception as exc:
        extractor, texts, _failed = None, [], (
            f"PDF extraction failed ({exc.__class__.__name__}) — nothing in "
            f"{os.path.basename(pdf_path)} was inspected.")

    warnings = [
        f"PDF content not fully read from {os.path.basename(pdf_path)} — {failure}."
        for failure in getattr(extractor, "failures", None) or []
    ]
    if _failed:
        warnings.append(_failed)
    return aggregate(
        [(source, text, engine.scan(text, channel="file")) for source, text in texts],
        source=pdf_path,
        warnings=warnings,
        extra={"file": pdf_path},
    )
