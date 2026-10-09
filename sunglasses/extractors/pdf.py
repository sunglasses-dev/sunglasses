"""
SUNGLASSES PDF Extractor — Scans PDFs for hidden prompt injection.

Extracts text from PDFs using multiple methods:
1. Page text — visible text content on each page
2. Metadata — document properties (title, author, subject, keywords, creator)
3. Annotations — comment text and author

Usage:
    from sunglasses.extractors.pdf import scan_pdf
    result = scan_pdf("/path/to/document.pdf")

Install: pip install sunglasses[pdf]  (requires PyPDF2)
"""

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

    __slots__ = ("data", "spent", "state", "detail", "notes")

    def __init__(self, data=None, spent=0, state="ok", detail="", notes=()):
        self.data = data
        self.spent = spent
        self.state = state    # ok | big | unsized | error
        self.detail = detail
        self.notes = list(notes)


_ASCII85_SKIP = bytes(b for b in range(256) if not 33 <= b <= 117)
_FLATE = ('/FlateDecode', '/Fl')
_ASCII85 = ('/ASCII85Decode', '/A85')
_LZW = ('/LZWDecode', '/LZW')


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
            out = inflater.decompress(pending, room + 1 - total)
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
    after = (inflater.unused_data + pending + data[pos:])[trailer:] if inflater.eof else b""
    return b"".join(chunks), inflater.eof, after, damaged


def _ascii85_length(data: bytes) -> int:
    """The length ASCII85 decoding produces, counted without decoding."""
    body = data.split(b"~", 1)[0]
    digits = len(body.translate(None, _ASCII85_SKIP))
    return (digits // 5) * 4 + max(0, digits % 5 - 1) + 4 * body.count(b"z")


def _predictor_of(params):
    """(predictor, columns, bits per component) the way PyPDF2 reads them."""
    def resolve(obj):
        return obj.get_object() if hasattr(obj, 'get_object') else obj
    params = resolve(params)
    predictor, columns, bits = 1, 1, 8
    entries = params if isinstance(params, (list, tuple)) else [params]
    for entry in entries:
        entry = resolve(entry)
        if not hasattr(entry, 'get'):
            continue
        predictor = resolve(entry.get('/Predictor', predictor))
        columns = resolve(entry.get('/Columns', columns))
        bits = resolve(entry.get('/BitsPerComponent', bits))
    return int(predictor), int(columns), int(bits)


def _decode_bounded(stream, room: int) -> "_Decoded":
    """Decode a stream's filter chain one stage at a time, so that no stage runs past what
    is left of the budget and nothing is decoded twice. Every stage's output, the
    intermediate ones included, is added to `spent`, and the chain is refused (state
    "big") as soon as that sum passes `room`. A Flate stage is inflated no further than
    `room` and gzip is read as well as zlib. ASCII85 and LZW are counted before they are
    decoded. A predictor is applied to the bounded output. A chain with a filter that is
    not sized here (hex, run length, an image filter, /Crypt, LZW that is not the last
    filter) is refused with state "unsized", and a stage that fails with "error". The
    reader's own get_data() is never called."""
    from PyPDF2 import filters as pdf_filters

    def resolve(obj):
        return obj.get_object() if hasattr(obj, 'get_object') else obj

    names = resolve(stream.get('/Filter')) if '/Filter' in stream else None
    if isinstance(names, (list, tuple)):
        names = [str(resolve(n)) for n in names]
    else:
        names = [] if names is None else [str(names)]
    data = getattr(stream, '_data', None) or b""
    out = _Decoded(data=data)
    if not data:
        return out
    try:
        for i, name in enumerate(names):
            if name in _FLATE:
                data, reached_end, after, damaged = _inflate(data, room - out.spent)
                out.spent += len(data)
                if out.spent > room:
                    return _Decoded(spent=room + 1, state="big")
                if damaged or not reached_end:
                    out.notes.append("compressed data ends before its stream does; "
                                     "the rest was not inspected")
                elif after.strip(b"\x00\t\n\x0c\r "):
                    out.notes.append("holds data after the end of its compressed stream; "
                                     "that data was not inspected")
                predictor, columns, bits = _predictor_of(stream.get('/DecodeParms'))
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
                        data = pdf_filters.FlateDecode._decode_png_prediction(data, columns, rowlength)
                        out.spent += len(data)
            elif name in _ASCII85:
                size = _ascii85_length(data)
                out.spent += size
                if out.spent > room:
                    return _Decoded(spent=room + 1, state="big")
                data = pdf_filters.ASCII85Decode.decode(data)
            elif name in _LZW and i == len(names) - 1:
                size = _lzw_length(data, room - out.spent)
                if size is None:
                    return _Decoded(spent=out.spent, state="unsized", detail=name)
                out.spent += size
                if out.spent > room:
                    return _Decoded(spent=room + 1, state="big")
                data = pdf_filters.LZWDecode.decode(data)
                if len(data) > size:
                    return _Decoded(spent=room + 1, state="big")
            else:
                return _Decoded(spent=out.spent, state="unsized", detail=name)
    except Exception as exc:
        return _Decoded(spent=out.spent, state="error", detail=exc.__class__.__name__)
    if isinstance(data, str):
        data = data.encode('latin-1', 'replace')
    out.data = data
    if not names:
        out.spent = len(data)
    return out


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
    VISIT_COST = 32   # bytes of the document budget for each annotation and state visited

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

    def painted_images(self, holder, depth):
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
            self.budget.spend(self.VISIT_COST)
            annot = _resolve(annot)
            if self._not_shown(annot):
                continue
            appearance = _resolve(annot.get('/AP')) if hasattr(annot, 'get') else None
            if not hasattr(appearance, 'raw_get') or '/N' not in appearance:
                continue
            ref = appearance.raw_get('/N')
            normal = _resolve(ref)
            if hasattr(normal, 'get_data'):
                states = [(ref, normal)]
            elif hasattr(normal, 'raw_get'):
                if len(normal) > self.MAX_APPEARANCES:
                    raise ValueError(
                        f"more than {self.MAX_APPEARANCES} appearance states on one annotation")
                # The selected state is the one the annotation's /AS names. With no
                # /AS (or one that is not a name) every state is read, as the state a
                # viewer would pick is not known.
                chosen = _resolve(annot.get('/AS'))
                keys = [chosen] if isinstance(chosen, NameObject) else list(normal)
                states = [(normal.raw_get(key), _resolve(normal.raw_get(key)))
                          for key in keys if key in normal]
            else:
                continue
            for state_ref, stream in states:
                self.budget.spend(self.VISIT_COST)
                if hasattr(stream, 'get_data'):
                    parts.append(self._form(stream, getattr(state_ref, 'idnum', None),
                                            scope, 1))
        found = self._sum((0, 0, 0), *parts)
        self.appearances[key] = (found, annots, scope)
        return found

    def _count(self, holder, scope, depth):
        self.budget.spend(self.VISIT_COST)
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
            obj = _resolve(ref)
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
        font = _resolve(ref)
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
        state = _resolve(ref)
        if not hasattr(state, 'get'):
            return (0, 0, 0)
        parts = []
        mask = _resolve(state.get('/SMask'))
        if hasattr(mask, 'raw_get'):
            group_ref = mask.raw_get('/G') if '/G' in mask else None
            group = _resolve(group_ref)
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
                stream = _resolve(procs.raw_get(glyph))
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
        if hasattr(holder, 'get_data'):
            streams = [holder]
        else:
            contents = _resolve(holder.get('/Contents'))
            if contents is None:
                return b""
            streams = [_resolve(c) for c in contents] if isinstance(contents, list) else [contents]
        out = []
        for stream in streams:
            if not hasattr(stream, 'get_data'):
                continue
            result = _decode_bounded(stream, self.budget.remaining())
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

    def __init__(self):
        _check_deps()
        self.failures = []
        self.budget = _ReadBudget()

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
        self.budget = _ReadBudget()

        with open(pdf_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)

            # 1. Metadata
            meta_texts = self._extract_metadata(reader)
            for field, text in meta_texts:
                if text.strip():
                    results.append((f"metadata:{field}", text))

            # 2. Page text. Pictures are judged apart from the text: a page
            # that paints a picture has words this extractor does not read (no
            # OCR runs by default), whatever else the page holds, so the page is
            # named as not inspected even when some text was found.
            walk = _ImageWalk(self.budget)
            for i, page in enumerate(reader.pages):
                text = page.extract_text()
                if text and text.strip():
                    results.append((f"page:{i+1}", text.strip()))
                self._note_unread_images(page, i + 1, walk)

            # 3. Annotations (comments, notes)
            for i, page in enumerate(reader.pages):
                annot_texts = self._extract_annotations(page)
                for label, text in annot_texts:
                    if text.strip():
                        results.append((f"page:{i+1}:{label}", text))

        return results

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
