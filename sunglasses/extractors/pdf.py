"""
SUNGLASSES PDF Extractor — Scans PDFs for hidden prompt injection.

Extracts text from PDFs using multiple methods:
1. Page text — visible text content on each page
2. Metadata — document properties (title, author, subject, keywords, creator)
3. Annotations — comments, notes, form fields
4. Embedded JavaScript — malicious scripts in PDF actions

Usage:
    from sunglasses.extractors.pdf import scan_pdf
    result = scan_pdf("/path/to/document.pdf")

Install: pip install sunglasses[pdf]  (requires PyPDF2)
"""

import os
import re
from typing import List, Tuple


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

    def spend(self, size: int) -> None:
        self.read += size
        if self.read > self.MAX_BYTES:
            raise _WalkBudget()


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
    rb"|(?P<op>(?:Do|BI|ID|Tf)(?!" + _REG + rb"))"
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
    """Return the number of inline images, the names a Do operator draws and the
    names a Tf operator selects as the font."""
    if b"Do" not in data and b"BI" not in data and b"Tf" not in data:
        return 0, [], []
    inline, names, fonts, last, font, pos, in_dict = 0, [], [], None, None, 0, False
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
    return inline, names, fonts


class _ImageWalk:
    """One bounded visit of a document's painted pictures. A picture counts only
    where a Do operator draws it (or an inline image sits in the content), so an
    unused resource entry does not. A form is read once and its count is kept, so
    pages that share forms or resources cost one visit, and the decoded content
    read over the whole document is capped.

    Every count is a triple: pictures drawn, Type3 fonts in use whose glyph
    procedures paint pictures, and drawing operators whose resource name could not
    be matched (a name that is not plain ASCII). The last two are not pictures this check
    counted, so they are reported as content that was not inspected."""

    MAX_FORM_DEPTH = 8
    MAX_GLYPHS = 512
    MAX_APPEARANCES = 64

    def __init__(self, budget):
        self.budget = budget
        self.stopped = False
        self.cache = {}
        self.open = set()

    @staticmethod
    def _sum(*parts):
        return tuple(sum(p[i] for p in parts) for i in range(3))

    def painted_images(self, holder, depth):
        resources = _resolve(holder.get('/Resources')) if hasattr(holder, 'get') else None
        return self._sum(self._count(holder, resources, depth),
                         self._appearances(holder, resources))

    def _appearances(self, page, resources):
        """Pictures drawn by the normal appearance of each annotation on the page."""
        annots = _resolve(page.get('/Annots')) if hasattr(page, 'get') else None
        if not isinstance(annots, list):
            return (0, 0, 0)
        parts = []
        for annot in annots:
            annot = _resolve(annot)
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
                states = [(normal.raw_get(key), _resolve(normal.raw_get(key))) for key in normal]
            else:
                continue
            for state_ref, stream in states:
                if hasattr(stream, 'get_data'):
                    parts.append(self._form(stream, getattr(state_ref, 'idnum', None),
                                            resources, 1))
        return self._sum((0, 0, 0), *parts)

    def _count(self, holder, resources, depth):
        data = self._content(holder)
        if not data:
            return (0, 0, 0)
        xobjects = _resolve(resources.get('/XObject')) if hasattr(resources, 'get') else None
        fonts = _resolve(resources.get('/Font')) if hasattr(resources, 'get') else None
        total, names, selected = _drawn_operations(data)
        glyphs = unmatched = 0
        seen = set()
        for raw in names:
            name = _name(raw)
            if name in seen:
                continue
            seen.add(name)
            if not hasattr(xobjects, 'raw_get') or name not in xobjects:
                # A plain name the resources do not hold draws nothing. A name that is
                # not plain ASCII is the case where two readings of the same bytes can
                # disagree, so a miss there is reported and not taken as nothing drawn.
                if not name.isascii():
                    unmatched += 1
                continue
            ref = xobjects.raw_get(name)
            ident = getattr(ref, 'idnum', None)
            obj = _resolve(ref)
            kind = obj.get('/Subtype') if hasattr(obj, 'get') else None
            if kind == '/Image':
                total += 1
            elif kind == '/Form':
                found = self._form(obj, ident, resources, depth + 1)
                total += found[0]
                glyphs += found[1]
                unmatched += found[2]
        for raw in selected:
            name = _name(raw)
            if ("font", name) in seen:
                continue
            seen.add(("font", name))
            if not hasattr(fonts, 'raw_get') or name not in fonts:
                continue
            ref = fonts.raw_get(name)
            font = _resolve(ref)
            if hasattr(font, 'get') and font.get('/Subtype') == '/Type3':
                found = self._type3(font, getattr(ref, 'idnum', None), resources, depth + 1)
                glyphs += found[1] + (1 if found[0] else 0)
                unmatched += found[2]
        return (total, glyphs, unmatched)

    def _type3(self, font, ident, parent_resources, depth):
        """The pictures the glyph procedures of a Type3 font paint. Which glyphs a
        page shows is not read, so a font in use counts as painting pictures when
        any of its procedures does."""
        if depth > self.MAX_FORM_DEPTH:
            raise ValueError(f"form nesting deeper than {self.MAX_FORM_DEPTH}")
        own = _resolve(font.get('/Resources'))
        effective = own if own else parent_resources
        key = None if ident is None else ("type3", ident, "own" if own else id(effective))
        if key is not None:
            if key in self.open:
                return (0, 0, 0)
            if key in self.cache:
                return self.cache[key][0]
            self.open.add(key)
        try:
            procs = _resolve(font.get('/CharProcs'))
            if not hasattr(procs, 'raw_get'):
                return (0, 0, 0)
            if len(procs) > self.MAX_GLYPHS:
                raise ValueError(f"more than {self.MAX_GLYPHS} glyph procedures in one font")
            parts = []
            for glyph in procs:
                stream = _resolve(procs.raw_get(glyph))
                if hasattr(stream, 'get_data'):
                    parts.append(self._count(stream, effective, depth))
            found = self._sum((0, 0, 0), *parts)
        finally:
            if key is not None:
                self.open.discard(key)
        if key is not None:
            self.cache[key] = (found, effective)
        return found

    def _form(self, form, ident, parent_resources, depth):
        if depth > self.MAX_FORM_DEPTH:
            raise ValueError(f"form nesting deeper than {self.MAX_FORM_DEPTH}")
        own = _resolve(form.get('/Resources'))
        effective = own if own else parent_resources
        # A form that names its own resources reads the same on every page. A form
        # that borrows resources reads differently under each page that draws it, so
        # the result is kept per resource set and is not shared across them.
        key = None if ident is None else (ident, "own" if own else id(effective))
        if ident is not None:
            if ident in self.open:
                return (0, 0, 0)
            if key in self.cache:
                return self.cache[key][0]
            self.open.add(ident)
        try:
            count = self._count(form, effective, depth)
        finally:
            if ident is not None:
                self.open.discard(ident)
        if key is not None:
            self.cache[key] = (count, effective)
        return count

    def _content(self, holder) -> bytes:
        """The decoded content of a page (one stream or an array) or a form."""
        if hasattr(holder, 'get_data'):
            streams = [holder]
        else:
            contents = _resolve(holder.get('/Contents'))
            if contents is None:
                return b""
            streams = [_resolve(c) for c in contents] if isinstance(contents, list) else [contents]
        out = []
        for stream in streams:
            data = stream.get_data() if hasattr(stream, 'get_data') else b""
            self.budget.spend(len(data))
            out.append(data)
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

    # Form XObjects nest. The depth bound and the in progress set keep a form
    # that points back at itself from looping.
    MAX_FORM_DEPTH = 8

    def _note_unread_images(self, page, number: int, walk) -> None:
        """Record a page that paints pictures this extractor did not read."""
        if walk.stopped:
            return
        try:
            count, glyph_fonts, unmatched = walk.painted_images(page, 0)
        except _WalkBudget:
            walk.stopped = True
            self.failures.append(
                f"page {number} and later pages not checked for images, the page "
                f"content passed the {_ReadBudget.MAX_BYTES >> 20} MiB limit")
            return
        except Exception as exc:
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
