"""An HTML page cut into the parts an agent reads.

The page is cut with the engine's own tokenizer (standard library only, linear in the length of
the page: every step moves forward by a find), so a hostile page costs the same per byte as an
ordinary one. Nothing outside the tag syntax is dropped:

* the text flow of the page is read in two forms ("text" and, when the page has block edges, "textflat"):
  text nodes in document order (the content of
  noscript, template, title and textarea included). An inline tag adds nothing, so a word split
  by a bold tag stays one word. In the first form a block tag, a list item, a table cell and a line
  break add a new line; in the second they add one space, so a sentence split over them is one sentence;
* a tag whose name is no known HTML, SVG or MathML element (forged markup, or a placeholder in angle
  brackets) stays in the text flow as written, start tag, inside and end tag, in both forms, so a rule
  that reads a tag and its words as one string still sees one string. A name with a hyphen gets no pass.
  Such a start tag is also listed with the start tags;
* the text flow is also read in a third form when the page has a link with an address (a or area with an
  href): the address stands right behind the link's words ("textlinks"), the plain forms stay as they are;
* every attribute value is its own part;
* every comment (as written, its opener and closer included), declaration and processing instruction is its own part, also before the doctype
  and after the closing html tag;
* every script body and every style body is its own part (a script whose type says it holds
  data, such as ld+json, is the kind "scriptdata", not code);
* a tag that never ends is kept whole as a part of its own;
* a link with rel stylesheet whose address is a data URI of type text/css (base64 or percent form) is
  decoded and its text is one more part ("sheet"), read like a style body; the address stays an
  attribute value. Anything else in a data address is not decoded;
* a meta or link start tag that carries msapplication, browserconfig, mask-icon or pinned is kept with the
  160 characters of the page that follow it, and the last words of the text before it;
* the start tags themselves, in document order, are one more part ("tags"), for the rules that
  read how an element is written (a loader with a handler, a quote left open in a tag). A tag
  that can be an injected element is kept with the words of the text just before it.

A text with no tag in it is not cut (cut_page returns None) and is read as one string.

A part that holds white space is always scanned alone. The one-token parts past TOKEN_CAP are packed into
chunks, and a page with more different white space parts than WHITESPACE_CAP keeps the block (see
pack_parts). Nothing is dropped.
"""
import base64
import binascii
import html
import bisect
import threading
import re
import urllib.parse

_TAGISH = re.compile(r"<[A-Za-z!/?]")
_BLOCK = frozenset((
    "address article aside blockquote body dd details dialog div dl dt fieldset figcaption figure footer form "
    "h1 h2 h3 h4 h5 h6 header hgroup hr html li main menu nav ol p pre section summary table tbody td tfoot th "
    "thead tr ul br option optgroup caption legend").split())
_BODIES = frozenset(("script", "style"))
# The elements a browser knows: HTML (living standard, with the legacy names a page still carries), SVG and
# MathML. Any other name is forged markup or a placeholder, and a name with a hyphen is the attacker's pick.
_KNOWN = frozenset((
    "a abbr acronym address applet area article aside audio b base basefont bdi bdo bgsound big blink blockquote "
    "body br button canvas caption center cite code col colgroup command content data datalist dd del details dfn "
    "dialog dir div dl dt element em embed fieldset figcaption figure font footer form frame frameset h1 h2 h3 h4 "
    "h5 h6 head header hgroup hr html i iframe image img input ins isindex kbd keygen label legend li link listing "
    "main map mark marquee math menu menuitem meta meter multicol nav nextid nobr noembed noframes noscript object "
    "ol optgroup option output p param picture plaintext portal pre progress q rb rp rt rtc ruby s samp script "
    "search section select shadow slot small source spacer span strike strong style sub summary sup svg table "
    "tbody td template textarea tfoot th thead time title tr track tt u ul var video wbr xmp "
    "a altglyph altglyphdef altglyphitem animate animatecolor animatemotion animatetransform circle clippath "
    "color-profile cursor defs desc discard ellipse feblend fecolormatrix fecomponenttransfer fecomposite "
    "feconvolvematrix fediffuselighting fedisplacementmap fedistantlight fedropshadow feflood fefunca fefuncb "
    "fefuncg fefuncr fegaussianblur feimage femerge femergenode femorphology feoffset fepointlight "
    "fespecularlighting fespotlight fetile feturbulence filter font-face font-face-format font-face-name "
    "font-face-src font-face-uri foreignobject g glyph glyphref hatch hatchpath hkern line lineargradient "
    "marker mask mesh meshgradient meshpatch meshrow metadata mpath path pattern polygon polyline "
    "radialgradient rect set solidcolor stop switch symbol text textpath tref tspan unknown use view vkern "
    "annotation annotation-xml maction maligngroup malignmark menclose merror mfenced mfrac mglyph mi "
    "mlabeledtr mlongdiv mmultiscripts mn mo mover mpadded mphantom mprescripts mroot mrow ms mscarries "
    "mscarry msgroup msline mspace msqrt msrow mstack mstyle msub msubsup msup mtable mtd mtext mtr munder "
    "munderover semantics".split()))
_SPACES = re.compile(r"[ \t\r\f\v]+")
_LINES = re.compile(r"[ \t\r\f\v]*\n\s*")
# A start tag that can be an injected element (a handler, a script url, a frame, a script, a form) is kept
# with the words just before it (a handler: the raw page text; a tag name: the text flow), because a rule reads "render this" and the element together.
_ELEMENT = re.compile(r"\bon[a-z]+\s*=|javascript:|^<\s*(?:iframe|script|form|link)\b", re.I)
_HANDLER = re.compile(r"\bon[a-z]+\s*=|javascript:", re.I)
_WINDOW = 160
_HREF = re.compile(r"""\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+))""", re.I)
# A meta or link tag that carries one of these words is kept with the words that follow it: a rule on pinned
# site metadata reads the tag and the words behind it as one string.
_PINNED = re.compile(r"^<\s*(?:meta|link)\b[^>]*(?:msapplication|browserconfig|mask-icon|pinned)", re.I)
_TYPE = re.compile(r"""\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+))""", re.I)
_CODE_TYPES = ("javascript", "ecmascript", "module", "jscript", "livescript", "babel", "jsx")
_VALUE = re.compile(r"""=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+))""")


# The caps sit well above what real pages hold: the page with the most different parts that hold white space
# has a thousand of them, and the page with the most one-token parts has three thousand.
WHITESPACE_CAP = 10000     # about ten times the most a real page holds
TOKEN_CAP = 5000           # one-token parts that are scanned apart before the rest are packed
CHUNK = 16000
SHEET_CAP = 400000         # characters of data stylesheets decoded on one page, all together
_SPACE = re.compile(r"\s")
_ATTR = re.compile(r"""\b([a-zA-Z_:][-\w:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+))""")
_DATA_CSS = re.compile(r"^\s*data:text/css\s*((?:;[^,;]*)*),(.*)$", re.I | re.S)


def _data_sheet(start_tag):
    """The decoded text of a `link` start tag that is a stylesheet whose address is a data URI of type
    text/css (base64 or percent form), or None when it is anything else or cannot be decoded."""
    attrs = {}
    for found in _ATTR.finditer(start_tag):
        attrs.setdefault(found.group(1).lower(), next(g for g in found.groups()[1:] if g is not None))
    if "stylesheet" not in attrs.get("rel", "").lower().split():
        return None
    match = _DATA_CSS.match(html.unescape(attrs.get("href", "")))
    if not match:
        return None
    params = [p.strip().lower() for p in match.group(1).split(";") if p.strip()]
    charset = [p[8:] for p in params if p.startswith("charset=")]
    if charset and charset[0].strip("\"'") not in ("utf-8", "utf8", "us-ascii", "ascii"):
        return None
    try:
        if "base64" in params:
            payload = "".join(match.group(2).split())
            raw = base64.b64decode(payload + "=" * (-len(payload) % 4), validate=True)
        else:
            raw = urllib.parse.unquote_to_bytes(match.group(2))
        return raw.decode("utf-8")
    except (binascii.Error, ValueError):
        return None


def pack_parts(parts):
    """(units, over) for the list of parts `parts`.

    A part that holds white space is always scanned alone, so a page cannot put a word in front of its
    own order from outside it. A part that is one token (an id, a link, a single class name) cannot
    carry a guard phrase, so the one-token parts past TOKEN_CAP are packed, in order and by kind, into
    chunks of at most CHUNK characters with a new line between. A part with the same text as an
    earlier one (both code or both not) is kept once. `over` is True when the page holds more
    different parts with white space than WHITESPACE_CAP: it cannot be read part by part in bounded
    time, and the caller keeps the block."""
    seen = set()
    out = []
    spaced = 0
    singles = 0
    chunks = {}           # kind -> [texts, size]
    done = []
    for kind, text in parts:
        key = (kind in ("script", "style", "sheet"), text)
        if key in seen:
            continue
        seen.add(key)
        if _SPACE.search(text.strip()):
            spaced += 1
            if spaced > WHITESPACE_CAP:
                return [], True
            out.append((kind, text))
            continue
        singles += 1
        if singles <= TOKEN_CAP:
            out.append((kind, text))
            continue
        held = chunks.setdefault(kind, [[], 0])
        if held[0] and held[1] + len(text) + 1 > CHUNK:
            done.append((kind, "\n".join(held[0])))
            held[0], held[1] = [], 0
        held[0].append(text)
        held[1] += len(text) + 1
    for kind, held in chunks.items():
        if held[0]:
            done.append((kind, "\n".join(held[0])))
    return out + done, False


def _body_kind(name, start_tag):
    """"style", "script" (code) or "scriptdata" (a script whose type says it holds data: json,
    ld+json, importmap, a text/ template)."""
    if name != "script":
        return name
    found = _TYPE.search(start_tag)
    if not found:
        return "script"
    kind = next(g for g in found.groups() if g is not None).strip().lower()
    if not kind or any(c in kind for c in _CODE_TYPES):
        return "script"
    return "scriptdata"


class Marks:
    """Where markup stood in the text flow ("text" part): a tag, a comment, a processing instruction, a
    declaration or a body that is not read as text. ``offsets()`` are places in the normalized text flow, the
    place of the character that follows the markup; they are worked out when asked for (a rule asks only when a
    forbidding word stands near a match)."""
    __slots__ = ("_flow", "_index", "_offsets", "lined", "lined_lower")

    def __init__(self, flow, index, lined=""):
        self._flow, self._index, self._offsets, self.lined = flow, index, None, lined
        self.lined_lower = lined.lower()

    def offsets(self):
        if self._offsets is None:
            lengths = [0]
            for piece in self._flow:
                lengths.append(lengths[-1] + len(piece))
            places = sorted({lengths[i] for i in self._index})
            raw = "".join(self._flow)
            for rx in (_SPACES, _LINES):
                runs = [(m.start(), m.end(), 1) for m in rx.finditer(raw)]
                starts = [r[0] for r in runs]
                cut = [0]
                for a, b, keep in runs:
                    cut.append(cut[-1] + (b - a) - keep)
                places = [self._shift(at, runs, starts, cut) for at in places]
                raw = rx.sub(" " if rx is _SPACES else "\n", raw)
            lead = len(raw) - len(raw.lstrip())
            self._offsets = sorted({max(at - lead, 0) for at in places})
        return self._offsets

    @staticmethod
    def _shift(at, runs, starts, cut):
        i = bisect.bisect_right(starts, at) - 1
        if i >= 0 and at < runs[i][1]:
            return runs[i][0] - cut[i] + (1 if at > runs[i][0] else 0)
        return at - cut[i + 1]


class _Sink(threading.local):
    marks = None


# Where a caller that cannot pass ``marks`` (the engine calls cut_page(text, tokens)) gets the
# markup places back: it sets ``MARKS_SINK.marks`` to a dict around the call.
MARKS_SINK = _Sink()


def cut_page(text, tokens=None, marks=None):
    """The parts of `text` as a list of (kind, text), or None when `text` holds no tag.
    ``marks``, a dict, gets the markup places of the text flow (a Marks object) under the text of each part that
    holds the flow.

    `kind` is one of "text" (the text flow), "textflat" (the same flow, block edges as spaces), "attr", "comment", "decl", "pi",
    "cdata", "script" (code), "scriptdata" (json, ld+json, importmap, a text/ template), "style",
    "tags" or "tail"."""
    if not _TAGISH.search(text):
        return None
    if marks is None:
        marks = MARKS_SINK.marks
    if tokens is None:
        from .engine import SunglassesEngine
        tokens = SunglassesEngine._html_tokens(text)
    flow = []
    at_mark = []                   # the length of the flow at each piece of markup (a place in the flow)
    flat = []                      # the same text flow with a block edge as one space, not a new line
    other = []
    tags = []
    last = 0
    run = ""                       # the last words of the text flow, kept for an element that can be an injection
    previous = None
    sheets = []
    sheet_chars = 0
    links = []                     # the address of each open link, so it can stand right behind the link's words
    inserts = []                   # (place in the flow, address) for the form of the text flow that has them
    for token in tokens:
        kind, name, start, end = token
        if start > last:
            piece = text[last:start]
            flow.append(piece)
            flat.append(piece)
            run = (run + piece[-_WINDOW:])[-_WINDOW:]
        last = max(last, end)
        seg = text[start:end]
        if marks is not None and not (kind in ("start", "end") and name not in _KNOWN):
            at_mark.append(len(flow))
        if kind in ("start", "end"):
            before = run                                  # the words before this tag, without the tag itself
            if name not in _KNOWN:
                flow.append(seg)                      # a forged tag or a placeholder: text, as written
                flat.append(seg)
                run = (run + seg[-_WINDOW:])[-_WINDOW:]
            if name in ("a", "area"):
                if kind == "start":
                    found = _HREF.search(seg)
                    address = next(g for g in found.groups() if g is not None) if found else ""
                    if name == "area":
                        if address:
                            inserts.append((len(flow), " " + address))
                    else:
                        links.append(address)
                elif name == "a" and links:
                    address = links.pop()
                    if address:
                        inserts.append((len(flow), " " + address))
            if kind == "start":
                if _PINNED.search(seg):
                    tags.append(before + seg + text[end:end + _WINDOW])      # the words before it too: a defusing sentence
                else:
                    tags.append(text[max(0, start - _WINDOW):end] if _HANDLER.search(seg) else before + seg if _ELEMENT.search(seg) else seg)
            if name in _BLOCK:
                flow.append("\n")
                flat.append(" ")
            for value in _VALUE.finditer(seg):
                other.append(("attr", next(g for g in value.groups() if g is not None)))
            if kind == "start" and name == "link" and "data:" in seg.lower():
                sheet = _data_sheet(seg)
                if sheet and sheet_chars + len(sheet) <= SHEET_CAP:
                    sheet_chars += len(sheet)
                    sheets.append(("sheet", sheet))
        elif seg.startswith("<!--"):
            body = seg[4:]
            for closer in ("-->", "--!>"):
                if body.endswith(closer):
                    body = body[:-len(closer)]
                    break
            if body.strip():
                other.append(("comment", seg))       # as written, opener and closer included: a rule can anchor on them
        elif name in _BODIES and previous is not None and previous[0] == "start" and previous[1] == name \
                and previous[3] == start:
            other.append((_body_kind(name, text[previous[2]:previous[3]]), seg))   # the body of a script or a style
        elif name and previous is not None and previous[0] == "start" and previous[1] == name \
                and previous[3] == start:
            flow.append(seg)                          # noscript, title, textarea and the like: text
            flat.append(seg)
        elif seg.startswith("<![CDATA["):
            other.append(("cdata", seg[9:-3] if seg.endswith("]]>") else seg[9:]))
        elif seg.startswith("<?"):
            other.append(("pi", seg[2:-1] if seg.endswith(">") else seg[2:]))
        elif seg.startswith("<!"):
            other.append(("decl", seg[2:-1] if seg.endswith(">") else seg[2:]))
        else:
            other.append(("tail", seg))               # a tag that never ends
        previous = token
    if last < len(text):
        flow.append(text[last:])
        flat.append(text[last:])
    body = _LINES.sub("\n", _SPACES.sub(" ", "".join(flow))).strip()
    parts = [("text", body)] if body else []
    # The same flow with a block edge as a space: a sentence the page splits over divs, a line break or list
    # items is one sentence to a rule. Only when it differs from the first form.
    body_flat = _LINES.sub("\n", _SPACES.sub(" ", "".join(flat))).strip()
    if body_flat and body_flat != body:
        parts.append(("textflat", body_flat))
    if marks is not None and at_mark and body:
        found = Marks(flow, at_mark, body)
        marks[body] = found
        if body_flat and len(body_flat) == len(body):
            marks[body_flat] = found
    if inserts:
        # The same flow with the address of each link right behind the link's words, as a page that is
        # turned into text for an agent shows it. Only when it differs from the first form.
        linked, at = [], 0
        for place, address in inserts:
            linked.extend(flow[at:place])
            linked.append(address)
            at = place
        linked.extend(flow[at:])
        body_linked = _LINES.sub("\n", _SPACES.sub(" ", "".join(linked))).strip()
        if body_linked and body_linked != body:
            parts.append(("textlinks", body_linked))
    parts.extend((kind, value) for kind, value in other if value.strip())
    parts.extend(sheet for sheet in sheets if sheet[1].strip())
    if tags:
        parts.append(("tags", "\n".join(tags)))
    return parts
