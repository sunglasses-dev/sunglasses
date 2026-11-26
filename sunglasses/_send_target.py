"""Where a page says to send something: a mail address whose host is dressed as another host of the same page.

A page that tells its reader to send, forward or submit something to an address is giving the reader a place to put it.
This module reads one shape, inside one block of the text: a sending verb of a closed list in front of a mail address
(or the word mail, e-mail or email with ``to`` directly in front of it) whose host is not a free-mail host and looks
like another host of the page.

The page is decoded and folded once (character references, the engine's own fold: format characters deleted,
compatibility forms to the plain form, marks dropped, the look-alike letter table), and the addresses, the linked
hosts, the verb and the quick test all read that view. A mail link target is read at the link's place, percent-decoded
with its query cut, an address between angle brackets is an address, and comments and text attribute values are read
as blocks of their own.

The hosts of the page are the hosts of its links, the hosts named as ``www.`` text, and the hosts of its other mail
addresses (free-mail hosts left out). A mail host looks like another host of the page when

* it holds the registered name of that host inside its own registered name, and is not that host;
* its own name is the name of a linked host under another ending, and that mail host is not linked or named as
  ``www.`` on the page;
* or labels in front of its registered name spell the registered name of that host.

The registered name of a host is its name under a public suffix, cut with a hand list of country second-level groups
and hosting suffixes.
"""
from __future__ import annotations

import html
import re
import unicodedata
from urllib.parse import unquote

from .preprocessor import replace_lookalikes, strip_ignorable

MAX_HOST = 253

_LABEL = r"(?:[^\W_]|-)+"
_HOST = _LABEL + r"(?:\." + _LABEL + r")+"
_MAIL = re.compile(r"[\w.%+-]{1,64}@(" + _HOST + ")")
_URL = re.compile(r"(?:https?:)?//(" + _HOST + ")")
_WWW = re.compile(r"(?i)\b(www\." + _HOST + ")")
_FILE_ENDING = re.compile(r"\.(?:png|jpg|jpeg|gif|svg|webp|css|js)$", re.I)
# the edges of a block: a sentence end, a blank line, two line-break tags, a block tag
_BLOCKS = re.compile(
    r"(?i)(?<=[.!?])\s+|\n[^\S\n]*\n|(?:<br[^<>]*>[^\S\n]*){2,}|</?(?:p|li|div|tr|td|th|h[1-6]|section|article|ul|ol|table|form|"
    r"label|header|footer|body|html|head|title|option|dd|dt|blockquote|pre)\b[^<>]*>")
_TAG = re.compile(r"<[^<>]*>")
_ANGLE = re.compile(r"(?i)(?:mailto:)?[\w.%+-]{1,64}(?:@|%40)" + _HOST)
_MAILTO = re.compile(r"(?i)mailto:([^\s\"'<>()\[\]?#]*)")
# a text attribute is read in one pass over the page's name runs: a name starts only where a run of name characters BEGINS
# (the look-behind), the whole run is taken once, and the run is judged as a whole; the value is the quoted string after the sign
_NAME_EQ = re.compile(r"(?<![\w-])([\w-]+)\s*=\s*")
_NAME_OK = re.compile(r"(?i)(?:^|-)(?:(?:alt|title|aria-label|placeholder|content|value)\Z|data-[\w-]+\Z)")
_QUOTED = re.compile(r"\"([^\"]*)\"|'([^']*)'")
_ADDR_CHAR = re.compile(r"[\w.%+@-]")
_VERB = re.compile(
    r"\b(?:send|sends|sending|sent|forward|forwards|forwarding|forwarded|submit|submitting|copy|cc|bcc|attach|"
    r"attaching|deliver|transfer|share|upload|route|redirect|dispatch|relay|transmit|transmits|transmitting|provide|provides|"
    r"providing|report|reports|reporting|write|writes|writing|post|posts|posting|transmitted|provided|wrote|written|posted)\b", re.I)
_MAILVERB = re.compile(r"(?i)\b(?:e-?mail(?:s|ing|ed)?|mail(?:s|ing|ed)?)\b")
_TO_BEFORE = re.compile(r"(?i)\bto[\s:<(\[{\"'\u201c\u2018]*$")
# the short-link host of a video site and of a forum site stand beside their brand's own host: a closed map of two
_SHORT_LINKS = {"youtu.be": "youtube.com", "redd.it": "reddit.com"}

_SECOND_LEVEL_GROUPS = {
    "uk": "co org ac gov me ltd plc net sch nhs police", "au": "com net org edu gov id asn", "nz": "co org net govt ac school geek",
    "jp": "co ne or ac go ed gr", "kr": "co or ne go ac re pe", "in": "co net org ac gov firm gen ind edu res",
    "br": "com net org gov edu", "cn": "com net org gov edu", "mx": "com org gob edu net", "tr": "com org net gov edu gen biz info",
    "ar": "com gob org net edu", "sg": "com edu gov org net", "hk": "com org edu gov net", "tw": "com org edu gov net idv",
    "za": "co org ac gov net web", "il": "co org ac gov net", "id": "co or ac go web my sch", "my": "com org edu gov net",
    "ph": "com org edu gov net", "vn": "com edu gov org net", "ua": "com org net gov edu in", "pl": "com org net edu gov info biz",
    "es": "com org nom gob edu", "pt": "com org edu gov", "eg": "com edu gov org net", "sa": "com gov edu org net",
    "pk": "com gov edu org net biz web", "ng": "com gov edu org net", "co": "com org edu gov net", "ve": "com co net org",
    "pe": "com org edu gob net", "ec": "com edu gov org net", "uy": "com edu gub org net", "ke": "co or go ac ne sc",
    "th": "co ac go or in net", "ae": "co net gov ac org", "ru": "com org net", "by": "com gov org", "kz": "com org edu gov net",
    "lk": "com org edu gov net", "bd": "com org edu gov net", "np": "com org edu gov", "ir": "co ac gov org net",
    "gr": "com edu gov org net", "ro": "com org nom net", "hu": "co org net", "cy": "com org net", "mt": "com org net",
    "tn": "com org net", "ma": "co org net", "gh": "com org edu gov", "tz": "co or go ac", "ug": "co or go ac", "zm": "co org ac",
    "bo": "com org net", "py": "com org net", "cr": "co or ac go", "do": "com org net", "gt": "com org net", "pa": "com org net"}
_SECOND_LEVEL = frozenset("%s.%s" % (second, country) for country, seconds in _SECOND_LEVEL_GROUPS.items()
                          for second in seconds.split())
# hosting suffixes that hand a name to anyone: the registered name sits one label under them
_HOSTING = ("github.io", "gitlab.io", "herokuapp.com", "appspot.com", "blogspot.com", "cloudfront.net", "azurewebsites.net",
            "netlify.app", "vercel.app", "pages.dev", "workers.dev", "web.app", "firebaseapp.com", "amazonaws.com", "wordpress.com",
            "wixsite.com", "weebly.com", "myshopify.com", "notion.site", "carrd.co", "webflow.io", "glitch.me", "repl.co", "fly.dev",
            "onrender.com", "surge.sh", "000webhostapp.com", "ngrok.io", "trycloudflare.com", "duckdns.org", "no-ip.org", "ddns.net",
            "blob.core.windows.net", "cloudapp.net", "herokudns.com", "myftpupload.com", "square.site")
# mail hosts of providers that give an address to anyone, and the placeholder hosts of documentation
_FREE_MAIL = frozenset((
    "gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "proton.me", "protonmail.com", "icloud.com", "example.com",
    "example.org", "example.net", "aol.com", "gmx.com", "gmx.de", "gmx.net", "mail.com", "yandex.com", "yandex.ru", "zoho.com",
    "zohomail.com", "fastmail.com", "tutanota.com", "tuta.com", "tuta.io", "yahoo.co.uk", "yahoo.co.jp", "yahoo.fr", "live.com",
    "msn.com", "qq.com", "163.com", "126.com", "mail.ru", "web.de", "t-online.de", "orange.fr", "free.fr", "libero.it", "me.com",
    "mac.com", "pm.me", "hey.com", "hotmail.co.uk", "hotmail.fr", "googlemail.com", "outlook.fr", "outlook.de", "live.co.uk",
    "rocketmail.com", "ymail.com", "inbox.com", "email.com", "mailbox.org", "posteo.de", "runbox.com", "disroot.org",
    "example.co.uk", "test.com", "domain.com", "yourdomain.com", "company.com", "email.example", "localhost.localdomain"))


def registered(host: str) -> str:
    """The name under the public suffix: ``mail.paypal.co.uk`` -> ``paypal.co.uk``. An IP address is returned whole."""
    host = host.strip(".")
    parts = host.split(".")
    if all(part.isdigit() for part in parts):
        return host
    for suffix in _HOSTING:
        count = suffix.count(".") + 1
        if host.endswith("." + suffix) and len(parts) > count:
            return ".".join(parts[-(count + 1):])
    if len(parts) >= 3 and ".".join(parts[-2:]) in _SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


_COMMAT = re.compile(r"(?i)&commat;?")
_MARKS = None


def _drop_marks(text: str) -> str:
    """The text without its combining marks (a letter and its accent written as two characters read as the letter)."""
    global _MARKS
    if _MARKS is None:
        _MARKS = {code: None for code in (*range(0x20000), *range(0xE0000, 0xE0200)) if unicodedata.category(chr(code)) == "Mn"}
    return unicodedata.normalize("NFKC", unicodedata.normalize("NFKD", text).translate(_MARKS))


def _view(text: str) -> str:
    """The page as the reader sees it: character references decoded (the at sign written as a name without its end mark
    too), then the engine's fold. This is the one view that the addresses, the hosts, the verbs and the quick test read."""
    page = html.unescape(text) if "&" in text else text
    if "&" in page:
        page = _COMMAT.sub("@", page)
    if page.isascii():
        return page
    return replace_lookalikes(_drop_marks(strip_ignorable(page)))


def may_read(text: str) -> bool:
    """The quick first test: does the viewed text hold an at sign (written plain, as a compatibility form, as a character
    reference, or as the percent form of a mail link target)."""
    if "@" in text:
        return True
    if "%40" in text:
        return True
    return ("&" in text or not text.isascii()) and "@" in _view(text)


def _fold(host: str) -> str:
    return host.lower()


def _host(raw: str):
    """The host as written in the view, lower case, or None when it is longer than a host can be."""
    return _fold(raw) if len(raw) <= MAX_HOST else None


def _name(reg: str) -> str:
    return reg.split(".")[0]


class _Hosts:
    """The hosts of one page, looked up by name: the linked and www. hosts, and the hosts of its other mail addresses."""

    def __init__(self, linked, mail_hosts):
        self.linked = linked                                        # registered hosts of links and www. names
        self.all = linked | mail_hosts
        self.by_name = {}                                           # name word -> registered hosts of that name
        self.linked_by_name = {}                                    # the same for linked and www. hosts, names of 3 letters or more
        self.by_start = {}                                          # first four letters of a name -> names
        for reg in sorted(self.all):
            name = _name(reg)
            if len(name) >= 4:
                self.by_name.setdefault(name, []).append(reg)
        for reg in sorted(linked):
            name = _name(reg)
            if len(name) >= 3:
                self.linked_by_name.setdefault(name, []).append(reg)
        for name in self.by_name:
            self.by_start.setdefault(name[:4], []).append(name)
        self.lengths = sorted({len(name) for name in self.by_name})


def _looks_like(host: str, reg: str, hosts: _Hosts):
    """The other host of the page this mail host is dressed as, with the form, or None."""
    name = _name(reg)
    part = reg[:reg.rfind(".")]
    for index in range(len(part) - 3):
        if part[index:index + 4] not in hosts.by_start:
            continue
        for length in hosts.lengths:
            word = part[index:index + length]
            if len(word) == length and word in hosts.by_name and word != name:
                for other in hosts.by_name[word]:
                    if other != reg and _SHORT_LINKS.get(other) != reg:
                        return other, "holds-the-name"
    if name in hosts.linked_by_name and reg not in hosts.linked:
        for other in hosts.linked_by_name[name]:
            if other != reg and _SHORT_LINKS.get(other) != reg:
                return other, "same-name-other-ending"
    labels = host.split(".")
    front = labels[:len(labels) - (reg.count(".") + 1)]
    for start in range(len(front)):
        for stop in range(start + 2, len(front) + 1):
            run = ".".join(front[start:stop])
            if run in hosts.all and run != reg and run not in _FREE_MAIL and _SHORT_LINKS.get(run) != reg:
                return run, "front-labels-of-another-host"
    return None


_REV_RUN = re.compile(r"(?:[\w.%+@-]|>[^<>]*<)*")
_RIGHT_RUN = re.compile(r"(?:[\w.%+@-]|<!--.*?-->|<[^<>]*>)*", re.S)
_TAGS_OF_RUN = re.compile(r">[^<>]*<")
RUN_CAP = 300
RUN_WINDOW = 900
_RIGHT_TAGS = re.compile(r"(?:[\w.%+@-]|<[^<>]*>)*")


def _left_run(tail: str) -> str:
    """The address characters that end ``tail``, the inline tags in between read as nothing; a block tag ends the run."""
    window = tail[-600:][::-1]
    run = _REV_RUN.match(window).group(0)
    if ">" in run:
        for tag in _TAGS_OF_RUN.finditer(run):
            if _BLOCKS.fullmatch(tag.group(0)[::-1]) is not None:
                run = run[:tag.start()]
                break
        run = _TAG_REV.sub("", run)
    return run[:RUN_CAP][::-1]


_TAG_REV = re.compile(r">[^<>]*<")


def _right_run(text: str, pos: int) -> str:
    """The address characters that follow ``pos``, the tags and comments in between read as nothing. The window is read once:
    comments are looked for only up to the last end mark of the window, tags alone behind it."""
    end = pos + RUN_WINDOW
    last = text.rfind("-->", pos, end)
    cut = last + 3 if last >= 0 else pos
    run = ""
    if cut > pos:
        first = _RIGHT_RUN.match(text, pos, cut)
        run = _MARKUP.sub("", first.group(0)) if "<" in first.group(0) else first.group(0)
        pos = first.end()
    if pos == cut:
        rest = _RIGHT_TAGS.match(text, pos, end).group(0)
        run += _TAG.sub("", rest) if "<" in rest else rest
    return run[:RUN_CAP]


_MARKUP = re.compile(r"<!--.*?-->|<[^<>]*>", re.S)


def _glue(tail: str, text: str, end: int) -> str:
    """What a tag or a comment leaves behind, ``tail`` being the text in front of it and ``text[end:]`` the text behind it:
    nothing when it stands between address characters with an at sign on one side of it, a space otherwise (also where a
    whole host stands in front of it and a letter or digit follows)."""
    before = _left_run(tail[-600:])
    if not before:
        return " "
    after = _right_run(text, end)
    if not after:
        return " "
    if "@" not in before and "@" not in after:
        return " "
    if "@" in before:
        host = before.rsplit("@", 1)[1]
        if "." in host and not host.endswith(".") and after[0].isalnum():
            return " "
    return ""


def _split_comments(page: str):
    """The page without its comments (each leaves what _glue says), and the text of each comment."""
    if "<!--" not in page:
        return page, []
    out, bodies, at, tail = [], [], 0, ""
    while True:
        start = page.find("<!--", at)
        if start < 0:
            out.append(page[at:])
            break
        end = page.find("-->", start + 4)
        if end < 0:
            out.append(page[at:start])
            bodies.append(page[start + 4:])
            break
        out.append(page[at:start])
        tail = (tail + page[at:start])[-300:]
        piece = _glue(tail, page, end + 3)
        out.append(piece)
        tail = (tail + piece)[-300:]
        bodies.append(page[start + 4:end])
        at = end + 3
    return "".join(out), bodies


def _attributes(tag: str, extras: list):
    """The text attribute values of one tag that hold an at sign go to ``extras``, each a block of its own."""
    if "=" in tag:
        pos = 0
        while True:
            name = _NAME_EQ.search(tag, pos)
            if name is None:
                break
            pos = name.end()
            if _NAME_OK.search(name.group(1)):
                value = _QUOTED.match(tag, pos)
                if value is not None:
                    pos = value.end()
                    text = value.group(1) if value.group(1) is not None else value.group(2)
                    if "@" in text or "%40" in text:
                        extras.append(text)


def _flat(block: str, extras: list) -> str:
    """One block as plain text: a tag is a space (or what _glue says), an anchor's mail target stands at its place,
    an address between angle brackets stays an address; text attribute values are put in ``extras`` as blocks of their own."""
    if "<" in block:
        out, tail, at = [], "", 0
        for match in _TAG.finditer(block):
            before = block[at:match.start()]
            out.append(before)
            tail = (tail + before)[-300:]
            body = match.group(0)
            inner = body[1:-1].strip()
            piece = None
            if ("@" in inner or "%40" in inner) and _ANGLE.fullmatch(inner):
                piece = " " + unquote(inner[7:] if inner[:7].lower() == "mailto:" else inner) + " "
            else:
                _attributes(body, extras)
                target = _MAILTO.search(body)
                if target is not None:
                    piece = " " + unquote(target.group(1)) + " "
            if piece is None:
                piece = _glue(tail, block, match.end())
            out.append(piece)
            tail = (tail + piece)[-300:]
            at = match.end()
        out.append(block[at:])
        flat = "".join(out)
    else:
        flat = block
    return _MAILTO.sub(lambda match: unquote(match.group(1)), flat)


def _blocks_of(page: str, extras: list):
    at = 0
    for edge in _BLOCKS.finditer(page):
        block = page[at:edge.start()]
        if block and ("@" in block or "%40" in block):
            yield _flat(block, extras)
        if edge.group(0)[:1] == "<":
            _attributes(edge.group(0), extras)
        at = edge.end()
    block = page[at:]
    if block and ("@" in block or "%40" in block):
        yield _flat(block, extras)


def read(text: str):
    """Findings of this shape in ``text``: a list of small evidence dicts, at most one per block."""
    page = _view(text)
    if "@" not in page and "%40" not in page:
        return []
    linked = set()
    for pattern in (_URL, _WWW):
        for match in pattern.finditer(page):
            host = _host(match.group(1))
            if host is not None:
                linked.add(registered(host))
    page, comments = _split_comments(page)
    extras = []
    flats = list(_blocks_of(page, extras))
    for body in comments:
        flats.extend(_blocks_of(body, extras))
    flats.extend(extras)
    blocks = []
    mail_hosts = set()
    parsed = {}                                                      # raw host -> (host, registered host) or None
    for flat in flats:
        entries = []
        for match in _MAIL.finditer(flat):
            raw = match.group(1)
            if raw not in parsed:
                host = _host(raw)
                parsed[raw] = None
                if host is not None and not _FILE_ENDING.search(host):
                    reg = registered(host)
                    if reg not in _FREE_MAIL:
                        parsed[raw] = (host, reg)
                        mail_hosts.add(reg)
            if parsed[raw] is not None:
                entries.append((match, parsed[raw]))
        if entries:
            blocks.append((flat, entries))
    if not blocks:
        return []
    hosts = _Hosts(linked, mail_hosts)
    looks = {}
    found = []
    for flat, entries in blocks:
        verb = _VERB.search(flat)
        mail_verb = _MAILVERB.search(flat)
        for match, (host, reg) in entries:
            if host not in looks:
                looks[host] = _looks_like(host, reg, hosts)
            if looks[host] is None:
                continue
            start = match.start()
            word = verb if verb is not None and verb.end() <= start else None
            if word is None and mail_verb is not None and mail_verb.end() <= start and _TO_BEFORE.search(flat, max(0, start - 40), start):
                word = mail_verb
            if word is None:
                continue
            found.append({"verb": word.group(0).lower(), "mail_host": reg, "looks_like": looks[host][0],
                          "form": looks[host][1], "address": match.group(0)[:120]})
            break
    return found
