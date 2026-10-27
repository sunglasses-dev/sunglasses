"""Send one finished scan to a URL the user named with `--report-to`.

Off unless the flag is given. When it is, the scan has already ended: its stdout,
its verdict and its exit code are decided before anything here runs, and nothing
here can change them. Every way the upload can fail is one line on stderr, never
an exception, never a different exit code.

What leaves the machine is one JSON document (`ENVELOPE_SCHEMA`): the scanner's own
result object as the user's `--json` run prints it, wrapped with the scanner version
and a source label. The text a rule matched is replaced by its SHA-256 and length
unless the user also passed `--report-include-text`. Each finding also carries `line`,
the 1-based line where its matched text first appears in the file as read, or null
when it cannot be located (text on the command line, a format that is extracted
before it is scanned, a file too large to read again). Paths are the ones the scan
output already shows.

With `--report-include-receipts` the document also carries the newest segment of the
user's signed hook log, from its first line, with the public key that signs it
(`receipts`). Lines are the file's own, each with its trailing newline, so a
receiver verifies the same bytes the user's own verifier does. Without the flag
`receipts` is null.

The token comes from the environment (`SUNGLASSES_REPORT_TOKEN`), never from an
argument, so it stays out of shell history and process listings. It is sent only
as a bearer header to the exact URL given: redirects are refused, and a token goes
over plain http only to this machine.
"""
from __future__ import annotations

import copy
import fnmatch
import hashlib
import ipaddress
import json
import os
import pathlib
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request

from . import __version__

ENVELOPE_SCHEMA = "sg-report/1"
TOKEN_ENV = "SUNGLASSES_REPORT_TOKEN"
MAX_BODY_BYTES = 1 << 20
MAX_FINDINGS = 5000
TIMEOUT_SECONDS = 10

KIND_SCAN = "scan"
KIND_DIR_SCAN = "dir_scan"
_SOURCE_KIND = {KIND_SCAN: "host", KIND_DIR_SCAN: "repo"}


def _line(message):
    print(f"sunglasses: --report-to: {message}", file=sys.stderr)


def _plain(text):
    """`text` with anything a terminal could act on replaced, for one stderr line."""
    return "".join(c if c.isprintable() else "?" for c in str(text))


def _loopback(host):
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _digest(text):
    return {"sha256": hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest(),
            "len": len(text)}


def hide_matched_text(node):
    """A copy of `node` in which every `matched_text` string is its digest.

    Walks the whole document, so the finding lists of a directory scan and its
    top-level list are both covered, and a field added next to them later is not.
    """
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            if key == "matched_text" and isinstance(value, str):
                out[key] = _digest(value)
            else:
                out[key] = hide_matched_text(value)
        return out
    if isinstance(node, list):
        return [hide_matched_text(item) for item in node]
    return copy.deepcopy(node)


LINE_READ_LIMIT = 4 << 20


def _read_again(path, root):
    """The file's text for locating lines, or None. Never leaves `root`, never a non-file."""
    try:
        if root is not None:
            real_root = os.path.realpath(root)
            path = os.path.realpath(path)
            if os.path.commonpath([real_root, path]) != real_root:
                return None
        info = os.stat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size > LINE_READ_LIMIT:
            return None
        with open(path, "rb") as handle:
            return handle.read(LINE_READ_LIMIT + 1).decode("utf-8", "replace")
    except (OSError, ValueError):
        return None


def _squashed(text):
    """`text` lower-cased with each run of whitespace as one space, and where each
    character of that came from. A rule's matched text is read from the scanner's
    normalized view of the file, so it is looked for in the same shape."""
    out, origin, gap = [], [], False
    for at, char in enumerate(text):
        if char.isspace():
            if gap:
                continue
            gap, char = True, " "
        else:
            gap = False
        for lowered in char.lower():
            out.append(lowered)
            origin.append(at)
    return "".join(out), origin


class _Located:
    """One file's text, searched for matched texts. The squashed view is built once, and
    only when an exact search has failed."""

    def __init__(self, text):
        self.text = text
        self._view = None

    def line_of(self, needle):
        if self.text is None or not isinstance(needle, str) or not needle:
            return None
        at = self.text.find(needle)
        if at < 0:
            if self._view is None:
                self._view = _squashed(self.text)
            squashed, origin = self._view
            wanted = _squashed(needle)[0].strip()
            found = squashed.find(wanted) if wanted else -1
            if found < 0:
                return None
            at = origin[found]
        return self.text.count("\n", 0, at) + 1


def with_lines(doc, kind, root=None, path=None):
    """A copy of the scan's JSON object with `line` on every finding.

    Done while the scanned files are still there (a cloned repo is removed when the
    scan ends), and on a copy: the document the user's own output prints is untouched.
    `path` is the one file of a single-file scan; `root` is the directory of a tree scan.
    """
    held = copy.deepcopy(doc)
    groups = []
    if kind == KIND_SCAN:
        groups.append((path, None, held.get("findings")))
    else:
        for entry in held.get("file_results") or []:
            rel = entry.get("file") if isinstance(entry, dict) else None
            if isinstance(rel, str) and root is not None and not os.path.isabs(rel):
                groups.append((os.path.join(root, rel), root, entry.get("findings")))
            elif isinstance(entry, dict):
                groups.append((None, None, entry.get("findings")))
    for where, base, findings in groups:
        located = _Located(_read_again(where, base) if where else None)
        for finding in findings or []:
            if isinstance(finding, dict):
                finding["line"] = located.line_of(finding.get("matched_text"))
    return held


def _hex(text, longest):
    return (isinstance(text, str) and 0 < len(text) <= longest
            and all(c in "0123456789abcdef" for c in text))


def read_receipts():
    """(the `receipts` object, None), or (None, why not): the newest hook-log segment
    from its genesis, complete lines only, and the raw public key as 64 hex."""
    home = pathlib.Path(os.environ.get("SUNGLASSES_HOME") or (pathlib.Path.home() / ".sunglasses"))
    log = home / "receipts" / "hook"
    try:
        names = sorted(n for n in os.listdir(log) if fnmatch.fnmatchcase(n, "segment-*.chain"))
    except OSError:
        names = []
    if not names:
        return None, "no signed log was found"
    try:
        path = log / names[-1]
        info = os.stat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BODY_BYTES:
            return None, "the log segment is larger than the report limit"
        with open(path, "rb") as handle:
            text = handle.read(MAX_BODY_BYTES + 1).decode("utf-8")
        lines = [piece + "\n" for piece in text.split("\n")[:-1]]
        genesis = json.loads(lines[0])
        chain_id, key_id = genesis["chain_id"], genesis["key_id"]
        if not (genesis.get("event") == "genesis" and _hex(chain_id, 64) and _hex(key_id, 128)):
            return None, "the log segment does not open with a genesis"
        with open(home / "keys" / "public" / f"{key_id}.pub", "rb") as handle:
            public = handle.read(33)
    except (OSError, ValueError, KeyError, IndexError, TypeError, AttributeError):
        return None, "the signed log or its public key could not be read"
    if len(public) != 32:
        return None, "the public key file is not a raw 32-byte key"
    return {"chain_id": chain_id, "public_key": public.hex(), "public_key_fp": key_id,
            "lines": lines}, None


def finding_count(doc):
    count = len(doc.get("findings") or [])
    for entry in doc.get("file_results") or []:
        if isinstance(entry, dict):
            count += len(entry.get("findings") or [])
    return count


def build_envelope(doc, kind, source_name=None, include_text=False, pattern_count=None,
                   receipts=None):
    """The one document that is uploaded. `doc` is the scan's JSON object."""
    scan = copy.deepcopy(doc) if include_text else hide_matched_text(doc)
    name = source_name or (doc.get("repo_name") if kind == KIND_DIR_SCAN else None) or "unnamed"
    return {
        "schema": ENVELOPE_SCHEMA,
        "client": {"version": __version__, "pattern_count": pattern_count},
        "source": {"kind": _SOURCE_KIND[kind], "name": str(name), "ref": None},
        "kind": kind,
        "scan": scan,
        "receipts": receipts,
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would carry the bearer header to a host the user never named."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _target(url):
    """(parsed url, None) when it may receive a token, else (None, the reason)."""
    try:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname
        parsed.port  # noqa: B018  -- raises ValueError on a bad port
    except ValueError:
        return None, "the URL is not valid; nothing sent"
    if parsed.scheme not in ("http", "https") or not host:
        return None, "the URL must start with https:// ; nothing sent"
    if parsed.username is not None or parsed.password is not None:
        return None, "put no user or password in the URL; the token comes from " \
                     f"{TOKEN_ENV}; nothing sent"
    if parsed.scheme == "http" and not _loopback(host):
        return None, "plain http is only accepted for this machine; use https; nothing sent"
    return parsed, None


def _post(url, parsed, body, token):
    """None when the server accepted the document, else the one-line reason."""
    host = _plain(parsed.hostname)
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {token}",
                 "User-Agent": f"sunglasses/{__version__}"})
    handlers = [_NoRedirect()]
    if _loopback(parsed.hostname):
        # A proxy named in the environment must not see a token meant for this machine.
        handlers.append(urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as answer:
            code = answer.status
    except urllib.error.HTTPError as err:
        if 300 <= err.code < 400:
            return f"{host} answered with a redirect, which is not followed; nothing more sent"
        return f"{host} answered HTTP {err.code}; the report was not accepted"
    except Exception as err:  # URLError, timeout, TLS, reset: all one line, never the text
        return f"could not reach {host} ({type(err).__name__}); the report was not sent"
    return None if 200 <= code < 300 else f"{host} answered HTTP {code}; the report was not accepted"


def deliver(url, held, source_name=None, include_text=False, pattern_count=None,
            include_receipts=False):
    """Upload what the scan held, or say in one stderr line why nothing was.

    `held` is `(doc, kind)` from the scan, or None when the run ended without a scan
    result (a refusal, a kind of scan this reporter does not cover). Never raises.
    """
    try:
        if held is None:
            _line("this run ended without a scan result to report; nothing sent")
            return
        doc, kind = held
        parsed, problem = _target(url)
        if problem:
            _line(problem)
            return
        token = os.environ.get(TOKEN_ENV, "").strip()
        if not token:
            _line(f"{TOKEN_ENV} is not set; nothing sent")
            return
        if not (token.isascii() and token.isprintable()):
            _line(f"{TOKEN_ENV} is not a usable header value; nothing sent")
            return
        if finding_count(doc) > MAX_FINDINGS:
            _line(f"the scan has more than {MAX_FINDINGS} findings; nothing sent")
            return
        receipts, why_not = read_receipts() if include_receipts else (None, None)
        envelope = build_envelope(doc, kind, source_name, include_text, pattern_count, receipts)
        body = json.dumps(envelope).encode("utf-8", "surrogatepass")
        if len(body) > MAX_BODY_BYTES and receipts is not None:
            receipts, why_not = None, "with them the report is over the size limit"
            envelope["receipts"] = None
            body = json.dumps(envelope).encode("utf-8", "surrogatepass")
        if len(body) > MAX_BODY_BYTES:
            _line(f"the report is {len(body)} bytes, over the {MAX_BODY_BYTES} limit; nothing sent")
            return
        failed = _post(url, parsed, body, token)
        if failed:
            _line(failed)
            return
        note = ""
        if include_receipts:
            note = " with receipts" if receipts else f", receipts left out: {why_not}"
        _line(f"report sent to {_plain(parsed.hostname)}{note}")
    except Exception as err:  # the scan's outcome never depends on this
        _line(f"could not build the report ({type(err).__name__}); nothing sent")
