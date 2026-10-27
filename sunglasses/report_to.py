"""Send one finished scan to a URL the user named with `--report-to`.

Off unless the flag is given. When it is, the upload runs after the scan has decided its
output and its exit code, and nothing here can change either. Every way the upload can
fail is one line on stderr, never an exception, never a different exit code.

What leaves the machine is one JSON document (`ENVELOPE_SCHEMA`) built from a fixed list
of fields, not by blanking out the ones known to be sensitive: the scan's counts and
flags, its file paths, and for each finding its rule id, severity, category, line and
the SHA-256 and length of the text it matched. Every other field of the scan's result
is left out, so a field added to that result later is not sent until it is added to the
list here. With `--report-include-text` the matched text itself is sent in place of its
hash. `line` is the 1-based line where the matched text first appears in the file as
read, or null when it cannot be located (text on the command line, a format that is
extracted before it is scanned, a file too large to read again).

With `--report-include-receipts` the document also carries the newest segment of the
user's signed hook log, from its first line, with the public key that signs it
(`receipts`). Lines are the file's own, each with its trailing newline, so a
receiver verifies the same bytes the user's own verifier does. Without the flag
`receipts` is null.

The token comes from the environment (`SUNGLASSES_REPORT_TOKEN`), never from an
argument, so it stays out of shell history and process listings. It is sent only
as a bearer header to the exact URL given: redirects are refused, and a token goes
over plain http only to this machine. The scan's own child processes are not given it.

Limits: one upload attempt, at most `DEADLINE_SECONDS` in all (name lookup, connect,
send and the answer together); a report over `MAX_BODY_BYTES` or `MAX_FINDINGS` is not
sent. The size is checked after the report is built, so building it can use memory in
proportion to the scan.
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
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import __version__

ENVELOPE_SCHEMA = "sg-report/1"
TOKEN_ENV = "SUNGLASSES_REPORT_TOKEN"
MAX_BODY_BYTES = 1 << 20
MAX_FINDINGS = 5000
TIMEOUT_SECONDS = 10           # each blocking socket call
DEADLINE_SECONDS = 15          # the whole upload, whatever the server does

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


# The fields of the scan's result that are uploaded. A field not named here is not sent.
_SCAN_FIELDS = (
    "event_id", "decision", "severity", "channel", "source", "repo_name", "truncated",
    "bytes_scanned", "extraction_complete", "inspection_complete", "threat_found", "is_clean",
    "findings_count", "patterns_fired", "latency_ms", "files_scanned", "files_with_threats",
    "files_incomplete", "files_skipped", "total_threats", "scan_time_ms", "exit_code")
_COUNT_MAPS = ("severity_breakdown", "category_breakdown")      # {name: count}
_FILE_FIELDS = ("file", "decision", "threats")
_FINDING_FIELDS = ("id", "severity", "category", "line")


def _plain_value(value):
    """True for the values a counter or a flag can hold: no containers, no bytes."""
    return value is None or isinstance(value, (str, int, float, bool))


def _project_finding(finding, include_text):
    out = {key: finding[key] for key in _FINDING_FIELDS
           if key in finding and _plain_value(finding[key])}
    text = finding.get("matched_text")
    if isinstance(text, str):
        out["matched_text"] = text if include_text else _digest(text)
    return out


def _project_findings(findings, include_text):
    return [_project_finding(f, include_text) for f in findings or [] if isinstance(f, dict)]


def project_scan(doc, include_text=False):
    """The part of the scan's result that is uploaded, built from the field lists above."""
    out = {key: doc[key] for key in _SCAN_FIELDS if key in doc and _plain_value(doc[key])}
    for key in _COUNT_MAPS:
        counts = doc.get(key)
        if isinstance(counts, dict):
            out[key] = {str(k): v for k, v in counts.items()
                        if isinstance(v, int) and not isinstance(v, bool)}
    if "findings" in doc:
        out["findings"] = _project_findings(doc["findings"], include_text)
    if "file_results" in doc:
        out["file_results"] = [
            {**{k: entry[k] for k in _FILE_FIELDS if k in entry and _plain_value(entry[k])},
             "findings": _project_findings(entry.get("findings"), include_text)}
            for entry in doc["file_results"] or [] if isinstance(entry, dict)]
    return out


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
    scan = project_scan(doc, include_text)
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


def _post_once(url, parsed, body, token):
    """None when the server accepted the document, else the one-line reason. May block
    for as long as a server keeps answering; `_post` is what bounds it."""
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


def _post(url, parsed, body, token):
    """`_post_once`, abandoned after `DEADLINE_SECONDS` in all.

    The socket timeout bounds each blocking call, not the upload: a server that answers a
    byte at a time, or a name lookup that does not return, would hold the scan's exit for
    as long as it likes. So the upload runs on a daemon thread and this waits for it up to
    the deadline. When it is not done, the line says so and the upload is left behind: the
    process is already on its way out, and the thread never writes to stdout or stderr.
    """
    outcome = []

    def work():
        try:
            outcome.append(_post_once(url, parsed, body, token))
        except Exception as err:
            outcome.append(f"could not send ({type(err).__name__}); the report was not sent")

    worker = threading.Thread(target=work, name="report-to-upload", daemon=True)
    started = time.monotonic()
    worker.start()
    worker.join(DEADLINE_SECONDS)
    if worker.is_alive():
        waited = max(1, round(time.monotonic() - started))
        return (f"{_plain(parsed.hostname)} did not finish within {waited} s; "
                "the upload was given up on and the report may not have arrived")
    return outcome[0]


def _encode(envelope):
    """The upload body. NaN and Infinity are not JSON; a document holding one is not sent."""
    return json.dumps(envelope, allow_nan=False).encode("utf-8", "surrogatepass")


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
        body = _encode(envelope)
        if len(body) > MAX_BODY_BYTES and receipts is not None:
            receipts, why_not = None, "with them the report is over the size limit"
            envelope["receipts"] = None
            body = _encode(envelope)
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
