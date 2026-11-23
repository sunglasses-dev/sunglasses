"""The marker a finding of a secret shows at every door that prints or writes the words it matched.

The engine keeps the full match: duplicate spans, the repo policy and the report line lookup read it in the process.
A DOOR is a place where the match leaves the process as text: the MCP server result, the command line (text and JSON),
a SARIF file, a report file that was asked to carry the text. At a door a finding of a secret class shows a MARKER

    first 4 characters, the length, the rule id, a short digest   e.g.  AKIA… [20 characters, GLS-SD-003, 1f0ab3c7]

enough to find the secret in the file the door names, and to tell two findings apart. The digest is the first 8
characters of the SHA-256 of the whole match: the same secret reads the same marker twice. Every door calls the one
function below; there is no second marker form. The words of a finding that is not a secret lose the characters of a
secret found in the same scan.
The library result (``ScanResult``, ``to_dict``) is not changed. The command line gives the full match back for the
person at the terminal who asks for it with ``--show-secrets`` (text and JSON); a SARIF file never carries it.
"""
import hashlib
from typing import Any

from .preprocessor import decode_leetspeak

SECRET_CATEGORY = "secret_detection"
SECRET_ID_PREFIX = "GLS-SD-"


DIGEST_CHARS = 8  # how much of the SHA-256 of the match the marker carries


def digest(matched: str) -> str:
    """The first DIGEST_CHARS characters of the SHA-256 of the match: the same secret reads the same digest, and
    two different secrets read two different digests."""
    return hashlib.sha256(matched.encode("utf-8", "surrogatepass")).hexdigest()[:DIGEST_CHARS]


def mask(matched: str, rule_id: Any) -> str:
    """The marker: first 4 characters, the length, the rule id, a short digest."""
    return f"{matched[:4]}… [{len(matched)} characters, {rule_id}, {digest(matched)}]"


def is_secret_finding(finding: Any) -> bool:
    """True for a finding whose match IS a credential: the secret detection family. A finding with no category
    is read by its rule id; a rule in doubt is masked."""
    if not isinstance(finding, dict):
        return False
    if finding.get("category") == SECRET_CATEGORY:
        return True
    rule_id = finding.get("id")
    return isinstance(rule_id, str) and rule_id.startswith(SECRET_ID_PREFIX)


EDGE_MIN = 3  # the fewest characters of a secret that a window may show at its edge before they are cut


def secret_strings(findings: Any) -> tuple:
    """The full matches of the secret findings of ONE scan: what no printed window may show a piece of."""
    out = []
    for f in findings or ():
        if is_secret_finding(f):
            matched = f.get("matched_text")
            if isinstance(matched, str) and len(matched) >= EDGE_MIN and matched not in out:
                out.append(matched)
    return tuple(out)


def clean_window(text: Any, secrets: Any) -> Any:
    """A window of words printed for a finding that is NOT a secret (its match, the whole words around it) loses the
    characters that overlap the span of a secret finding of the same scan: a whole key, the end of a key at the
    start of the window, the start of a key at its end, a window that lies inside a key. The cut is one ellipsis."""
    if not isinstance(text, str) or not text or not secrets:
        return text
    out = text
    keys = []
    for secret in secrets:
        # The words a finding quotes can be the text as the scanner folded it (case, look-alike digits), so the
        # secret is cut under both readings.
        for key in (secret.lower(), decode_leetspeak(secret.lower())):
            if key not in keys:
                keys.append(key)
    for key in keys:
        low = out.lower()
        at = low.find(key)
        while at != -1:                                   # the whole secret
            out = out[:at] + "\u2026" + out[at + len(key):]
            low = out.lower()
            at = low.find(key)
        if len(low) >= EDGE_MIN and low.strip("\u2026") and low.strip("\u2026") in key:   # the window lies inside the key
            out = "\u2026"
            continue
        for k in range(min(len(low), len(key) - 1), EDGE_MIN - 1, -1):   # the window starts with the end of the key
            if low.startswith(key[-k:]):
                out = "\u2026" + out[k:]
                break
        low = out.lower()
        for k in range(min(len(low), len(key) - 1), EDGE_MIN - 1, -1):   # the window ends with the start of the key
            if low.endswith(key[:k]):
                out = out[:len(out) - k] + "\u2026"
                break
    return out


def shown_match(finding: Any, matched: Any = None, show_secrets: bool = False, secrets: Any = ()) -> Any:
    """The words a door prints for a finding: the mask for a secret; for any other finding its words, without the
    characters that overlap a secret of the same scan (``secrets``, from secret_strings).
    ``matched`` defaults to the finding's own matched_text."""
    if matched is None and isinstance(finding, dict):
        matched = finding.get("matched_text")
    if show_secrets or not isinstance(matched, str) or not matched:
        return matched
    if is_secret_finding(finding):
        return mask(matched, finding.get("id"))
    return clean_window(matched, secrets)


def _cut_finding(masked: Any, original: Any, secrets: tuple) -> Any:
    """A finding of a document that is not a secret, with its windows cut."""
    if not isinstance(masked, dict) or is_secret_finding(original):
        return masked
    for key in ("matched_text", "shown_text"):
        if isinstance(masked.get(key), str):
            masked[key] = clean_window(masked[key], secrets)
    return masked


def mask_document(doc: Any, show_secrets: bool = False) -> Any:
    """A copy of a JSON document (a scan result, a list of results, a directory report) in which every finding
    of a secret class shows a mask in matched_text. Everything else is the same object, byte for byte."""
    if show_secrets:
        return doc
    if isinstance(doc, dict):
        out = {}
        # The findings listed side by side in one document are one scan: a secret among them cuts the windows of
        # the others (a window of a neighbouring finding can hold the start or the end of the key).
        listed = doc.get("findings")
        secrets = secret_strings(listed) if isinstance(listed, list) else ()
        for key, value in doc.items():
            if secrets and key == "findings" and isinstance(value, list):
                out[key] = [_cut_finding(mask_document(v), v, secrets) for v in value]
            else:
                out[key] = mask_document(value)
        if isinstance(out.get("matched_text"), str) and is_secret_finding(out):
            full = doc.get("matched_text")
            out["matched_text"] = mask(full, out.get("id"))
            if isinstance(out.get("shown_text"), str) and out["shown_text"]:
                out["shown_text"] = mask(full, out.get("id"))
        return out
    if isinstance(doc, list):
        return [mask_document(item) for item in doc]
    return doc
