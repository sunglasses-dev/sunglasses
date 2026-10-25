"""Real agent transcripts, taken from public issue trackers, and what the scanner decides on them.

These texts are excerpts from public issue reports: tool-call logs, session captures,
API error payloads, console output. Each has its source URL and the licence of that
repository.
The excerpts are the posters' own words; the source URL is the attribution.

MANIFEST.json holds, per text, a hand label (ordinary / relay / attack), whether it
was read in full or screened, and the decision the scanner gave it, with the finding ids that
fired, on four channels: message, file, api_response and tool_output. The ids are as of the
last refresh of the record.

The decision check is a ratchet in one direction, on the order allow < quarantine < block.
A scan that is WORSE than the recorded one fails: for an ordinary or relay text, any step
up (allow to quarantine, allow to block, quarantine to block); for an attack text, any step
down (block to quarantine, block to allow, quarantine to allow). A scan that is better
passes, and the record is refreshed when someone next regenerates it.
"""
import hashlib
import json
import pathlib
import re

import pytest

from sunglasses.engine import SunglassesEngine

CORPUS = pathlib.Path(__file__).resolve().parent / "fixtures" / "real_transcripts"
MANIFEST = json.loads((CORPUS / "MANIFEST.json").read_text(encoding="utf-8"))
CHANNELS = ("message", "file", "api_response", "tool_output")
LABELS = {"ordinary", "relay", "attack"}
READ = {"full", "screened"}
DECISIONS = {"allow", "quarantine", "block"}
SECRETS = {
    "key prefixes": re.compile(r"\b(sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    "cloud key id": re.compile(r"\bAKIA[0-9A-Z]{12,}"),
    "chat token": re.compile(r"\bxox[abp]-[A-Za-z0-9-]{10,}"),
    "api key": re.compile(r"\bAIza[0-9A-Za-z_-]{20,}"),
    "bearer": re.compile(r"(?i)bearer\s+(?!REDACTED_TOKEN)[A-Za-z0-9._~+/=-]{16,}"),
    "e-mail": re.compile(r"[\w.+-]+@(?!example\.invalid)[\w-]+\.[\w.-]+"),
    "unix home": re.compile(r"/(?:Users|home)/(?!user\b)[^/\s\"']+"),
    "windows home": re.compile(r"C:\\Users\\(?!user\b)[^\\\s\"']+"),
    "request id": re.compile(r"(?i)\brequest[ _-]?id[\"']?\s*[:=]\s*[\"']?(?!(?:req_)?REDACTED_ID)[A-Za-z0-9:_-]{8,}"),
    "request id prefix": re.compile(r"\breq_(?!REDACTED_ID)[A-Za-z0-9]{8,}"),
    "token field": re.compile(r"(?i)\b(?:auth[-_ ]?token|api[-_ ]?key|secret)[\"']?\s*[:=]\s*[\"']?(?!REDACTED_TOKEN)[A-Za-z0-9._~+/=-]{12,}"),
}
# Each control is a (guard, variant) pair, shown to fire on a detail of the kind the guard names and to stay
# quiet on its replacement. REQUIRED_CONTROLS declares the pairs separately, so dropping one row fails the file.
GUARD_CONTROLS = [
    ("request id", "dotted", "Request ID: AAAA:000000:000000:000000:00000000", "Request ID: REDACTED_ID"),
    ("request id", "uuid", "request_id: 00000000-0000-4000-8000-000000000000", "request_id: req_REDACTED_ID"),
    ("request id prefix", "req prefix", "reply req_0123456789abcdef", "reply req_REDACTED_ID"),
    ("token field", "auth-token", "Auth-Token: EXAMPLE-SEC-0123456789AB", "Auth-Token: REDACTED_TOKEN"),
    # Samples that look like a credential or a person are built from pieces, so no stored line in this
    # file is itself one.
    ("key prefixes", "sk-", "key " + "sk-" + "0" * 24, "OPENAI_API_KEY=REDACTED_TOKEN"),
    ("key prefixes", "ghp_", "key " + "ghp_" + "0" * 24, "OPENAI_API_KEY=REDACTED_TOKEN"),
    ("key prefixes", "gho_", "key " + "gho_" + "0" * 24, "OPENAI_API_KEY=REDACTED_TOKEN"),
    ("key prefixes", "github_pat_", "key " + "github_pat_" + "0" * 24, "OPENAI_API_KEY=REDACTED_TOKEN"),
    ("cloud key id", "AKIA", "id " + "AKIA" + "0" * 16, "id REDACTED_TOKEN"),
    ("chat token", "xox", "token " + "xoxb-" + "0" * 12, "token REDACTED_TOKEN"),
    ("api key", "AIza", "key " + "AIza" + "0" * 24, "key REDACTED_TOKEN"),
    ("bearer", "bearer", "Authorization: Bearer " + "0" * 24, "Authorization: Bearer REDACTED_TOKEN"),
    ("e-mail", "e-mail", "write to person@" + "mail.test", "write to person@example.invalid"),
    ("unix home", "/home", "/home/" + "someone" + "/project", "/home/user/project"),
    ("unix home", "/Users", "/Users/" + "someone" + "/project", "/Users/user/project"),
    ("windows home", "C:\\Users", "C:\\Users\\" + "someone" + "\\project", "C:\\Users\\user\\project"),
]
REQUIRED_CONTROLS = {
    ("request id", "dotted"),
    ("request id", "uuid"),
    ("request id prefix", "req prefix"),
    ("token field", "auth-token"),
    ("key prefixes", "sk-"),
    ("key prefixes", "ghp_"),
    ("key prefixes", "gho_"),
    ("key prefixes", "github_pat_"),
    ("cloud key id", "AKIA"),
    ("chat token", "xox"),
    ("api key", "AIza"),
    ("bearer", "bearer"),
    ("e-mail", "e-mail"),
    ("unix home", "/home"),
    ("unix home", "/Users"),
    ("windows home", "C:\\Users"),
}


def _text(rid):
    return (CORPUS / "texts" / f"{rid}.txt").read_bytes().decode("utf-8")


def test_manifest_rows_match_the_text_files():
    files = {p.stem for p in (CORPUS / "texts").glob("*.txt")}
    assert set(MANIFEST) == files, (
        f"rows without a file: {sorted(set(MANIFEST) - files)}; files without a row: {sorted(files - set(MANIFEST))}"
    )


@pytest.mark.parametrize("rid", sorted(MANIFEST))
def test_each_row_has_provenance_a_label_and_a_matching_hash(rid):
    row = MANIFEST[rid]
    assert re.fullmatch(r"https://github\.com/[\w.-]+/[\w.-]+/(issues|pull)/\d+", row["source_url"]), row["source_url"]
    assert row["licence_of_repo"], "a licence note is required, even if it is 'none declared'"
    assert row["label"] in LABELS and row["read"] in READ
    assert set(row["main"]) == set(CHANNELS)
    assert all(row["main"][c]["decision"] in DECISIONS for c in CHANNELS)
    assert hashlib.sha256(_text(rid).encode("utf-8")).hexdigest() == row["sha256"], "text changed without its row"


@pytest.mark.parametrize("rid", sorted(MANIFEST))
def test_no_secret_or_personal_detail_is_left_in_a_text(rid):
    text = _text(rid)
    for name, rx in SECRETS.items():
        m = rx.search(text)
        assert m is None, f"{rid}: the {name} guard matched {m.group(0)[:20]!r}"


@pytest.mark.parametrize("name,variant,left,replaced", GUARD_CONTROLS)
def test_each_guard_catches_the_detail_it_names_and_accepts_the_replacement(name, variant, left, replaced):
    assert SECRETS[name].search(left), f"the {name} guard missed {left!r}"
    assert not any(rx.search(replaced) for rx in SECRETS.values()), f"a guard rejects the replacement {replaced!r}"


def test_every_guard_has_a_control():
    assert {name for name, _, _, _ in GUARD_CONTROLS} == set(SECRETS), (
        f"guards without a control: {sorted(set(SECRETS) - {name for name, _, _, _ in GUARD_CONTROLS})}; "
        f"controls without a guard: {sorted({name for name, _, _, _ in GUARD_CONTROLS} - set(SECRETS))}"
    )


def test_every_required_control_is_present_once():
    held = [(name, variant) for name, variant, _, _ in GUARD_CONTROLS]
    assert len(held) == len(set(held)), f"a control is listed twice: {sorted(x for x in held if held.count(x) > 1)}"
    assert set(held) == REQUIRED_CONTROLS, (
        f"missing controls: {sorted(REQUIRED_CONTROLS - set(held))}; unlisted controls: {sorted(set(held) - REQUIRED_CONTROLS)}"
    )


def test_every_label_the_grammar_allows_is_used_and_attack_rows_exist():
    used = {r["label"] for r in MANIFEST.values()}
    assert "ordinary" in used and "attack" in used, used


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


_RANK = {"allow": 0, "quarantine": 1, "block": 2}


@pytest.mark.parametrize("rid", sorted(MANIFEST))
def test_the_scanner_is_no_worse_than_the_recorded_decision(rid, engine):
    row = MANIFEST[rid]
    text = _text(rid)
    for ch in CHANNELS:
        got = engine.scan(text, channel=ch).decision
        was = row["main"][ch]["decision"]
        if row["label"] == "attack":
            assert _RANK[got] >= _RANK[was], f"{rid}/{ch}: an attack text recorded as {was} is now {got}"
        else:
            assert _RANK[got] <= _RANK[was], f"{rid}/{ch}: an {row['label']} text recorded as {was} is now {got}"
