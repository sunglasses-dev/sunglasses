"""The list of rules that keep no guard-floor copy (sunglasses/_floor_quiet.py) is pinned here.

What these tests hold:

  A. the shipped list is the pinned list: same ids, same count, same "reviewed" ids, no repeats, sorted,
  B. every id names a rule the engine knows, and the engine keeps no floor copy for it,
  C. the engine's own set (what the scan reads) is the shipped list; a copy with one unlisted id added, or
     one listed id removed, fails the pin check,
  D. a rule that is not listed still gets its floor copy, and the guard walk in tests/test_guard_floor.py
     excuses no id outside the pin,
  E. the rules whose floor copy is matched per window (FLOOR_WINDOWED) are the pinned ones, are not on the quiet
     list, keep their copy for a compact attack with a guard word, and lose it for the same words spread apart.

The tuning texts the list was measured on live on one machine; the script that recomputes the list stays
there. The repository holds the list and this pin.
"""
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from _floor_quiet_pin import QUIET_COUNT, QUIET_IDS, REVIEWED_IDS, WINDOWED_IDS   # noqa: E402
from sunglasses import _floor_quiet, engine as engine_module            # noqa: E402
from sunglasses.engine import SunglassesEngine, _guard_floor_twin        # noqa: E402

REASONS = {"wide", "reviewed"}


def check_pin(engine_ids, listed):
    """The checks of section A and C, as one function, so a test can show that they fail on a changed list."""
    pinned = set(QUIET_IDS)
    assert len(QUIET_IDS) == QUIET_COUNT == len(pinned), "the pin lists an id twice or the count is stale"
    assert set(listed) == pinned, ("not pinned", sorted(set(listed) - pinned), "not listed", sorted(pinned - set(listed)))
    assert set(engine_ids) == pinned, ("engine set differs from the pin", sorted(set(engine_ids) ^ pinned))


# ── A. the shipped list is the pinned list ───────────────────────────────────

def test_the_list_is_the_pinned_list():
    check_pin(engine_module._FLOOR_QUIET_IDS, _floor_quiet.FLOOR_QUIET_IDS)


def test_the_list_has_no_repeats_and_is_sorted():
    ids = [rule_id for rule_id, _reason in _floor_quiet.FLOOR_QUIET]
    assert ids == sorted(ids)
    assert len(ids) == len(set(ids)) == QUIET_COUNT


def test_every_reason_is_known_and_the_reviewed_ids_are_pinned():
    for _rule_id, reason in _floor_quiet.FLOOR_QUIET:
        assert reason in REASONS
    reviewed = sorted(rule_id for rule_id, reason in _floor_quiet.FLOOR_QUIET if reason == "reviewed")
    assert reviewed == sorted(REVIEWED_IDS)


# ── B. the ids name rules, and the engine keeps no copy for them ─────────────

@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


@pytest.mark.parametrize("rule_id", sorted(QUIET_IDS))
def test_a_listed_rule_exists_and_has_no_floor_copy(engine, rule_id):
    assert rule_id in engine._pattern_by_id, rule_id
    assert engine._floor_entry(rule_id) is None


# ── C. a changed list is caught ──────────────────────────────────────────────

def _unlisted_guarded_rule(engine):
    for pattern in engine._pattern_by_id.values():
        if pattern["id"] not in QUIET_IDS and _guard_floor_twin(pattern) is not None:
            return pattern["id"]
    raise AssertionError("no guarded rule outside the list")


def test_an_added_id_fails_the_pin(engine):
    extra = _unlisted_guarded_rule(engine)
    with pytest.raises(AssertionError):
        check_pin(set(engine_module._FLOOR_QUIET_IDS) | {extra}, _floor_quiet.FLOOR_QUIET_IDS)
    with pytest.raises(AssertionError):
        check_pin(engine_module._FLOOR_QUIET_IDS, set(_floor_quiet.FLOOR_QUIET_IDS) | {extra})


def test_a_removed_id_fails_the_pin():
    some = sorted(QUIET_IDS)[0]
    with pytest.raises(AssertionError):
        check_pin(set(engine_module._FLOOR_QUIET_IDS) - {some}, _floor_quiet.FLOOR_QUIET_IDS)
    with pytest.raises(AssertionError):
        check_pin(engine_module._FLOOR_QUIET_IDS, set(_floor_quiet.FLOOR_QUIET_IDS) - {some})


def test_an_added_id_would_fail_the_guard_walk(monkeypatch):
    """The walk in test_guard_floor.py holds every id outside the pin to "a guard word never allows". With one
    unlisted id added to the engine's set, that very check fails for it: the excuse is no wider than the pin."""
    from test_guard_floor import _case, _rule_ids                          # noqa: E402
    extra = None
    for rule_id in _rule_ids():
        if rule_id in QUIET_IDS:
            continue
        pattern, _plain, guarded, base, guards = _case(rule_id)
        if base is None or not guards:
            continue
        channel, attack = base
        if any(guarded.scan(attack + " " + g, channel=channel).decision == "allow" for g in guards):
            continue                                   # the walk is red for it already; pick a clean one
        extra = (rule_id, pattern, base, guards)
        break
    assert extra, "no rule to test with"
    rule_id, pattern, (channel, attack), guards = extra
    monkeypatch.setattr(engine_module, "_FLOOR_QUIET_IDS", frozenset(set(QUIET_IDS) | {rule_id}))
    mutant = SunglassesEngine(patterns=[pattern], mechanisms=False, validators=False)
    assert any(mutant.scan(attack + " " + g, channel=channel).decision == "allow" for g in guards), rule_id
    with pytest.raises(AssertionError):
        check_pin(engine_module._FLOOR_QUIET_IDS, _floor_quiet.FLOOR_QUIET_IDS)


# ── D. a rule that is not listed keeps its copy ──────────────────────────────

def test_a_rule_outside_the_list_keeps_its_floor_copy(engine):
    extra = _unlisted_guarded_rule(engine)
    entry = engine._floor_entry(extra)
    assert entry is not None
    assert entry[0]["id"] == extra


# ── E. a floor copy matched per window ───────────────────────────────────────

ATTACK = {
    "GLS-AW-679": ("message", "browser self-play reviewer golden trust without branchid".split(), "defensive"),
    "GLS-MR-039": ("message", "memorized verbatim patient".split(), "unit test"),
}
FILLER = "lorem ipsum dolor sit amet consectetur " * 80          # about 3,000 characters, no signal word


def _one_rule_engine(rule_id):
    pattern = SunglassesEngine()._pattern_by_id[rule_id]
    return SunglassesEngine(patterns=[pattern], mechanisms=False, validators=False)


def test_the_windowed_list_is_the_pinned_list_and_not_quiet():
    assert tuple(sorted(_floor_quiet.FLOOR_WINDOWED_IDS)) == tuple(sorted(WINDOWED_IDS))
    assert set(engine_module._FLOOR_WINDOWED_IDS) == set(WINDOWED_IDS)
    assert len(_floor_quiet.FLOOR_WINDOWED) == len(set(_floor_quiet.FLOOR_WINDOWED))
    assert not (set(WINDOWED_IDS) & set(QUIET_IDS))


@pytest.mark.parametrize("rule_id", sorted(WINDOWED_IDS))
def test_a_windowed_rule_keeps_a_floor_copy_matched_per_window(engine, rule_id):
    entry = engine._floor_entry(rule_id)
    assert entry is not None
    assert [mode for mode, _rx, _guards in entry[1]] == ["windowed_edges"]


@pytest.mark.parametrize("rule_id", sorted(WINDOWED_IDS))
def test_a_compact_attack_with_a_guard_word_is_not_allowed(rule_id):
    channel, words, guard = ATTACK[rule_id]
    engine = _one_rule_engine(rule_id)
    assert engine.scan(" ".join(words), channel=channel).decision != "allow"          # the rule itself
    assert engine.scan(" ".join(words) + " " + guard, channel=channel).decision != "allow"   # its floor copy


@pytest.mark.parametrize("rule_id", sorted(WINDOWED_IDS))
def test_the_same_words_spread_over_a_document_with_a_guard_word_are_allowed(rule_id):
    channel, words, guard = ATTACK[rule_id]
    engine = _one_rule_engine(rule_id)
    spread = (" " + FILLER + " ").join(words) + " " + guard
    assert len(spread) > 4 * engine.COOCCUR_WINDOW
    assert engine.scan(spread, channel=channel).decision == "allow"


# GLS-MR-039 opens with ^ and a lookahead, so its copy is "windowed" by the anchored branch even when the id leaves
# the windowed set (only the window-edge move is lost). Its words also sit within 200 characters of each other in the
# rule itself, so spread words never match as a whole text. The id-leaves mutant cannot fail for it; it has its own
# mutant below (the copy matched on the whole text, with the last group far from the first two).
ID_LEAVES_CAN_FAIL = sorted(set(WINDOWED_IDS) - {"GLS-MR-039"})


@pytest.mark.parametrize("rule_id", ID_LEAVES_CAN_FAIL)
def test_without_the_window_the_spread_words_would_not_be_allowed(monkeypatch, rule_id):
    """The mutant: the id leaves the windowed set. The spread document then matches the whole-text copy."""
    channel, words, guard = ATTACK[rule_id]
    monkeypatch.setattr(engine_module, "_FLOOR_WINDOWED_IDS", frozenset())
    engine = _one_rule_engine(rule_id)
    spread = (" " + FILLER + " ").join(words) + " " + guard
    assert engine.scan(spread, channel=channel).decision != "allow"


FAR_GROUP = "memorized verbatim " + FILLER + " patient unit test"      # the pair, then 3,000 characters, then the third group


def test_a_third_group_far_from_the_pair_is_allowed_because_the_copy_is_matched_per_window():
    engine = _one_rule_engine("GLS-MR-039")
    rx = engine._floor_entry("GLS-MR-039")[1][0][1]
    assert rx.match(FAR_GROUP)                                        # the whole text holds all three groups
    assert engine._match_windowed(rx, FAR_GROUP, edges=True) is None  # no window holds them together
    assert len(FAR_GROUP) > 2 * engine.COOCCUR_WINDOW
    assert engine.scan(FAR_GROUP, channel="message").decision == "allow"


def test_a_far_third_group_would_not_be_allowed_if_the_copy_were_matched_on_the_whole_text(monkeypatch):
    """The mutant: the per-window match becomes a match on the whole text."""
    monkeypatch.setattr(SunglassesEngine, "_match_windowed", lambda self, rx, text, edges=False: rx.match(text))
    assert _one_rule_engine("GLS-MR-039").scan(FAR_GROUP, channel="message").decision != "allow"


def test_an_unlisted_id_added_to_the_windowed_set_fails_the_pin(monkeypatch):
    extra = _unlisted_guarded_rule(SunglassesEngine())
    monkeypatch.setattr(engine_module, "_FLOOR_WINDOWED_IDS", frozenset(set(WINDOWED_IDS) | {extra}))
    with pytest.raises(AssertionError):
        assert set(engine_module._FLOOR_WINDOWED_IDS) == set(WINDOWED_IDS)


# ── F. a window edge never cuts a word ───────────────────────────────────────

FILL = "lorem ipsum "


def _edge_text(before, tail, window, stride):
    """A document in which the window that starts at `stride` begins inside the word `inpatient`."""
    head = (FILL * 80)[: stride - 2]
    return head + "in" + before + " memorized verbatim " + (FILL * 200)[: window] + tail


def test_a_window_that_starts_inside_a_word_does_not_make_a_word_boundary(engine):
    """`patient` inside `inpatient` is no word. The window at offset 600 starts between `in` and `patient`."""
    rx = engine._floor_entry("GLS-MR-039")[1][0][1]
    text = _edge_text("patient", "", engine.COOCCUR_WINDOW, engine.COOCCUR_STRIDE)
    assert text[engine.COOCCUR_STRIDE : engine.COOCCUR_STRIDE + 7] == "patient"
    assert rx.match(text) is None                                     # the whole text has no such word
    assert engine._match_windowed(rx, text, edges=True) is None                   # and no window may invent one
    assert rx.match(text[engine.COOCCUR_STRIDE : engine.COOCCUR_STRIDE + engine.COOCCUR_WINDOW])   # the old cut does


def test_a_window_that_ends_inside_a_word_does_not_make_a_word_boundary(engine):
    """`patientx` is no `patient`; the window that ends right after `patient` must not see an end of word."""
    rx = engine._floor_entry("GLS-MR-039")[1][0][1]
    lead = "memorized verbatim "
    room = engine.COOCCUR_WINDOW - len(lead) - 7
    pad = (FILL * 200)[:room]
    pad = pad[: pad.rfind(" ") + 1].ljust(room)                      # ends on a space, so `patient` starts a word
    text = lead + pad + "patientx " + (FILL * 120)
    assert text[engine.COOCCUR_WINDOW - 7 : engine.COOCCUR_WINDOW] == "patient"
    assert rx.match(text) is None
    assert engine._match_windowed(rx, text, edges=True) is None
    assert rx.match(text[: engine.COOCCUR_WINDOW])                    # the old cut does


@pytest.mark.parametrize("rule_id", sorted(WINDOWED_IDS))
def test_the_edges_of_every_window_land_on_whitespace_in_a_text_of_short_words(engine, rule_id):
    text = (FILL * 400)[:5000]
    for i in range(0, len(text), engine.COOCCUR_STRIDE):
        start, end = engine._window_edges(text, i)
        assert start == 0 or text[start - 1].isspace(), (i, start)
        assert end == len(text) or text[end].isspace() or text[end - 1].isspace(), (i, end)
        assert start <= i and i - start < engine.WINDOW_EDGE_SLACK                # never narrower than the plain cut
        assert end >= min(i + engine.COOCCUR_WINDOW, len(text))


def test_a_window_inside_one_long_word_keeps_the_plain_cut(engine):
    text = "x" * 5000
    assert engine._window_edges(text, 600) == (600, 1800)


def test_the_last_word_of_a_text_with_no_space_after_it_is_kept_whole(engine):
    """The end of the text is the end of the word: `patientx` is cut after `patient` by the plain edge (1200)
    and must be carried to the end of the text (1201), the way a start at offset 0 is."""
    text = " " * 1193 + "patientx"
    assert len(text) == 1201 and text[1193:1200] == "patient"
    assert engine._window_edges(text, 0) == (0, 1201)


def test_the_window_end_moves_at_most_the_slack_forward_and_the_start_at_most_the_slack_back(engine):
    slack, window = engine.WINDOW_EDGE_SLACK, engine.COOCCUR_WINDOW
    assert slack == 256 and window == 1200
    # END, whitespace after the word: the plain cut is at 1200, the word ends 256 on, or 257 on.
    for run, moved in ((slack, True), (slack + 1, False)):
        text = " " * 100 + "x" * (window - 100 + run) + " " + "y" * 50
        end = engine._window_edges(text, 0)[1]
        assert end == (window + run if moved else window), (run, end)
    # END, end of the text after the word: 256 on moves, 257 on keeps the plain cut.
    for run, moved in ((slack, True), (slack + 1, False)):
        text = " " * 100 + "x" * (window - 100 + run)
        end = engine._window_edges(text, 0)[1]
        assert end == (len(text) if moved else window), (run, end)
    # START, whitespace before the word: the plain cut is at 1200, the word begins 256 back, or 257 back.
    for run, moved in ((slack, True), (slack + 1, False)):
        text = " " * (window - run) + "x" * 1500
        start = engine._window_edges(text, window)[0]
        assert start == (window - run if moved else window), (run, start)
    # START, start of the text before the word: 256 back moves to 0, 257 back keeps the plain cut.
    for run, moved in ((slack, True), (slack + 1, False)):
        text = "x" * 1500
        start = engine._window_edges(text, run)[0]
        assert start == (0 if moved else run), (run, start)


def test_a_window_moved_to_the_end_of_the_text_holds_the_plain_one(engine):
    for text in (" " * 1193 + "patientx", " " * 100 + "x" * 1356, "x" * 1456 + " " + "y" * 30):
        for i in range(0, len(text), engine.COOCCUR_STRIDE):
            start, end = engine._window_edges(text, i)
            assert start <= i and end >= min(i + engine.COOCCUR_WINDOW, len(text)) and end <= len(text)


def _last_word_text(guard=""):
    """1,201 characters. The plain window ends right after `patient`; the text ends with `patientx`."""
    lead = "memorized verbatim " + (guard + " " if guard else "")
    text = lead + " " * (engine_module.SunglassesEngine.COOCCUR_WINDOW + 1 - len(lead) - len("patientx")) + "patientx"
    assert len(text) == engine_module.SunglassesEngine.COOCCUR_WINDOW + 1
    assert text[engine_module.SunglassesEngine.COOCCUR_WINDOW - 7 : engine_module.SunglassesEngine.COOCCUR_WINDOW] == "patient"
    return text


def test_the_real_rule_copy_does_not_see_a_word_end_at_the_cut_before_the_last_word(engine):
    """GLS-MR-039 floor copy: `patientx` is no word `patient`. The whole text has no match, the old plain cut
    (and the old end edge, which stopped one short of the end of the text) found one in the first window."""
    rx = engine._floor_entry("GLS-MR-039")[1][0][1]
    text = _last_word_text()
    assert rx.match(text) is None
    assert rx.match(text[: engine.COOCCUR_WINDOW])                                  # the plain cut invents the word end
    assert engine._match_windowed(rx, text) is not None                             # plain windows: the fragment matches
    assert engine._match_windowed(rx, text, edges=True) is None                     # moved edges: it does not
    assert engine._eval_regex("windowed_edges", rx, None, text) is None


def test_the_whole_scanner_allows_the_last_word_that_only_looks_like_the_listed_word():
    """Real rule, only that rule enabled, its guard word in the text so the floor copy decides."""
    channel, words, guard = ATTACK["GLS-MR-039"]
    engine = _one_rule_engine("GLS-MR-039")
    text = _last_word_text(guard)
    assert engine.scan(text, channel=channel).decision == "allow"
    assert engine.scan(text[:-1], channel=channel).decision != "allow"              # the real word `patient` at the end


def test_a_compact_match_inside_a_long_document_is_still_found(engine):
    """Moving the edges to whitespace loses nothing: the attack sits whole inside some window."""
    rx = engine._floor_entry("GLS-MR-039")[1][0][1]
    for offset in (0, 1, 599, 600, 601, 1199, 1200, 2399, 2400):
        text = (FILL * 400)[:offset] + " memorized verbatim patient " + (FILL * 400)[:4000]
        assert engine._match_windowed(rx, text, edges=True), offset


def test_a_window_moved_to_whitespace_still_holds_everything_the_plain_cut_held(engine):
    """Two signals 600 apart, the first inside the word the window at 1200 cuts (`xxalpha`): the plain cut
    keeps `alpha`, so the moved window must keep it too (it starts at the word start, not after the word)."""
    import re
    rx = re.compile(r"(?is)^(?=.*alpha)(?=.*beta).*$")
    head = (FILL * 200)[:1197]
    head = head[: head.rfind(" ") + 1].ljust(1197) + " "                 # 1198 characters, the last one a space
    text = head + "xxalpha" + " " * (1800 - 1205) + "beta " + (FILL * 100)
    assert text[1200:1205] == "alpha" and text[1800:1804] == "beta"
    assert rx.match(text) and rx.match(text[1200:2400])               # the whole text and the plain cut match
    assert engine._match_windowed(rx, text, edges=True)
    start, end = engine._window_edges(text, 1200)
    assert start == 1198 and end >= 2400


def test_every_window_holds_the_plain_one(engine):
    text = ("alpha-beta gamma" + FILL) * 300
    for i in range(0, len(text), engine.COOCCUR_STRIDE):
        start, end = engine._window_edges(text, i)
        assert start <= i and end >= min(i + engine.COOCCUR_WINDOW, len(text))


def test_only_the_floor_copy_has_its_window_edges_moved(engine):
    """An ordinary windowed rule keeps the plain cut, so its results on long documents are what they were."""
    rx = engine._floor_entry("GLS-MR-039")[1][0][1]
    text = _edge_text("patient", "", engine.COOCCUR_WINDOW, engine.COOCCUR_STRIDE)
    assert engine._match_windowed(rx, text)                                         # plain cut: the fragment matches
    assert engine._match_windowed(rx, text, edges=False)
    assert engine._match_windowed(rx, text, edges=True) is None                     # moved edges: it does not
    assert engine._eval_regex("windowed", rx, None, text)
    assert engine._eval_regex("windowed_edges", rx, None, text) is None


def test_no_other_floor_copy_is_matched_with_moved_edges(engine):
    modes = {}
    for rule_id in engine._pattern_by_id:
        entry = engine._floor_entry(rule_id)
        if entry is not None:
            for mode, _rx, _guards in entry[1]:
                modes.setdefault(mode, set()).add(rule_id)
    assert modes.get("windowed_edges") == set(WINDOWED_IDS)
