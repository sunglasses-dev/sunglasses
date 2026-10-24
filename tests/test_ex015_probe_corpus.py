"""The EX-015 probe texts that earlier review rounds ran, one file per case, with the answer each
gets today.

`tests/fixtures/ex015_corpus/<packet>/<kind>__<case>` is the text; `<packet>/expected.json` holds
the decision the engine returns for it on the `file` channel and whether GLS-EX-015 is among the
findings. Other rules are not pinned, so a new pattern that fires on one of these texts does not move
an answer here. `<kind>` is the label the case carried when it was written (`relay` or `ordinary`),
kept in the id. `ordinary` must not carry GLS-EX-015 and its decision must not be `block`, except the
cases named in `OTHER_BLOCKS`, which another rule blocks; `relay` must carry GLS-EX-015, except the
cases listed in `KNOWN_MISS`, which are relays the rule does not find (see
tests/test_ex015_predicate.py). A case that disagrees with its label fails, and `--regen` refuses to
write the expected files while one does.

A change to the EX-015 rule moves some of these answers. Run the file before pushing, read which
cases moved, and when each move is intended regenerate the expected files:

    python3 tests/test_ex015_probe_corpus.py --regen
"""
import json
import os
import sys

import pytest

_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "ex015_corpus")


# relay-labelled cases the rule does not find: a sink inside a longer name, or named before the read
KNOWN_MISS = {("c475r2", "relay__n17.txt"), ("c475r2", "relay__n19.txt"), ("c475r2", "relay__n20.txt"),
              ("c475r2", "relay__n26.txt"), ("c475r2", "relay__v10.txt")}


# ordinary cases that a different rule blocks (the answer pins which decision, the rule id is kept here)
OTHER_BLOCKS = {("c470r3", "ordinary__ssh_setup_public.txt"): "GLS-SC-002"}


def _packets():
    return sorted(d for d in os.listdir(_ROOT) if os.path.isdir(os.path.join(_ROOT, d)))


def _cases(packet):
    return sorted(n for n in os.listdir(os.path.join(_ROOT, packet)) if n != "expected.json")


def _text(packet, case):
    with open(os.path.join(_ROOT, packet, case), encoding="utf-8") as fh:
        return fh.read()


def _answer(engine, text):
    result = engine.scan(text, channel="file")
    return {"decision": result.decision, "ex015": any(f["id"] == "GLS-EX-015" for f in result.findings)}


def _expected(packet):
    with open(os.path.join(_ROOT, packet, "expected.json"), encoding="utf-8") as fh:
        return json.load(fh)


CASES = [(p, c) for p in _packets() for c in _cases(p)]


@pytest.fixture(scope="module")
def engine():
    from sunglasses.engine import SunglassesEngine
    return SunglassesEngine()


@pytest.mark.parametrize("packet", _packets())
def test_every_case_file_has_an_expected_answer_and_the_other_way_round(packet):
    assert sorted(_expected(packet)) == _cases(packet)


@pytest.mark.parametrize("packet,case", CASES, ids=[f"{p}/{c}" for p, c in CASES])
def test_each_probe_text_gets_its_pinned_answer(engine, packet, case):
    assert _answer(engine, _text(packet, case)) == _expected(packet)[case]


def _disagrees(packet, case, answer):
    label = case.split("__")[0]
    if (label == "relay") != answer["ex015"] and (packet, case) not in KNOWN_MISS:
        return True
    return label == "ordinary" and answer["decision"] == "block" and (packet, case) not in OTHER_BLOCKS


@pytest.mark.parametrize("packet,case", CASES, ids=[f"{p}/{c}" for p, c in CASES])
def test_each_probe_text_answers_as_its_label_says(engine, packet, case):
    assert not _disagrees(packet, case, _answer(engine, _text(packet, case)))


@pytest.mark.parametrize("packet,case", sorted(OTHER_BLOCKS))
def test_an_ordinary_case_blocked_by_another_rule_is_blocked_by_that_rule_alone(engine, packet, case):
    result = engine.scan(_text(packet, case), channel="file")
    assert result.decision == "block"
    assert sorted({f["id"] for f in result.findings}) == [OTHER_BLOCKS[(packet, case)]]


@pytest.mark.parametrize("packet,case", sorted(KNOWN_MISS))
def test_a_known_miss_is_a_relay_label_the_rule_does_not_find(engine, packet, case):
    assert case.startswith("relay__")
    assert not _answer(engine, _text(packet, case))["ex015"]


if __name__ == "__main__":
    if sys.argv[1:] != ["--regen"]:
        sys.exit("usage: python3 tests/test_ex015_probe_corpus.py --regen")
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from sunglasses.engine import SunglassesEngine
    eng = SunglassesEngine()
    all_rows = {pk: {c: _answer(eng, _text(pk, c)) for c in _cases(pk)} for pk in _packets()}
    wrong = [f"{pk}/{c}" for pk, rows in all_rows.items() for c, a in rows.items() if _disagrees(pk, c, a)]
    if wrong:
        sys.exit("not written: these answer against their label: " + ", ".join(wrong))
    for pk, rows in all_rows.items():
        with open(os.path.join(_ROOT, pk, "expected.json"), "w", encoding="utf-8") as fh:
            json.dump(rows, fh, indent=1, sort_keys=True)
            fh.write("\n")
        print(pk, len(rows))
