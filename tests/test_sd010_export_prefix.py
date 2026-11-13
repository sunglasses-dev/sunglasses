"""GLS-SD-010 reads an assignment at the start of a line, and a shell line may start with `export`.

`export NAME=value` is the form a shell profile, an install guide and a CI step use to put a secret
in the environment. The rule reads it like the bare `NAME=value` line, on the channels the rule
covers. What stays as it was: a name that continues past the listed word, a line that starts with
anything else, and the channels the rule does not list.
"""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from sunglasses.engine import SunglassesEngine   # noqa: E402
from sunglasses.patterns import PATTERNS          # noqa: E402

RULE = "GLS-SD-010"
VALUE = "placeholder_value_1234"
NAMES = ["API_KEY", "SECRET_KEY", "ACCESS_KEY", "TOKEN", "PASSWORD", "DATABASE_URL",
         "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AWS_SECRET_ACCESS_KEY"]


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


def found(engine, text, channel="file"):
    return RULE in [f["id"] if isinstance(f, dict) else f.id for f in engine.scan(text, channel=channel).findings]


@pytest.mark.parametrize("name", NAMES)
def test_an_export_line_is_read_like_the_bare_line(engine, name):
    assert found(engine, f"{name}={VALUE}")
    assert found(engine, f"export {name}={VALUE}")


@pytest.mark.parametrize("channel", ["message", "file", "code"])
def test_an_export_line_is_read_on_each_channel_of_the_rule(engine, channel):
    assert found(engine, f"export API_KEY={VALUE}", channel)


@pytest.mark.parametrize("text", [
    f"export\tAPI_KEY={VALUE}",
    f"export   API_KEY={VALUE}",
    f"export API_KEY = {VALUE}",
    f"# profile\nexport PASSWORD={VALUE}\nexport EDITOR=vim",
    f"echo start\nexport DATABASE_URL={VALUE}",
])
def test_the_spacing_around_the_export_is_free(engine, text):
    assert found(engine, text)


@pytest.mark.parametrize("text", [
    f"  export API_KEY={VALUE}",
    f"exports API_KEY={VALUE}",
    f"xexport API_KEY={VALUE}",
    f"export API_KEY_NAME is read from the vault",
    f"export EDITOR={VALUE}",
    f"# export API_KEY={VALUE}",
    f"Do not do this: export API_KEY={VALUE}",
    f"set API_KEY={VALUE}",
    f"export\nAPI_KEY_FILE={VALUE}",
])
def test_a_line_with_other_text_in_front_is_read_as_it_was_before(engine, text):
    assert not found(engine, text)


def test_the_channels_of_the_rule_are_unchanged():
    rule = next(p for p in PATTERNS if p["id"] == RULE)
    assert sorted(rule["channel"]) == ["code", "file", "message"]
