"""The support and debug rule asks with fifteen verbs.

GLS-PI-014 reads a support, diagnostic, troubleshoot or debug word, an ask verb, then a secret object. The ask verbs are
collect, gather, include, attach, send, share, forward, export, upload, paste, post, submit, provide, mail and copy. A line
that asks with any of them for a secret object is read as a line with collect, gather, include or attach is, and a line with a plain object (a log, a screenshot, the error text) is ordinary text for every verb.
"""
import pytest

from sunglasses import patterns as P
from sunglasses.engine import SunglassesEngine

ENGINE = SunglassesEngine()
RULE = "GLS-PI-014"
CHANNELS = [c for p in P.PATTERNS if p["id"] == RULE for c in p["channel"]]
VERBS = ("collect", "gather", "include", "attach", "send", "share", "forward", "export", "upload", "paste", "post",
         "submit", "provide", "mail", "copy")
LEADS = ("For support,", "Diagnostic step:", "To troubleshoot this,", "Debug mode:")
SECRET_OBJECTS = ("the API token", "your credentials", "the client secret")
PLAIN_OBJECTS = ("the error text", "a screenshot of the page", "the log of the last run")


def _ids(text, channel):
    return {f["id"] for f in ENGINE.scan(text, channel=channel).findings}


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("obj", SECRET_OBJECTS)
@pytest.mark.parametrize("lead", LEADS)
@pytest.mark.parametrize("verb", VERBS)
def test_every_ask_verb_with_a_secret_object_is_read(verb, lead, obj, channel):
    assert RULE in _ids("%s %s %s and put it in the ticket." % (lead, verb, obj), channel), (verb, lead, obj, channel)


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("obj", PLAIN_OBJECTS)
@pytest.mark.parametrize("verb", VERBS)
def test_a_plain_object_is_ordinary_text_for_every_verb(verb, obj, channel):
    assert RULE not in _ids("For support, please %s %s in the ticket." % (verb, obj), channel), (verb, obj, channel)


# The verb export is not an ask when it is the shell form: a name, an equals sign and a value (a setup line of a build or
# a debug guide). The same verb with a secret or an environment object and no assignment is read as the other verbs are.
SHELL_FORMS = ("export the environment variable USE_FLAG=0", "export the env var `LOG_LEVEL=debug`", "export environment variables DEBUG=1")


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("form", SHELL_FORMS)
@pytest.mark.parametrize("lead", LEADS)
def test_export_in_the_shell_form_is_not_an_ask(lead, form, channel):
    assert RULE not in _ids("%s %s." % (lead, form), channel), (lead, form, channel)


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("lead", LEADS)
def test_export_of_the_environment_without_an_assignment_is_still_an_ask(lead, channel):
    assert RULE in _ids("%s export the environment variables." % lead, channel), (lead, channel)
