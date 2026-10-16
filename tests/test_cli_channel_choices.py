"""`scan --channel` offers every channel the engine documents.

The command line carried its own hand-written list of channels. When the
engine documented nine, the command line still offered five, so a user could
not scan a tool result, an agent input, code or a prompt from the shell:
argparse refused the name and exited 2 before any scan ran. The choices now come
from the engine's own tuple, so the two cannot drift apart again.
"""
import subprocess
import sys

import pytest

from sunglasses.engine import SunglassesEngine


def _scan(channel):
    return subprocess.run(
        [sys.executable, "-m", "sunglasses", "scan", "--channel", channel,
         "--text", "hello"],
        capture_output=True, text=True, timeout=120,
    )


@pytest.mark.parametrize("channel", SunglassesEngine.DOCUMENTED_CHANNELS)
def test_every_documented_channel_is_accepted(channel):
    proc = _scan(channel)
    assert proc.returncode == 0, (
        f"--channel {channel} is documented by the engine but the command "
        f"line refused it: {proc.stderr.strip()[-200:]}"
    )


def test_an_unknown_channel_is_still_refused():
    assert _scan("not-a-channel").returncode == 2


def test_the_help_text_lists_every_documented_channel():
    proc = subprocess.run(
        [sys.executable, "-m", "sunglasses", "scan", "--help"],
        capture_output=True, text=True, timeout=120,
    )
    flat = " ".join(proc.stdout.split())
    for channel in SunglassesEngine.DOCUMENTED_CHANNELS:
        assert channel in flat
