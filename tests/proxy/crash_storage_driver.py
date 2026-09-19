"""Inject a real SIGKILL into one phase of an install, including the TEMP write.

ASTRA's `crash_matrix_driver.py` hooks `Path.write_text` and `Path.write_bytes`
keyed on the record filenames. That works while the writes go through `Path`,
and this row deliberately moves them to `os.open`/`os.write`/`os.replace` so a
symlink cannot be followed and a partial record cannot be published. Keeping
the old driver would have left four of the sixteen phases unreachable, and a
phase that cannot fire reports "fault not reached", which reads like a pass and
is not one. So the driver moves with the writer.

It hooks the OS layer instead, and keeps an fd -> path map from `os.open` so
`os.write` still knows WHICH file it is truncating. `os.replace` is keyed on the
DESTINATION, because two different replaces matter here: the config target and
the completed record.

Usage: crash_storage_driver.py <config> <home> <artifact> <phase>
Exits by SIGKILL when the phase is reached; anything else means it was not.
"""
import os
import signal
import sys
from pathlib import Path

from sunglasses import install as inst

config, home, artifact, phase = map(str, sys.argv[1:])

real_open, real_write, real_replace = os.open, os.write, os.replace
real_discard = inst._discard
fds = {}


def kill():
    os.kill(os.getpid(), signal.SIGKILL)


def opened(path, *args, **kwargs):
    fd = real_open(path, *args, **kwargs)
    fds[fd] = os.path.basename(str(path))
    return fd


def written(fd, data, *args, **kwargs):
    name = fds.get(fd)
    # `complete-partial` is keyed on the COMPLETION, not on the temp filename.
    # Keyed on `.focus.json.sg-new` alone it is a hook on the repair rather than
    # on the thing being repaired: the ATOMIC-PUBLISH mutant writes the record
    # straight to `focus.json`, the hook never fires, the driver exits 0, and
    # the control fails on "fault not reached" -- a SETUP failure, which the
    # round-12 classifier correctly refuses to count as a kill. Unmutated,
    # `focus.json` is only ever created by the rename and never written through
    # a descriptor, so naming it here costs nothing and is what makes the mutant
    # die at the same boundary the property is about.
    half = {
        "focus.pending": "pending-partial",
        ".focus.json.sg-new": "complete-partial",
        "focus.json": "complete-partial",
    }.get(name)
    if half is not None and phase == half:
        real_write(fd, data[: len(data) // 2], *args, **kwargs)
        os.fsync(fd)
        kill()
    n = real_write(fd, data, *args, **kwargs)
    full = {
        "focus.original": "retained-full",
        "focus.pending": "pending-full",
    }.get(name)
    if full is not None and phase == full:
        os.fsync(fd)
        kill()
    return n


def replaced(src, dst):
    to = os.path.basename(str(dst))
    if to == "focus.json":
        # The completed record's publication, not the config's.
        r = real_replace(src, dst)
        if phase == "complete-full":
            kill()
        return r
    if phase == "before-replace":
        kill()
    r = real_replace(src, dst)
    if phase == "after-replace":
        kill()
    return r


def discarded(*paths):
    r = real_discard(*paths)
    if phase == "after-cleanup" and any(str(x).endswith(".pending") for x in paths):
        kill()
    return r


os.open, os.write, os.replace = opened, written, replaced
inst._discard = discarded
inst.install(config, "focus", home=Path(home), artifact=Path(artifact))
