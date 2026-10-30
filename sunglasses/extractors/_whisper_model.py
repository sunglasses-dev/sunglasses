"""Load the Whisper speech model, and try to say so before a missing model is fetched.

`whisper.load_model` downloads the model file when it is not in Whisper's cache
folder. The scanner runs on your machine, so a notice is attempted (best effort, on
stderr) before the download starts. When the helper can see both the download
function and the model table, and the name is in that table, a cached file that
fails Whisper's own checksum is downloaded again by Whisper without a notice;
when either of them is not usable, the notice is tried on every load.

The announcement is made by standing in for `whisper._download` while a model
loads. That is a process-wide change, so loads through this helper run one at a
time, and the original function is put back when the outermost helper load ends.
Those rules cover loads made through this helper. Code that calls
`whisper.load_model` directly is not coordinated with it: while a helper load is
in progress such a call uses the same stand-in, and its notice carries the helper
load's model name.

When the installed Whisper does not expose the `_download` function or the `_MODELS`
table this helper stands in for, it cannot see whether the model file is cached. It
then tries to print one line on stderr before each load, saying that Whisper may
download the model first. That line is not suppressed for a name that is also a
file on disk, because the helper cannot tell which of the two Whisper will use.
A name that is not in the table is passed to Whisper unchanged, with no line
printed, only when both the download function and the table are usable.

A missing stderr, or an OSError or ValueError while the notice is written, does
not stop the load. The notice is not written anywhere else; there is no stdout
fallback.
"""

import os
import sys
import threading
from urllib.parse import urlparse

_LOCK = threading.RLock()
_loading = {"name": None, "original": None}


def _say(text):
    """Write one line to stderr.

    A missing stderr, or an OSError or ValueError while writing, never stops a load.
    """
    stream = sys.stderr
    if stream is None:
        return
    try:
        stream.write(text + "\n")
        stream.flush()
    except (OSError, ValueError):
        pass


def _announcing_fetch(url, root, *args, **kwargs):
    # `root` is the cache folder Whisper chose, so the check follows whatever
    # location it uses and reads no environment variable here.
    if not os.path.isfile(os.path.join(root, os.path.basename(url))):
        _say(f"fetching whisper model {_loading['name']} from {urlparse(url).netloc}")
    return _loading["original"](url, root, *args, **kwargs)


def load_whisper_model(name):
    """Return `whisper.load_model(name)`, trying to print a notice before a missing model is downloaded."""
    import whisper

    with _LOCK:
        fetch = getattr(whisper, "_download", None)
        urls = getattr(whisper, "_MODELS", None)
        if not callable(fetch) or not isinstance(urls, dict):
            _say(f"loading whisper model {name}; Whisper may download it first if it is not already cached")
            return whisper.load_model(name)
        if name not in urls:
            return whisper.load_model(name)

        outer = dict(_loading)
        installing = fetch is not _announcing_fetch
        try:
            if installing:
                _loading["original"] = fetch
                whisper._download = _announcing_fetch
            _loading["name"] = name
            return whisper.load_model(name)
        finally:
            if installing:
                whisper._download = fetch
            _loading.update(outer)
