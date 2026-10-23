"""Load the Whisper speech model, and say so before a missing model is fetched.

`whisper.load_model` downloads the model file when it is not in Whisper's cache
folder. The scanner runs on your machine, so that download is announced on stderr
before it starts. The notice covers a model file that is missing; a cached file
that fails Whisper's own checksum is downloaded again by Whisper without it.

The announcement is made by standing in for `whisper._download` while a model
loads. That is a process-wide change, so loads through this helper run one at a
time, and the original function is put back when the outermost helper load ends.
Those guarantees cover loads made through this helper. Code that calls
`whisper.load_model` directly is not coordinated with it: while a helper load is
in progress such a call uses the same stand-in, and its notice carries the helper
load's model name.

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
    """Return `whisper.load_model(name)`, announcing a download of a missing model."""
    import whisper

    with _LOCK:
        fetch = getattr(whisper, "_download", None)
        urls = getattr(whisper, "_MODELS", None)
        if not callable(fetch) or not isinstance(urls, dict) or name not in urls:
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
