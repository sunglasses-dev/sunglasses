"""R28. The scanner engine is built BEFORE the first frame is accepted.

`default_engine()` is one engine per process, built on first use. First use was
the activation scan of the server's first tools/list page, which runs inside
`snapshot.collect`'s list deadline. Building the pattern set is ~9.5 s of CPU on
a developer Mac, so on a busy machine the cold build alone ran the list past its
10000 ms deadline: the activation was refused as incomplete, nothing was
captured, and the operator had no snapshot to approve.

The ruling is to warm before the clock, not to move the clock. So the property
tested is an ORDER, never a duration: when the client reader first reads,
the engine already exists. No timing assertion, so no load-dependent result.
"""
import io
import sys
import threading

import sunglasses.engine as engine_module
from sunglasses.proxy import activation, inspection, serve


class _Engine:
    """Stands in for the pattern set, so the test builds nothing expensive."""


class _ClientThatRecordsTheEngine:
    """A client stdin that notes, at its FIRST read, whether the engine was
    already built, then ends the session with EOF."""

    def __init__(self):
        self.engine_at_first_read = "never read"

    def read1(self, _size):
        if self.engine_at_first_read == "never read":
            self.engine_at_first_read = inspection._engine
        return b""

    read = read1


def _cold(monkeypatch):
    monkeypatch.setattr(inspection, "_engine", None)
    monkeypatch.setattr(engine_module, "SunglassesEngine", _Engine)


def test_the_engine_is_built_before_the_first_client_read(monkeypatch, tmp_path):
    _cold(monkeypatch)
    # `main` sets the module's `_FINISHED` on its way out, and while it is set
    # `exit_process` leaves with `os._exit`: a later in-process test that calls
    # it would take the whole runner down with a clean exit and no summary.
    # This run gets its own event; the module's stays clear.
    monkeypatch.setattr(serve, "_FINISHED", threading.Event())
    client = _ClientThatRecordsTheEngine()
    serve.main(["--state-root", str(tmp_path / "state"), "--",
                sys.executable, "-c", "import sys; sys.stdin.buffer.read()"],
               stdin=client, stdout=io.BytesIO(), stderr=io.StringIO())
    assert client.engine_at_first_read != "never read", \
        "the client reader never ran, so the order was not observed"
    assert isinstance(client.engine_at_first_read, _Engine), \
        "the first client frame could be read before the engine existed"


def test_activation_builds_the_engine_before_its_first_page(monkeypatch):
    """The belt: a caller that reaches activation without `serve.main` still
    does not put the cold build inside the list deadline."""
    _cold(monkeypatch)
    seen = []

    def list_pages(_cursor):
        seen.append(inspection._engine)
        return None  # not a page: the collector stops, incomplete

    activation.activate(_Store(), list_pages=list_pages,
                        scan=lambda _page: {}, server_identity="s")
    assert seen and isinstance(seen[0], _Engine), seen


class _Store:
    revision = 0
    epoch = 0
