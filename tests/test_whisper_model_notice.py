"""The Whisper speech model is announced on stderr before a missing model is fetched.

Whisper is replaced by a stand-in that keeps the real module's shape: a table of
model URLs, a `_download(url, root, in_memory)` that fetches only when the file is
missing from the cache folder, and a `load_model(name)` that looks `_download` up
on the module when it runs. Nothing here reaches the network.
"""

import sys
import threading
import types

import pytest

from sunglasses.extractors import _whisper_model
from sunglasses.extractors._whisper_model import load_whisper_model
from sunglasses.extractors.audio import AudioExtractor
from sunglasses.extractors.video import VideoExtractor

HOST = "models.example.test"
URLS = {
    "base": f"https://{HOST}/main/whisper/models/abc123/base.pt",
    "small": f"https://{HOST}/main/whisper/models/def456/small.pt",
}


class _Stream:
    """A stderr stand-in that writes into the same event list as the downloads."""

    def __init__(self, events):
        self.events = events

    def write(self, text):
        self.events.append(("notice", text))
        return len(text)

    def flush(self):
        pass


@pytest.fixture
def events():
    return []


@pytest.fixture
def fake_whisper(tmp_path, monkeypatch, events):
    mod = types.ModuleType("whisper")
    mod._MODELS = dict(URLS)
    mod.cache = tmp_path

    def _download(url, root, in_memory):
        assert root == str(tmp_path)
        target = tmp_path / url.rsplit("/", 1)[-1]
        if not target.is_file():
            events.append(("download", url))
            target.write_bytes(b"model")
        return str(target)

    def load_model(name, download_root=None, in_memory=False):
        # The real load_model looks `_download` up on the module when it runs.
        mod._download(mod._MODELS[name], str(tmp_path), in_memory)
        return ("model", name)

    mod._download = _download
    mod.load_model = load_model
    monkeypatch.setitem(sys.modules, "whisper", mod)
    return mod


class _LockSpy:
    """Wraps the module lock and reports when the named thread reaches it."""

    def __init__(self, inner, thread_name, reached):
        self.inner = inner
        self.thread_name = thread_name
        self.reached = reached

    def __enter__(self):
        if threading.current_thread().name == self.thread_name:
            self.reached.set()
        return self.inner.__enter__()

    def __exit__(self, *exc):
        return self.inner.__exit__(*exc)


def watch(monkeypatch, events):
    """Route stderr into `events`. Pytest swaps sys.stderr again when the test body
    starts, so this runs inside the test, not in a fixture."""
    monkeypatch.setattr(sys, "stderr", _Stream(events))


def private_state(monkeypatch):
    """Give one test a lock and a load record of its own.

    A test that runs a nested load in a worker thread can leave that thread stuck if the lock
    regresses. On the module's real state it would also leave `_loading` half set for every
    test that follows, so the failure would show up in the wrong tests."""
    monkeypatch.setattr(_whisper_model, "_LOCK", type(_whisper_model._LOCK)())
    monkeypatch.setattr(_whisper_model, "_loading", {"name": None, "original": None})


def _notices(events):
    return [text for kind, text in events if kind == "notice"]


def _downloads(events):
    return [url for kind, url in events if kind == "download"]


def test_a_missing_model_is_announced_before_its_download_starts(fake_whisper, events, monkeypatch):
    watch(monkeypatch, events)
    assert load_whisper_model("base") == ("model", "base")
    assert [kind for kind, _ in events if kind in ("notice", "download")][:2] == ["notice", "download"]
    assert _notices(events) == [f"fetching whisper model base from {HOST}\n"]
    assert _downloads(events) == [URLS["base"]]


def test_a_model_already_in_the_cache_loads_without_a_notice_or_a_download(
        fake_whisper, events, capsys, monkeypatch):
    watch(monkeypatch, events)
    (fake_whisper.cache / "base.pt").write_bytes(b"model")
    assert load_whisper_model("base") == ("model", "base")
    assert events == []
    assert capsys.readouterr().out == ""


def test_the_load_after_a_successful_download_is_silent(fake_whisper, events, monkeypatch):
    watch(monkeypatch, events)
    load_whisper_model("base")
    del events[:]
    load_whisper_model("base")
    assert events == []


def test_whisper_is_left_as_it_was_found(fake_whisper):
    original = fake_whisper._download
    load_whisper_model("base")
    assert fake_whisper._download is original


@pytest.mark.parametrize("failure", [RuntimeError("disk full"), KeyboardInterrupt()])
def test_whisper_is_left_as_it_was_found_when_the_load_stops(fake_whisper, failure):
    original = fake_whisper._download

    def failing(name, download_root=None, in_memory=False):
        raise failure

    fake_whisper.load_model = failing
    with pytest.raises(type(failure)):
        load_whisper_model("base")
    assert fake_whisper._download is original
    fake_whisper.load_model = lambda name, **kw: ("model", name)
    assert load_whisper_model("base") == ("model", "base")


@pytest.mark.parametrize("first,second", [("base", "base"), ("base", "small")])
def test_overlapping_loads_leave_whisper_as_they_found_it(fake_whisper, events, first, second, monkeypatch):
    watch(monkeypatch, events)
    original = fake_whisper._download
    inside = threading.Event()
    release = threading.Event()
    first_done = threading.Event()
    real_load = fake_whisper.load_model

    def slow_load(name, **kw):
        if name == first and not inside.is_set():
            inside.set()
            assert release.wait(5)
        elif name == second and second != first:
            # The second model may only reach its download once the first load
            # has finished and put Whisper back.
            assert first_done.wait(5)
        return real_load(name, **kw)

    fake_whisper.load_model = slow_load
    results = {}
    reached = threading.Event()
    monkeypatch.setattr(_whisper_model, "_LOCK", _LockSpy(_whisper_model._LOCK, "two", reached))

    def run(key, name):
        results[key] = load_whisper_model(name)

    one = threading.Thread(target=run, args=("one", first), daemon=True)
    two = threading.Thread(target=run, args=("two", second), name="two", daemon=True)
    try:
        one.start()
        assert inside.wait(5)
        two.start()
        assert reached.wait(5)
        release.set()
        one.join(5)
        first_done.set()
        two.join(5)
    finally:
        release.set()
        first_done.set()
        for worker in (one, two):
            if worker.is_alive():
                worker.join(5)

    assert not one.is_alive() and not two.is_alive()
    assert results == {"one": ("model", first), "two": ("model", second)}
    assert fake_whisper._download is original
    expected = sorted({first, second})
    assert sorted(_notices(events)) == sorted(
        f"fetching whisper model {n} from {HOST}\n" for n in expected)


def test_a_load_inside_a_load_does_not_wait_on_itself(fake_whisper, events, monkeypatch):
    watch(monkeypatch, events)
    # A load that waited on itself would hold the module's lock for good, so
    # this test runs on a lock and a load record of its own and leaves the real ones free.
    private_state(monkeypatch)
    original = fake_whisper._download
    real_load = fake_whisper.load_model

    def nested(name, **kw):
        if name == "base":
            load_whisper_model("small")
        return real_load(name, **kw)

    fake_whisper.load_model = nested
    done = []
    worker = threading.Thread(target=lambda: done.append(load_whisper_model("base")), daemon=True)
    worker.start()
    worker.join(5)
    assert done == [("model", "base")]
    assert fake_whisper._download is original
    assert sorted(_notices(events)) == [
        f"fetching whisper model base from {HOST}\n",
        f"fetching whisper model small from {HOST}\n"]


def test_a_missing_stderr_loads_the_model_and_prints_nothing_on_stdout(
        fake_whisper, events, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stderr", None)
    assert load_whisper_model("base") == ("model", "base")
    assert capsys.readouterr().out == ""
    assert _downloads(events) == [URLS["base"]]


def test_a_stderr_that_cannot_be_written_still_loads_the_model(fake_whisper, events, monkeypatch):
    class Broken:
        def write(self, text):
            raise OSError("closed pipe")

        def flush(self):
            raise OSError("closed pipe")

    monkeypatch.setattr(sys, "stderr", Broken())
    assert load_whisper_model("base") == ("model", "base")
    assert _downloads(events) == [URLS["base"]]


def _record_load(fake_whisper, events):
    """Replace load_model so the event list shows whether the notice came before the load."""
    def load_model(name, **kw):
        events.append(("load", name))
        return ("model", name)
    fake_whisper.load_model = load_model


def test_a_whisper_without_the_download_hook_says_so_before_it_loads(fake_whisper, events, monkeypatch):
    watch(monkeypatch, events)
    del fake_whisper._download
    _record_load(fake_whisper, events)
    assert load_whisper_model("base") == ("model", "base")
    assert [kind for kind, _ in events] == ["notice", "load"]
    assert _notices(events) == ["loading whisper model base; Whisper may download it first if it is not already cached\n"]


def test_a_whisper_without_the_model_table_says_so_before_it_loads(fake_whisper, events, monkeypatch):
    watch(monkeypatch, events)
    del fake_whisper._MODELS
    _record_load(fake_whisper, events)
    assert load_whisper_model("small") == ("model", "small")
    assert [kind for kind, _ in events] == ["notice", "load"]
    assert "small" in _notices(events)[0]


def test_a_whisper_with_a_renamed_download_hook_says_so_even_for_a_cached_model(fake_whisper, events, monkeypatch):
    """The helper cannot see the cache then, so it tries to say so before each load rather than guess."""
    watch(monkeypatch, events)
    fake_whisper._fetch_model = fake_whisper._download
    del fake_whisper._download
    (fake_whisper.cache / "base.pt").write_bytes(b"model")
    _record_load(fake_whisper, events)
    load_whisper_model("base")
    load_whisper_model("base")
    assert len(_notices(events)) == 2


def test_a_whisper_without_the_hook_still_says_so_for_a_model_file_on_disk(
        fake_whisper, events, tmp_path, monkeypatch):
    """The helper cannot tell a file load from a download, so the line is not skipped."""
    watch(monkeypatch, events)
    del fake_whisper._download
    del fake_whisper._MODELS
    mine = tmp_path / "mine.pt"
    mine.write_bytes(b"model")
    _record_load(fake_whisper, events)
    assert load_whisper_model(str(mine)) == ("model", str(mine))
    assert [kind for kind, _ in events] == ["notice", "load"]


def test_a_whisper_without_the_hook_says_so_for_a_registered_name_that_is_also_a_file(
        fake_whisper, events, tmp_path, monkeypatch):
    """A loader may take the registered name before the file, so a same-named file is no reason to stay quiet."""
    watch(monkeypatch, events)
    del fake_whisper._download
    monkeypatch.chdir(tmp_path)
    (tmp_path / "base").write_bytes(b"not the registered weights")
    _record_load(fake_whisper, events)
    assert load_whisper_model("base") == ("model", "base")
    assert [kind for kind, _ in events] == ["notice", "load"]


def test_a_whisper_without_the_hook_passes_an_unhashable_name_on_unchanged(fake_whisper, events, monkeypatch):
    watch(monkeypatch, events)
    del fake_whisper._download
    fake_whisper.load_model = lambda name, **kw: ("model", name)
    assert load_whisper_model(["base"]) == ("model", ["base"])


def test_the_fallback_notice_does_not_stop_a_load_when_stderr_is_missing(fake_whisper, events, monkeypatch):
    monkeypatch.setattr(sys, "stderr", None)
    del fake_whisper._download
    _record_load(fake_whisper, events)
    assert load_whisper_model("base") == ("model", "base")
    assert events == [("load", "base")]


def test_a_model_name_that_is_a_file_path_loads_as_before(fake_whisper, events, monkeypatch):
    watch(monkeypatch, events)
    fake_whisper.load_model = lambda name, **kw: ("model", name)
    assert load_whisper_model("/models/mine.pt") == ("model", "/models/mine.pt")
    assert events == []


@pytest.mark.parametrize("extractor", [AudioExtractor, VideoExtractor])
def test_audio_and_video_load_through_the_announcing_loader(
        extractor, fake_whisper, events, monkeypatch):
    watch(monkeypatch, events)
    monkeypatch.setattr("sunglasses.extractors.audio._check_deps", lambda: None)
    monkeypatch.setattr("sunglasses.extractors.video._check_deps", lambda: None)
    assert extractor()._get_model() == ("model", "base")
    assert _notices(events) == [f"fetching whisper model base from {HOST}\n"]

    assert extractor()._get_model() == ("model", "base")
    assert len(_notices(events)) == 1
    assert _downloads(events) == [URLS["base"]]


def test_a_failed_checksum_after_the_notice_stops_the_load_and_restores_whisper(
        fake_whisper, events, monkeypatch):
    watch(monkeypatch, events)
    original = fake_whisper._download

    def bad_download(url, root, in_memory):
        original(url, root, in_memory)
        raise RuntimeError("model has been downloaded but the SHA256 checksum does not match")

    fake_whisper._download = bad_download
    with pytest.raises(RuntimeError, match="checksum"):
        load_whisper_model("base")
    assert _notices(events) == [f"fetching whisper model base from {HOST}\n"]
    assert fake_whisper._download is bad_download
    assert _whisper_model._loading == {"name": None, "original": None}


def test_a_cached_file_that_is_replaced_by_whisper_is_not_announced(fake_whisper, events, monkeypatch):
    watch(monkeypatch, events)
    cached = fake_whisper.cache / "base.pt"
    cached.write_bytes(b"damaged")
    real_download = fake_whisper._download

    def redownload(url, root, in_memory):
        # Whisper's own checksum check discards a damaged file and fetches it again.
        cached.unlink()
        return real_download(url, root, in_memory)

    fake_whisper._download = redownload
    assert load_whisper_model("base") == ("model", "base")
    assert _downloads(events) == [URLS["base"]]
    assert _notices(events) == []


def test_a_closed_stderr_still_loads_the_model_and_writes_nothing_elsewhere(
        fake_whisper, events, monkeypatch, capsys):
    import io

    stream = io.StringIO()
    stream.close()
    monkeypatch.setattr(sys, "stderr", stream)
    assert load_whisper_model("base") == ("model", "base")
    assert _downloads(events) == [URLS["base"]]
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("assigned,failure", [
    (False, AttributeError("read-only for this test")),
    (True, KeyboardInterrupt()),
], ids=["refused", "interrupted-after-assignment"])
def test_the_load_state_is_idle_again_when_the_hook_installation_stops(
        fake_whisper, events, monkeypatch, assigned, failure):
    watch(monkeypatch, events)
    original = fake_whisper._download
    stopped = []

    class Strict(types.ModuleType):
        def __setattr__(self, key, value):
            if key == "_download" and not stopped:
                stopped.append(value)
                if assigned:
                    super().__setattr__(key, value)
                raise failure
            super().__setattr__(key, value)

    strict = Strict("whisper")
    strict.__dict__.update(fake_whisper.__dict__)

    def load_model(name, **kw):
        strict._download(strict._MODELS[name], str(fake_whisper.cache), False)
        return ("model", name)

    strict.load_model = load_model
    monkeypatch.setitem(sys.modules, "whisper", strict)
    with pytest.raises(type(failure)):
        load_whisper_model("base")
    assert strict._download is original
    assert _whisper_model._loading == {"name": None, "original": None}
    assert load_whisper_model("base") == ("model", "base")
    assert _notices(events) == [f"fetching whisper model base from {HOST}\n"]


def test_the_outer_model_is_named_again_once_a_nested_load_ends(fake_whisper, events, monkeypatch):
    watch(monkeypatch, events)
    # Runs on a lock and a load record of its own, in a daemon worker, so a regression in
    # the lock fails here instead of holding up or polluting the rest of the run.
    private_state(monkeypatch)
    real_load = fake_whisper.load_model

    def nested(name, **kw):
        if name == "base":
            load_whisper_model("small")
        return real_load(name, **kw)

    fake_whisper.load_model = nested
    done = []
    worker = threading.Thread(target=lambda: done.append(load_whisper_model("base")), daemon=True)
    worker.start()
    worker.join(5)
    assert done == [("model", "base")]
    assert _notices(events) == [
        f"fetching whisper model small from {HOST}\n",
        f"fetching whisper model base from {HOST}\n"]
    assert _whisper_model._loading == {"name": None, "original": None}


def test_a_direct_whisper_load_during_a_helper_load_is_announced_under_the_helper_models_name(
        fake_whisper, events, monkeypatch):
    watch(monkeypatch, events)
    real_load = fake_whisper.load_model

    def with_direct_call(name, **kw):
        if name == "base":
            real_load("small")
        return real_load(name, **kw)

    fake_whisper.load_model = with_direct_call
    assert load_whisper_model("base") == ("model", "base")
    assert _downloads(events) == [URLS["small"], URLS["base"]]
    assert _notices(events) == [f"fetching whisper model base from {HOST}\n"] * 2
