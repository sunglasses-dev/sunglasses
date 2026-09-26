"""One failing row must not fail its neighbours.

`run_one` binds a Destination on the declared port 18762 and stops it near the
end. Between the two there is no `try/finally`, so when `call_claude` raises —
which is exactly what a native direct-route test does when its node child dies
— the listener is never released and lives until the process exits.

Measured 2026-09-22 inside ONE pytest process: after
`test_r1_configured_direct_route_produces_own_capture` fails, binding 18762
gives `[Errno 48] Address already in use`. The next sink then falls back to an
ephemeral port, which is allowed and documented, and every
`endpoint_as_declared` assertion downstream goes false.

Cost: THREE failing tests became SEVEN. Deselecting the three took the suite
from 11 failed to 4.

(My first check of this looked from a SEPARATE process after pytest had exited,
where an in-process listener is always released. It reported "not a leak" and
was worthless. The probe has to run inside the same interpreter.)
"""
import pathlib
import socket
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import batch                                                   # noqa: E402


def _declared_port_is_free():
    probe = socket.socket()
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind(("127.0.0.1", 18762))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def test_a_raising_call_releases_the_declared_observer(tmp_path, monkeypatch):
    """The row that would have caught it, and the reason it is worth a row.

    A leaked listener is invisible to the test that leaks it — that one already
    failed for its own reason — and it only ever shows up as an unrelated
    neighbour asserting the wrong port.
    """
    assert _declared_port_is_free(), (
        "18762 was already held before this test; something earlier leaked it "
        "and this row cannot measure anything")

    class Boom(RuntimeError):
        pass

    def explode(*args, **kwargs):
        raise Boom("the native child died, as it does when its config is stale")

    monkeypatch.setattr(batch, "call_claude", explode)

    # A FIRST GENERATION SEED, because `run_one` materialises through the
    # scenario's own `run.py` and the gen2 seeds do not go down that path.
    import runner
    entry = next(e for e in runner.load_manifest()["scenarios"]
                 if e["id"] == "G2-08")
    variant = next(v for v in runner.scenario_of(entry)["variants"]
                   if v["name"] == "result")

    from destination.sink import Destination
    monkeypatch.setattr(Destination, "collect_drops", lambda self: None)

    with pytest.raises(Boom):
        batch.run_one(entry, variant, outdir=pathlib.Path("/private/tmp") /
                      f"leakprobe-{tmp_path.name}", route="proxy_strict",
                      engine_root=HERE.parents[2],
                      upstream_argv=[sys.executable], ledger=None,
                      dry_run=True, call_no=0)

    assert _declared_port_is_free(), (
        "run_one raised and left its observer bound to 18762. One failing row "
        "then fails every neighbour that asserts endpoint_as_declared.")
