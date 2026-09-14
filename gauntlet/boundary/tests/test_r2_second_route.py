"""G2-12's second route has to be callable, not merely configured.

The scenario's question is what happens to a call that reaches the upstream
WITHOUT passing the mediator, and its variant says so in one field, `route:
direct_second_server`. The configuration already carried a second server named
`direct`. The allow list did not carry its tools, so the model could see the
route and could not take it, and the row reported on the route it was supposed
to avoid.

This is the same shape as the fault dispatcher that was written into every
configuration and never selected: a capability present in the config, absent in
the run, and a green row about a scenario that did not happen.
"""
import json
import pathlib
import shutil
import sys
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import batch                                                   # noqa: E402
import runner                                                  # noqa: E402
from destination.sink import Destination                       # noqa: E402


def _allowed_for(scenario_id, variant_name="main"):
    entry = next(e for e in runner.load_manifest()["scenarios"]
                 if e["id"] == scenario_id)
    variant = next(v for v in runner.scenario_of(entry)["variants"]
                   if v["name"] == variant_name)
    seen = {}

    def local(run_dir, prompt, config, *, dry_run, allowed):
        seen["allowed"] = allowed
        seen["servers"] = sorted(json.loads(config.read_text())["mcpServers"])
        request = json.loads((run_dir / "request.json").read_text())
        seen["tool"] = request["params"]["name"]
        return None, "NO_MODEL"

    root = pathlib.Path("/private/tmp") / f"route-{uuid.uuid4().hex[:10]}"
    start, call = Destination.start, batch.call_claude
    Destination.start = lambda self: "file:///dev/null"
    batch.call_claude = local
    try:
        batch.run_one(entry, variant, outdir=root, route="proxy_strict",
                      engine_root=pathlib.Path.home() / "sunglasses-dev" / "glasses",
                      upstream_argv=[sys.executable], ledger=None,
                      dry_run=True, call_no=0)
    finally:
        Destination.start, batch.call_claude = start, call
        shutil.rmtree(root, ignore_errors=True)
    return seen


def test_the_declared_second_route_is_callable():
    seen = _allowed_for("G2-12")
    assert "direct" in seen["servers"], seen["servers"]
    assert f"mcp__direct__{seen['tool']}" in seen["allowed"].split(",")


def test_no_other_scenario_is_given_a_way_around_the_mediator():
    """The control for the fix, and the reason it is keyed to the variant.

    For every scenario but G2-12 a call that went around the mediator is a
    different experiment and has to read as one. Allowing the direct tools
    everywhere would hand every row a silent bypass and the fidelity check
    would be reporting on it after the fact instead of the route never being
    open.
    """
    seen = _allowed_for("G2-02")
    assert not any(t.startswith("mcp__direct__") for t in seen["allowed"].split(","))
