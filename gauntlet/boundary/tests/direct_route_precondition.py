"""The frozen direct-route config, and whether anything can still run it.

Three tests drive a NATIVE upstream from a config frozen into the delivery at
`ARCHIVE/evidence/GATE2_RUN_2026-09-13/live4/G2-04.main.control/mcp.control.json`.
That config names an absolute entrypoint inside ANOTHER SESSION'S scratchpad:

    /private/tmp/claude-501/-Users-azrollin/78494234-.../scratchpad/g2batch1/
        upstream/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js

The session ended weeks ago and the tree was reaped. The node child dies with
MODULE_NOT_FOUND, writes that to `native.stderr`, and the test then waits ten
seconds for a reply that cannot come.

REFUSED BY NAME rather than run, which is the same answer this harness gives
`hook_stdout` and `release_scheduler`: a scenario whose component does not
exist is not a failing scenario, it is one nobody can run. Running it anyway
cost more than the three rows — until the observer leak was fixed, each of
these took four neighbours down with it.

The delivery is NOT edited. Nothing here rewrites the frozen config, and no
network install is performed off a peer's ruling. Re-enabling this is a pinned,
gitignored, per-checkout install of `@modelcontextprotocol/server-filesystem`,
which is its own row.

COVERAGE LOSS, stated so it is not discovered later as a silence: G2-12 has no
executed native direct-route evidence while this holds, and
`capability_map.json` records it.
"""
import json
import pathlib

import pytest

CONFIG_RELATIVE = ("evidence/GATE2_RUN_2026-09-13/live4/"
                   "G2-04.main.control/mcp.control.json")


def entrypoint_of(archive: pathlib.Path) -> pathlib.Path | None:
    """The node entrypoint the frozen config names, or None if unreadable."""
    config = archive / CONFIG_RELATIVE
    try:
        server = json.loads(config.read_text())["mcpServers"]["fs"]
    except (OSError, ValueError, KeyError):
        return None
    args = server.get("args") or []
    return pathlib.Path(args[0]) if args else None


def refuse_unless_runnable(archive: pathlib.Path) -> pathlib.Path:
    """The entrypoint, or a refusal naming exactly what is missing.

    Checked BEFORE the ten second wait, so a reaped tree costs nothing.
    """
    entrypoint = entrypoint_of(archive)
    if entrypoint is None:
        pytest.skip(
            "REFUSED BY NAME: the frozen direct-route config at "
            f"{archive / CONFIG_RELATIVE} is missing or unreadable, so there "
            "is no native upstream to drive.")
    if not entrypoint.is_file():
        pytest.skip(
            "REFUSED BY NAME: the frozen config targets a reaped scratchpad. "
            f"Its entrypoint {entrypoint} does not exist, and no durable "
            "install of @modelcontextprotocol/server-filesystem exists on this "
            "machine. The node child would die MODULE_NOT_FOUND and the test "
            "would wait ten seconds for a reply that cannot come. Re-enabling "
            "this is a pinned per-checkout install, not a skip to be removed.")
    return entrypoint
