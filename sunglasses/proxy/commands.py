"""The commands the proxy lane ships.

Written against `tests/test_proxy_commands.py`, committed first.

R-DOCTOR-OWNER (T9, 2026-09-15): `doctor`, `install` and `uninstall` are NOT
here. They were, backed by a second install/uninstall/classify implementation
in this lane's own doctor.py, and `sunglasses/install.py` is the one that has
been through the property controls and the mutation round. Two classify()
functions on main is how the doctor and the install command come to disagree
about what WRAPPED means. What remains is the mediator form and `approve`,
which is T5.R1's door and reads approvals.py, not the doctor.

The dispatch has one rule that is not obvious and matters. A first token that
is neither a known command nor `--` is a USAGE ERROR. It is never treated as a
server command, because doing that executes whatever the user mistyped, with
whatever followed it, as a child process. `docter` should print usage, not run
a program called docter.

Printing is where T10.R3's last sentence finally bites, too. Every other module
merely carried the route checks; this one renders them, so the allowlist that
kept upstream text out of the data has to survive contact with a formatter.
"""
from __future__ import annotations

import sys

USAGE = """usage:
  python -m sunglasses.proxy -- <server command> [args...]   run the mediator
  python -m sunglasses.proxy approve <server-id> --snapshot SHA [--state-root PATH]
"""

EXIT_OK = 0
EXIT_FAULT = 1
EXIT_USAGE = 2

COMMANDS = ("approve",)
SEPARATOR = "--"


def main(argv=None, *, stdout=None, stderr=None, serve=None, confirm=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    stdout = stdout if stdout is not None else sys.stdout
    stderr = stderr if stderr is not None else sys.stderr

    if not argv:
        return _usage(stderr)
    head = argv[0]
    if head not in COMMANDS:
        # The mediator form, which may carry our own options BEFORE the
        # separator: `--state-root PATH -- npx server`. So the test is whether
        # a separator is present anywhere, not whether it is first.
        #
        # And with no separator at all this is a usage error, never a server.
        # Running it would execute a mistyped command name as a child process
        # with whatever arguments followed it.
        if SEPARATOR not in argv:
            return _usage(stderr)
        from .serve import main as serve_main
        return (serve or serve_main)(argv)

    options, rest = _options(argv[1:])
    if not rest:
        return _usage(stderr)
    return _approve(rest[0], options, stdout, stderr, confirm=confirm)


def _usage(stderr):
    stderr.write(USAGE)
    return EXIT_USAGE


def _options(argv):
    """Flags, positionals, and everything after `--` kept separate.

    The wrapper argv is not parsed. It belongs to the command being wrapped and
    reinterpreting its flags as ours is how a server's own `--config` would end
    up pointing this tool somewhere.
    """
    options, positional, wrapped = {}, [], None
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == SEPARATOR:
            wrapped = argv[index + 1:]
            break
        if token in ("--config", "--state-root", "--snapshot") and index + 1 < len(argv):
            options[token[2:]] = argv[index + 1]
            index += 2
            continue
        positional.append(token)
        index += 1
    options["wrapped"] = wrapped
    return options, positional



def _approve(server_id, options, stdout, stderr, *, confirm=None):
    """T5.R1's door, and the only one. Nothing on the serving path may write an
    approval record; this is what does, after a human has seen the capture.

    The command existed only in the contract and in `approvals.py`'s own
    refusal message, which named a command the package did not ship. A gate
    nobody can open is a gate that gets worked around.

    Three refusals, and none of them is exit 2, because none of them is a
    mistyped command line:

      the capture named does not exist -- there is nothing a human could have
      looked at, so there is nothing to record;

      this is not an interactive terminal -- `viewed` records that a PERSON
      looked, and a pipe cannot look. Approving here would write the record on
      their behalf, which is exactly what T5.R1 forbids and what
      `write_without_human` refuses in the library;

      the person said no.
    """
    import json
    import pathlib

    from . import approvals
    from .serve import state_root

    snapshot = options.get("snapshot")
    if not snapshot:
        return _usage(stderr)
    # THE DEFAULT IS THE PROXY'S OWN ROOT, not the working directory.
    #
    # Until 2026-09-19 this read `or "."`, so `approve` looked for the capture
    # under whatever directory the user happened to be standing in while the
    # proxy had written it to `state_root()`. The command then refused with "no
    # stored capture" — correctly, about a directory nobody had written to — and
    # there was no way for a reader to discover the difference. Measured: the
    # same command exits 1 from anywhere else and 0 with `--state-root` pointed
    # at the proxy's root.
    #
    # `--state-root` stays the explicit override, and `state_root()` stays an
    # ARGUMENT rather than an environment variable for the reason its own
    # docstring gives: a variable that moves the approval store is a switch
    # anything in the process tree could flip.
    root = (pathlib.Path(options["state-root"]) if options.get("state-root")
            else state_root())
    store = approvals.Store(root, server_id=server_id)
    capture = store.captures / f"{server_id}.{snapshot}.json"
    if not capture.exists():
        stderr.write(
            f"no stored capture {snapshot[:12]} for {server_id}; the sha "
            f"approved must be the sha that was shown\n")
        return EXIT_FAULT

    stored = json.loads(capture.read_text())
    tools = stored.get("tools_by_name") or {}
    stdout.write(f"server {server_id}\nsnapshot {snapshot}\n")
    stdout.write(f"{len(tools)} tool(s) in this capture\n")
    for tool_name in sorted(tools):
        digest = (tools[tool_name] or {}).get("descriptor_sha256") or "?"
        stdout.write(f"  {tool_name}  {digest[:16]}\n")

    answered = confirm() if confirm is not None else _ask(stdout)
    if answered is None:
        stderr.write(
            "approving records that a human viewed this capture, and this is "
            "not an interactive terminal, so nobody did\n")
        return EXIT_FAULT
    if not answered:
        stderr.write("not approved\n")
        return EXIT_FAULT

    store.approve(snapshot_sha256=snapshot, viewed=True)
    stdout.write("approved\n")
    return EXIT_OK


def _ask(stdout):
    """None when there is no person to ask, which is not the same as no."""
    if not sys.stdin or not sys.stdin.isatty():
        return None
    stdout.write("approve these descriptors? [y/N] ")
    stdout.flush()
    return sys.stdin.readline().strip().lower() in ("y", "yes")



