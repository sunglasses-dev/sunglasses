"""The commands, so the doctor is something a person can run.

Written against `tests/test_proxy_commands.py`, committed first.

T10.R4 and T10.R5 are written as commands. T10.R3 is a report with three lines
and an exit code, and an exit code only means something to somebody who can run
the thing that returns it. Until this file existed, doctor.py was a correct
library that nothing in the package called, which is the same fault a review of
this lane found at five components.

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

from . import doctor

USAGE = """usage:
  python -m sunglasses.proxy -- <server command> [args...]   run the mediator
  python -m sunglasses.proxy doctor [--config PATH]          report the route
  python -m sunglasses.proxy install <name> --config PATH -- <argv>
  python -m sunglasses.proxy uninstall <name> --config PATH
  python -m sunglasses.proxy approve <server-id> --snapshot SHA [--state-root PATH]
"""

EXIT_OK = 0
EXIT_FAULT = 1
EXIT_USAGE = 2

COMMANDS = ("doctor", "install", "uninstall", "approve")
SEPARATOR = "--"


def main(argv=None, *, stdout=None, stderr=None, serve=None, report=None,
         confirm=None):
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
    if head == "doctor":
        return _doctor(options, stdout, report)
    if not rest:
        return _usage(stderr)
    name = rest[0]
    if head == "install":
        return _install(name, options, stdout, stderr)
    if head == "approve":
        return _approve(name, options, stdout, stderr, confirm=confirm)
    return _uninstall(name, options, stdout)


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


def _doctor(options, stdout, report):
    runner = report or doctor.run
    sources = None
    if options.get("config"):
        sources = [("--config", options["config"])]
    outcome = runner(sources=sources) if sources else runner()

    rendered = doctor.render(outcome)
    stdout.write("self test: %s\n" % (
        "valid" if rendered["self_test"]["valid"] else "FAILED"))
    if rendered["self_test"].get("detail"):
        stdout.write("  %s\n" % rendered["self_test"]["detail"])
    stdout.write("per wrapper:\n")
    for row in rendered["per_wrapper"]:
        stdout.write("  %s %s %s\n" % (row["source"], row["name"],
                                       row["result"]))
    stdout.write("inventory:\n")
    for row in rendered["inventory"]:
        stdout.write("  %s %s %s\n" % (row.get("source"), row.get("name"),
                                       row.get("state")))
    stdout.write("aggregate: %s\n" % rendered["aggregate"])
    return rendered["exit_code"]



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

    snapshot = options.get("snapshot")
    if not snapshot:
        return _usage(stderr)
    root = pathlib.Path(options.get("state-root") or ".")
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


def _install(name, options, stdout, stderr):
    if not options.get("wrapped"):
        # R4's syntax is `install <name> -- <argv>`. With no separator there is
        # no wrapper command, and inventing one wraps the entry in whatever
        # this process happens to be.
        return _usage(stderr)
    record = doctor.install(options.get("config"), name, options["wrapped"],
                            root=options.get("state-root"))
    stdout.write("%s %s\n" % ("already wrapped" if record.get("already_wrapped")
                              else "wrapped", name))
    return EXIT_OK


def _uninstall(name, options, stdout):
    outcome = doctor.uninstall(options.get("config"), name,
                               root=options.get("state-root"))
    stdout.write("%s %s\n" % (outcome.reason, outcome.detail))
    # A conflict is not a restore. A script reading zero here carries on as
    # though the entry were back.
    return EXIT_OK if outcome.mutated else EXIT_FAULT
