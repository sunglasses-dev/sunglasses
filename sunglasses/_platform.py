"""One answer to "can the commands that need POSIX run here?".

Signed receipts and the config transactions take `fcntl` file locks, and the
proxy supervisor and the opt-in worker start children in their own process group.
Neither exists on Windows. Without this module the first of those a user reached
(`sunglasses doctor`, `sunglasses proxy`, `sunglasses receipts init`) died with an
ImportError or an AttributeError, and `receipts init` and `install` died after
they had started writing. `sunglasses scan` needs none of it.

The check is made before any such command does anything, and it asks the two
facts that matter, not a platform name: the interpreter says it is Windows, or
`fcntl` cannot be imported. Hiding `fcntl` (`sys.modules["fcntl"] = None`) is
therefore the same answer as Windows, which is how the tests reach it.
"""
import os
import sys

EXIT_UNSUPPORTED = 2        # the CLI's usage-error code: the invocation cannot be run here

# The commands that cannot run without the POSIX pieces. Everything else, scan
# first, does not touch them.
POSIX_ONLY_COMMANDS = ("proxy", "doctor", "receipts", "install", "uninstall", "init")


def _os_name():
    return os.name


def posix_pieces_missing():
    """True when this interpreter is Windows, or `fcntl` cannot be imported."""
    if _os_name() == "nt":
        return True
    try:
        import fcntl  # noqa: F401
    except ImportError:
        return True
    return False


def refusal_line(command):
    """The one line printed instead of a traceback."""
    return (f"sunglasses {command} is not supported on Windows yet: it needs file locks (fcntl) "
            "and process groups, which Windows does not have. `sunglasses scan` uses neither "
            "but is untested there. See Platforms in the README.")


def refuse_if_unsupported(command, stderr=None):
    """None when `command` can run here, else EXIT_UNSUPPORTED after printing the line."""
    if command not in POSIX_ONLY_COMMANDS or not posix_pieces_missing():
        return None
    out = stderr if stderr is not None else sys.stderr
    out.write(refusal_line(command) + "\n")
    return EXIT_UNSUPPORTED
