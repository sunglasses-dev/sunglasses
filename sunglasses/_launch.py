"""How sunglasses starts its own Python, so the folder it runs in never decides what it imports.

`python -m module` and `python -c code` put the CURRENT DIRECTORY first on `sys.path`, ahead
of the standard library and site-packages. Every place we start Python (the scan worker, the
proxy worker, the PreToolUse hook line `init` writes, the proxy wrapper `install` writes) was
therefore reading the folder being scanned, or the project folder of the agent, as if it
were part of Python: a `json.py` or `_json.py` there ran instead of the standard library.

THE FIX IS ONE RULE, written two ways that behave the same: drop the first path entry when
that entry is the implicit one, and nothing else.
  * Python 3.11 and newer: the `-P` flag does exactly that.
  * Python 3.9 and 3.10 have no `-P`: a short start-up line does the same thing (`sys.path[0]`
    is '' under `-c`; it is dropped only when it is ''), then runs the module with `runpy`.
`-I` is NOT used: it also drops the user site and every PYTHON* variable, so a copy of
sunglasses installed with `pip install --user` would stop importing, and a hook that cannot
import blocks every tool call. Entries a person put on the path on purpose (PYTHONPATH, an
editable install, a source checkout reached through a .pth file) are left alone.

THE PACKAGE ROOT, for a child we start ourselves. A child must still find `sunglasses` when
its parent got the package from the current folder (an uninstalled checkout, our own test
suite). So the parent hands the child its own package root in the start-up line, and the
child appends it to the END of the path, and only when `sunglasses` cannot be found any other
way. It is never put ahead of the standard library. It is the folder that holds the package the
parent itself imported, not a folder chosen by what is being scanned; it can be the scanned
folder only when the checkout that holds the package is the thing being scanned.
"""

import shlex
import sys

HOOK_FLAGS_MIN_VERSION = (3, 11)


def has_safe_path_flag(version_info=None):
    """True when the running Python has `-P` (3.11 and newer)."""
    return tuple((version_info or sys.version_info)[:2]) >= HOOK_FLAGS_MIN_VERSION


def package_root():
    """The folder that holds the `sunglasses` package this process imported."""
    import os
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def bootstrap(module, root=None):
    """One line of Python that drops the implicit first path entry, then runs `module` as `__main__`.

    With `root`, the line also appends it to the END of `sys.path` when `sunglasses` is not
    importable otherwise (see the module note). `module` and `root` are embedded as literals,
    so the child's own argv is left exactly as the caller built it.
    """
    parts = [
        "import sys",
        "sys.path[:1] = [] if sys.path[:1] == [''] else sys.path[:1]",
        "import importlib.util, runpy",
    ]
    if root is not None:
        parts.append("importlib.util.find_spec('sunglasses') or sys.path.append(%r)" % (root,))
    parts.append("runpy.run_module(%r, run_name='__main__', alter_sys=True)" % (module,))
    return "; ".join(parts)


def child_argv(module, flags=("-B",)):
    """argv for a child we start with the running interpreter: `module` as `__main__`, with the guard."""
    argv = [sys.executable, *flags]
    if has_safe_path_flag():
        argv.append("-P")
    return [*argv, "-c", bootstrap(module, root=package_root())]


def module_args(module, running=True):
    """The arguments after the interpreter for a line WRITTEN into a config file (hook, wrapper).

    `running` says the interpreter being written is the one running this code, so its version is
    known and `-P` can be chosen on it. For any other interpreter the version is not known here,
    so the start-up line is written: it behaves the same on every version from 3.9.
    """
    if running and has_safe_path_flag():
        return ["-P", "-m", module]
    return ["-c", bootstrap(module)]


def command_line(interpreter, module, running=True):
    """A shell command line (the hook form): the interpreter, then `module_args`, every word quoted."""
    return " ".join(shlex.quote(w) for w in [interpreter, *module_args(module, running)])
