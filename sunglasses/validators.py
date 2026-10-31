"""Structural validators: rules that read structure instead of matching characters.

A pattern is a regular expression over text. That is the right tool for a phrase and the
wrong tool for a question about structure: which object a field belongs to, which word of a
shell command is the program, whether a word is an option of that program, whether the file
that is run is the file that was downloaded. Each of those needs a parse, and a pattern that
tries to answer them from characters turns into a list of counterexamples.

A validator is a plain object with the shape of a rule (``id``, ``name``, ``category``,
``severity``, ``channel``, ``description``) and two methods:

``pregate(text) -> bool``
    Cheap substring checks only. When it is False the validator is not run, so a text that
    cannot carry the structure costs nothing.

``run(text) -> list[dict]``
    Findings in the shape the pattern layer reports, plus ``"structural": True`` and a small
    ``"evidence"`` dict. Output depends on ``text`` alone: no clock, no randomness, no
    environment. Cost is meant to be linear in the size of ``text`` and is measured on the
    input families in ``tests/test_structural_validators.py``.

The engine contains a validator that raises: the findings already made stand and the result
reports the inspection as not complete.

The engine runs the validators after the pattern layers (``SunglassesEngine._scan``, Step 3c)
on the raw, capped text; a config is read literally, not as prose, so there is no
normalisation, negation or framing pass. Validators are counted separately from patterns
(``info()["validators"]``); the published pattern count does not move.

GLS-STRUCT-001 -- a hook command that downloads code and hands it to a shell or an interpreter
----------------------------------------------------------------------------------------------

Membership is read by parsing. The text is parsed as JSON; if it is not one JSON document, the
outermost object around every literal ``"hooks"`` key is found with a single linear brace walk
and parsed on its own. Under a key named ``hooks`` (to a bounded depth) every string value of a
key named ``command`` is a hook command. A ``command`` anywhere else is not one.

Each command is split into words by a small shell tokenizer (quotes, escapes, comments,
``$(...)``, backticks, ``<(...)``, redirections, heredocs) and then into pipeline segments.
In a segment the program is the first word after assignments and wrapper words (``env``,
``sudo``, ``nice``, ``timeout`` ... with their own options) with any directory removed, so a
print command (``echo``, ``printf``) is text, never a fetch and never a run. The fetched bytes
must reach the runner by one of four links:

``pipe``                  ``curl ... | sh`` (the bytes pass through any filter in between)
``process_substitution``  ``bash <(curl ...)``, ``source <(...)``, ``. <(...)``
``command_substitution``  ``sh -c "$(curl ...)"``, ``eval "$(curl ...)"``, ``bash "$(...)"``
``download_then_run``     a download saved under a name that a later segment then runs

Interpreter options are classified, not pattern-matched: ``sh -n``, ``sh -o noexec``,
``python3 -V``, ``python3 -m json.tool``, ``node --check`` and the like do not run their
standard input. The same is done for the modes of the other words: ``curl --version``,
``env --help`` and ``sudo -l`` do not fetch or run anything, nor does the start of a long
informational name (``env --hel``), which is that option or is refused by the program. A word that is the
value of an option the program takes a value for (``grep -e --help``) is not an option; for a program whose
options are not listed, a long option written without ``=`` is read as taking the next word unless that
word asks for the version or help, and a short option as taking none. For a listed program, an option
whose meaning differs between implementations is read as a plain switch. A redirection on the runner
replaces the pipe (``sh < /dev/null`` reads nothing that was fetched; ``sh < <(curl ...)``
and ``bash <<< "$(curl ...)"`` read the fetched bytes), a program that prints its own text
(``echo``, ``printf``) ends the stream, and a later write to a downloaded file replaces what
was downloaded.

GLS-STRUCT-004 -- a Claude Code settings file that removes the safety prompts
-------------------------------------------------------------------------------

The text is read as the one JSON document a settings file is. Text that is not exactly one JSON
object (a prose example around a config, two documents, a comment, a trailing comma, a truncated
file) is not read, and neither is any key that is not at the top of the document: the same keys in
a schema, a template, a fixture or a nested object are not settings. Keys and values are compared
after the JSON parse, so a key or a value written with ``\\uXXXX`` escapes is the setting it spells.
``NaN`` and ``Infinity`` are not JSON, so a text that holds one is not a document. No setting is a
number: a long integer is read as 0 and a port is measured by its digits before it is converted, so
the answer and the cost of a very long number are the same on every interpreter.

Three shapes are reported, each at most once: ``permissions.defaultMode`` set to the string
``bypassPermissions`` or ``skipDangerousModePermissionPrompt`` set to ``true`` (the prompts are
off); an entry of ``permissions.allow`` that is the whole shell tool (``Bash``, ``Bash(*)``,
``Bash(:*)``) or ``*``; and ``env.ANTHROPIC_BASE_URL`` pointed at a public IP address or a tunnel
host. The base URL is split with the URL parser and the host is judged by the address parser: a
host is an address only if it parses as one, and it is public only if it is outside the blocks that
the address registries reserve (the list is carried here, so the answer does not depend on the
interpreter). A tunnel host is a name under ``ngrok``, ``ngrok-free``, ``trycloudflare.com`` or
``loca.lt``. Corporate host names, loopback, private, shared, link-local, documentation and
reserved addresses are not reported.

The owner of a settings file can write the same lines, so the severity is the lowest one: the
finding is shown and nothing is blocked or quarantined. The rule reads ``file`` (and its alias
``code``) and ``tool_output``; it is not read on ``message`` or ``web_content``, where tutorials
quote these keys.

Not read, by design: JSON with comments, a settings object inside a larger text, a URL that is not
``http`` or ``https``, an address written as a number or with fewer than four parts or with a
leading zero, an IPv4-mapped IPv6 address, an IPv6 address with a zone, a host name that resolves
to an address (a tunnel name is the one kind of name that is reported), and the other places a
prompt can be turned off.

This is a reader of words, not a shell. It does not model reachability beyond a few
word-level cases (``false && ...``, ``exit``), heredoc bodies, functions, other downloaders,
interpreter-native fetches, array-form commands, or hook formats that are not JSON. Those are
documented limits; the carriers still run.

GLS-STRUCT-005 -- Python that prints, logs, writes or sends every environment variable
----------------------------------------------------------------------------------------

The text is parsed as one Python module; if that is a syntax error (a document, Python 2, a
fragment), each fenced block tagged ``python``, ``py`` or ``python3`` is parsed on its own (at most
20; a fence left open runs to the end of the text). Nothing is matched by spelling: names are
resolved from the file's imports (``import os as o``, ``from os import environ``), a name the file
rebinds is not the module, and a fenced fragment that leaves out ``import os`` still reads ``os``
as the module.

"The environment" is ``os.environ``, ``dict(os.environ)``, ``os.environ.copy()``, ``{**os.environ}``,
and its ``.items()``, ``.values()`` and ``.keys()`` (alone or inside ``list``, ``tuple``, ``sorted``).
A loop binds the value of each variable when it iterates ``.items()`` (``for k, v``, or one name for
the pair), ``.values()``, or the names with ``os.environ[k]`` / ``.get(k)`` in the body. A variable
assigned from the environment is not followed.

A finding needs a sink that shows what it is given: ``print`` (to stdout, stderr, ``None`` or a file the
program opened for writing, not ``/dev/null``), ``pprint``, ``sys.stdout.write``, ``f.write``,
``json.dump``, ``Path(...).write_text``, ``map(print, ...)``, a logging call at a level that is shown
(warning and above by default; debug and info only when the file sets a level that shows them; a higher
level set in the file hides what is under it; none after ``logging.disable``), and the ``data=`` or
``params=`` of a ``requests`` or ``httpx`` call (``json=`` only when it is a real dict and no ``data=``
or ``files=`` overrides it). What the sink shows is decided on the tree: a bare name,
``str``/``repr``/``format``, an f-string field with no spec (or a spec that a string takes), ``+``,
``%`` and ``.format`` whose placeholders match the arguments and do not truncate, a tuple, list or dict
display, ``sep.join(...)`` over the items, ``json.dumps`` of a real dict or list, ``print(*items)``. A
comparison, ``not``, ``and``/``or``, a conditional expression, a subscript or slice, any other call
(``len``, ``.upper()``), a precision, names only, and ``json.dumps(os.environ)`` (which raises
``TypeError``) show nothing. A loop that tests the variables it prints (``if``, ``while``, ``match``, a
comprehension ``if``), or can leave early (``break``, ``continue``, ``return``, ``raise``,
``sys.exit``), is not a dump of every variable. Only branches proven unable to run are skipped (a constant or ``not <constant>``
test, the right side of ``False and`` / ``True or``, code after ``return``, the ``else`` of ``while True``). Any other test,
``TYPE_CHECKING`` included, is unknown: code under it is read, and a loop with an exit under it is a filter.

It is a judgment from syntax, not proof that the code runs: a function never called, a dump behind
a flag, and a logging handler that discards the record are still reported. The grammar is the one of the
interpreter that runs the scan, so syntax newer than that interpreter (a ``match`` statement before
Python 3.10) makes the text not Python and it is not read. ``return`` and ``yield``
of the environment are not output and are not reported. The finding is for review (medium); it
reads ``file`` and ``code``. A text the parser itself cannot take (too deep, parser stack full) is not
Python and is not read; the walk of a parsed tree that is too deep raises ``RecursionError``, which the
engine reports as an inspection that is not complete.
"""
from __future__ import annotations

import ast
import ipaddress
import json
import re
import string
import textwrap
import urllib.parse
import warnings

__all__ = ["HookFetchAndRun", "SettingsWithoutPrompts", "VALIDATORS", "classify_command"]

# ----------------------------------------------------------------------------- JSON side

_MAX_CANDIDATES = 64
_MAX_HOOKS_DEPTH = 8
_MAX_NESTED_COMMANDS = 4

# One token per JSON string or brace. An unterminated string ends at the line, never at the
# end of the text, so the scan stays linear and a stray quote in prose costs one line.
_JSON_TOKEN = re.compile(r'"[^"\\\n]*(?:\\[\s\S][^"\\\n]*)*(?:"|$)|[{}]', re.M)


def _json_candidates(text):
    """Parsed JSON values that may hold a hooks object, in text order."""
    try:
        whole = json.loads(text)
    except (ValueError, RecursionError):
        whole = None
    if isinstance(whole, (dict, list)):
        return [whole]
    starts, parent, close = [], [], []
    stack, hook_keys = [], []
    for match in _JSON_TOKEN.finditer(text):
        token = match.group()
        first = token[0]
        if first == "{":
            parent.append(stack[-1] if stack else -1)
            starts.append(match.start())
            close.append(-1)
            stack.append(len(starts) - 1)
        elif first == "}":
            if stack:
                close[stack.pop()] = match.end()
        elif token == '"hooks"' and stack:
            hook_keys.append(stack[-1])
    if not hook_keys:
        return []
    # The outermost CLOSED object around each key: an unclosed brace in prose above a real
    # config must not hide the config.
    top = [-1] * (max(hook_keys) + 1)
    for index in range(len(top)):
        if close[index] == -1:
            continue
        above = parent[index]
        top[index] = index if above == -1 or close[above] == -1 else top[above]
    roots, seen = [], set()
    for index in hook_keys:
        if close[index] == -1:
            continue
        root = top[index]
        if root not in seen:
            seen.add(root)
            roots.append(root)
            if len(roots) >= _MAX_CANDIDATES:
                break
    parsed = []
    for root in roots:
        try:
            parsed.append(json.loads(text[starts[root]:close[root]]))
        except (ValueError, RecursionError):
            continue
    return parsed


def _hook_commands(value):
    """Every string ``command`` under a ``hooks`` key (bounded depth), in order."""
    found = []
    stack = [(value, -1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            items = list(node.items())
            if depth >= 0:
                for key, item in items:
                    if key == "command" and isinstance(item, str):
                        found.append(item)
            for key, item in reversed(items):
                if depth < 0:
                    child = 0 if key == "hooks" else -1
                else:
                    child = depth + 1
                    if child > _MAX_HOOKS_DEPTH:
                        continue
                if isinstance(item, (dict, list)):
                    stack.append((item, child))
        elif isinstance(node, list):
            child = -1 if depth < 0 else depth + 1
            if child > _MAX_HOOKS_DEPTH:
                continue
            for item in reversed(node):
                if isinstance(item, (dict, list)):
                    stack.append((item, child))
    return found


# ---------------------------------------------------------------------------- shell side

class _Syntax(Exception):
    """The command is not something a shell would run (unbalanced quote or bracket)."""


class _Tok:
    __slots__ = ("kind", "value", "subs", "lead", "body", "expand", "at")

    def __init__(self, kind, value, subs=(), lead=False):
        self.kind = kind      # 'w' word | 'ps' process substitution | 'redir' | 'op'
        self.value = value    # word text with quotes removed; ps/command body; operator text
        self.subs = subs      # bodies of $(...) and backticks inside a word
        self.lead = lead      # a substitution is the first thing in the word
        self.body = None      # a here-document delimiter: the lines up to the delimiter (script reader only)
        self.expand = True    # a here-document delimiter: False when it was quoted, so the body is literal
        self.at = 0           # offset in the text where the token starts (script reader only)


_DOLLAR = "\x00"         # a '$' the shell leaves alone (single quotes, backslash); only the script reader asks for it
_WS = re.compile(r"[ \t\r\f\v]+")
_PLAIN = re.compile(r"[^\s'\"\\`$|&;<>()]+")
_DQ_RUN = re.compile(r'[^"\\$`]+')
_BRACKET = re.compile(r"[()'\"\\`]")
_REDIR = re.compile(r"(?:\d+|&)?(?:>>|>&|>\||>|<<<|<<-?|<&|<>|<)")
_OP = re.compile(r"\|\||\|&|\||&&|&|;;|;|\(|\)|\n")
_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")


def _closing_backtick(s, i):
    n = len(s)
    j = i + 1
    while j < n:
        c = s[j]
        if c == "\\":
            j += 2
            continue
        if c == "`":
            return j
        j += 1
    raise _Syntax


def _skip_double_quote(s, i):
    """Index just after the double-quoted string that opens at ``s[i]``."""
    n = len(s)
    j = i + 1
    while j < n:
        c = s[j]
        if c == "\\":
            j += 2
        elif c == '"':
            return j + 1
        elif c == "$" and s.startswith("$(", j):
            j = _balanced(s, j + 1)
        elif c == "`":
            j = _closing_backtick(s, j) + 1
        else:
            j += 1
    raise _Syntax


def _balanced(s, i):
    """Index just after the ``)`` that closes the ``(`` at ``s[i]``."""
    depth = 0
    pos = i
    while True:
        match = _BRACKET.search(s, pos)
        if not match:
            raise _Syntax
        c = match.group()
        at = match.start()
        if c == "(":
            depth += 1
            pos = at + 1
        elif c == ")":
            depth -= 1
            pos = at + 1
            if depth == 0:
                return pos
        elif c == "\\":
            pos = at + 2
        elif c == "'":
            end = s.find("'", at + 1)
            if end < 0:
                raise _Syntax
            pos = end + 1
        elif c == '"':
            pos = _skip_double_quote(s, at)
        else:
            pos = _closing_backtick(s, at) + 1


def _word(s, i, literal=False):
    """Read one shell word at ``s[i]``; returns (token, next index).

    With ``literal`` a ``$`` that quoting or a backslash protects is returned as ``_DOLLAR``."""
    n = len(s)
    parts, subs = [], []
    lead = False
    seen = False
    while i < n:
        c = s[i]
        plain = _PLAIN.match(s, i)
        if plain:
            parts.append(plain.group())
            seen = True
            i = plain.end()
            continue
        if c == "'":
            end = s.find("'", i + 1)
            if end < 0:
                raise _Syntax
            parts.append(s[i + 1:end].replace("$", _DOLLAR) if literal else s[i + 1:end])
            seen = True
            i = end + 1
        elif c == '"':
            seen = True
            i += 1
            buf = []
            while True:
                if i >= n:
                    raise _Syntax
                c = s[i]
                if c == '"':
                    i += 1
                    break
                if c == "\\":
                    nxt = s[i + 1:i + 2]
                    if nxt in ('"', "\\", "$", "`"):
                        buf.append(_DOLLAR if literal and nxt == "$" else nxt)
                        i += 2
                    elif nxt == "\n":
                        i += 2
                    else:
                        buf.append("\\")
                        i += 1
                elif c == "$" and s.startswith("$(", i):
                    end = _balanced(s, i + 1)
                    if not parts and not buf:
                        lead = True
                    subs.append(s[i + 2:end - 1])
                    buf.append(s[i:end])
                    i = end
                elif c == "`":
                    end = _closing_backtick(s, i)
                    if not parts and not buf:
                        lead = True
                    subs.append(s[i + 1:end])
                    buf.append(s[i:end + 1])
                    i = end + 1
                else:
                    run = _DQ_RUN.match(s, i)
                    if run:
                        buf.append(run.group())
                        i = run.end()
                    else:       # a lone '$'
                        buf.append(c)
                        i += 1
            parts.append("".join(buf))
        elif c == "\\":
            if i + 1 < n:
                if s[i + 1] != "\n":
                    parts.append(_DOLLAR if literal and s[i + 1] == "$" else s[i + 1])
                    seen = True
                i += 2
            else:
                parts.append("\\")
                seen = True
                i += 1
        elif c == "`":
            end = _closing_backtick(s, i)
            if not parts:
                lead = True
            subs.append(s[i + 1:end])
            parts.append(s[i:end + 1])
            seen = True
            i = end + 1
        elif c == "$":
            if s.startswith("$(", i):
                end = _balanced(s, i + 1)
                if not parts:
                    lead = True
                subs.append(s[i + 2:end - 1])
                parts.append(s[i:end])
                i = end
            elif s.startswith("${", i):
                end = s.find("}", i)
                if end < 0:
                    raise _Syntax
                parts.append(s[i:end + 1])
                i = end + 1
            elif s.startswith("$'", i):
                end = i + 2
                while end < n and s[end] != "'":
                    end += 2 if s[end] == "\\" else 1
                if end >= n:
                    raise _Syntax
                parts.append(s[i + 2:end])
                i = end + 1
            else:
                parts.append("$")
                i += 1
            seen = True
        else:
            break
    if not seen:
        raise _Syntax
    return _Tok("w", "".join(parts), tuple(subs), lead), i


def _lex(cmd):
    """Split a command line into word / ps / redir / op tokens."""
    toks = []
    n = len(cmd)
    i = 0
    heredocs = []
    while i < n:
        c = cmd[i]
        if c in " \t\r\f\v":
            i = _WS.match(cmd, i).end()
            continue
        if c == "\\" and cmd.startswith("\n", i + 1):
            i += 2
            continue
        if c == "#":
            end = cmd.find("\n", i)
            i = n if end < 0 else end
            continue
        if c == "\n":
            toks.append(_Tok("op", "\n"))
            i += 1
            for delim, strip in heredocs:
                while i < n:
                    end = cmd.find("\n", i)
                    line = cmd[i:n if end < 0 else end]
                    i = n if end < 0 else end + 1
                    if (line.lstrip("\t") if strip else line) == delim:
                        break
            heredocs = []
            continue
        if c in "<>" and cmd.startswith("(", i + 1):
            end = _balanced(cmd, i + 1)
            toks.append(_Tok("ps", cmd[i + 2:end - 1]))
            i = end
            continue
        redir = _REDIR.match(cmd, i)
        if redir:
            toks.append(_Tok("redir", redir.group()))
            i = redir.end()
            if redir.group().endswith("<<") or redir.group().endswith("<<-"):
                while i < n and cmd[i] in " \t":
                    i += 1
                word, i = _word(cmd, i)
                toks.append(word)
                heredocs.append((word.value, redir.group().endswith("<<-")))
            continue
        op = _OP.match(cmd, i)
        if op:
            toks.append(_Tok("op", op.group()))
            i = op.end()
            continue
        word, i = _word(cmd, i)
        toks.append(word)
    return toks


class _Segment:
    __slots__ = ("words", "redirs", "sep_before", "sep_after")

    def __init__(self, sep_before):
        self.words = []
        self.redirs = []        # (operator, target word)
        self.sep_before = sep_before
        self.sep_after = None


def _segments(toks):
    segments = []
    current = _Segment(None)
    pending = None
    i = 0
    n = len(toks)
    while i < n:
        tok = toks[i]
        i += 1
        if tok.kind == "op":
            if current.words or current.redirs:
                current.sep_after = tok.value
                segments.append(current)
                current = _Segment(None)
            if tok.value in ("(", ")"):
                if pending is None:
                    pending = ";"
            else:
                pending = tok.value
            current.sep_before = pending
            continue
        if not (current.words or current.redirs):
            current.sep_before = pending if pending is not None else current.sep_before
        if tok.kind == "redir":
            target = toks[i] if i < n and toks[i].kind in ("w", "ps") else None
            if target is not None:
                i += 1
            current.redirs.append((tok.value, target))
        else:
            current.words.append(tok)
    if current.words or current.redirs:
        segments.append(current)
    return segments


_KEYWORDS = frozenset(("if", "then", "else", "elif", "while", "until", "do", "!", "{", "}"))

_WRAPPER_VALUE_OPTIONS = {
    "env": frozenset(("-u", "-C", "-S", "-P", "--unset", "--chdir", "--split-string")),
    "command": frozenset(),
    "builtin": frozenset(),
    "exec": frozenset(("-a",)),
    "nohup": frozenset(),
    "time": frozenset(("-f", "-o", "--format", "--output")),
    "nice": frozenset(("-n", "--adjustment")),
    "ionice": frozenset(("-c", "-n", "-p", "-P", "-u", "--class", "--classdata")),
    "sudo": frozenset(("-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T",
                       "--user", "--group", "--chdir", "--host", "--prompt", "--role", "--type")),
    "doas": frozenset(("-u", "-C")),
    "timeout": frozenset(("-s", "-k", "--signal", "--kill-after")),
    "stdbuf": frozenset(("-i", "-o", "-e")),
    "setsid": frozenset(),
    "caffeinate": frozenset(("-t", "-w")),
    "xargs": frozenset(("-n", "-I", "-P", "-d", "-L", "-s", "-E", "-a")),
}
_DURATION = re.compile(r"\d+(?:\.\d+)?[smhd]?\Z")

# Wrapper modes that print or look something up and never run the command that follows.
_WRAPPER_NOEXEC_LONG = {
    "env": ("--help", "--version"),
    "sudo": ("--list", "--validate", "--version", "--help"),
    "timeout": ("--help", "--version"),
    "nice": ("--help", "--version"),
    "nohup": ("--help", "--version"),
    "stdbuf": ("--help", "--version"),
    "xargs": ("--help", "--version"),
    "ionice": ("--help", "--version"),
    "time": ("--help", "--version"),
    "setsid": ("--help", "--version"),
}
_WRAPPER_NOEXEC_SHORT = {"sudo": "lVv"}


def _starts_one_of(name, options):
    """Is the long option ``name`` one of ``options`` or the start of one?

    A start of an option is that option, or fits several and is refused by the program: in
    both cases nothing the line fetches is run or passed on. ``--`` alone is not a start."""
    return len(name) > 2 and any(option.startswith(name) for option in options)


def _split_string(stack):
    """``env -S STRING`` in any spelling at the top of the stack: (the string, words used) or (None, 0)."""
    value = stack[-1].value
    nxt = stack[-2] if len(stack) > 1 else None
    if value in ("-S", "--split-string"):
        return (nxt.value, 2) if nxt is not None and nxt.kind == "w" else ("", 1)
    if value.startswith("--split-string="):
        return value.partition("=")[2], 1
    if value.startswith("-S") and not value.startswith("--") and len(value) > 2:
        return value[2:], 1
    if value.startswith("-") and not value.startswith("--") and len(value) > 2 \
            and value.endswith("S") and value[1:].isalpha():
        return (nxt.value, 2) if nxt is not None and nxt.kind == "w" else ("", 1)
    return None, 0


def _skip_wrapper(name, stack):
    """Consume a wrapper's own options from ``stack`` (the unread words, next word last).

    Returns False when the wrapper only looks something up. ``env -S STRING`` splits STRING
    into the words it runs; they are pushed back onto the stack, so each word is handled
    once however many strings are split."""
    takes = _WRAPPER_VALUE_OPTIONS[name]
    noexec_long = _WRAPPER_NOEXEC_LONG.get(name, ())
    noexec_short = _WRAPPER_NOEXEC_SHORT.get(name, "")
    while stack:
        word = stack[-1]
        if word.kind != "w":
            break
        value = word.value
        if value == "--":
            stack.pop()
            break
        if name == "env" and _ASSIGN.match(value):
            stack.pop()
            continue
        if len(value) > 1 and value[0] == "-":
            if _starts_one_of(value.partition("=")[0], noexec_long):
                return False
            if name == "command" and not value.startswith("--") and ("v" in value or "V" in value):
                return False
            if name == "env":
                string, used = _split_string(stack)
                if used:
                    try:
                        lexed = _lex(string)
                    except _Syntax:
                        return False
                    del stack[-used:]
                    stack.extend(t if t.kind == "w" else _Tok("w", t.value) for t in reversed(lexed))
                    continue
            if noexec_short and not value.startswith("--"):
                for ch in value[1:]:
                    if ch in noexec_short:
                        return False
                    if "-" + ch in takes:
                        break
            del stack[-2 if value in takes else -1:]
            continue
        break
    if name == "timeout" and stack and stack[-1].kind == "w" and _DURATION.match(stack[-1].value):
        stack.pop()
    return True


def _base(value):
    return value.rsplit("/", 1)[-1]


def _program(words):
    """(program word, argument words) past assignments, keywords and wrapper words, or None."""
    stack = words[::-1]                 # the next word is last, so a wrapper never copies the rest
    while stack:
        word = stack[-1]
        if word.kind != "w":
            return None
        value = word.value
        stack.pop()
        if _ASSIGN.match(value) or value in _KEYWORDS:
            continue
        name = _base(value)
        if name in _WRAPPER_VALUE_OPTIONS:
            if not _skip_wrapper(name, stack):
                return None
            continue
        stack.reverse()
        return word, stack
    return None


def _norm(path):
    """The path without leading ``./`` pairs, found by index so the cost stays linear."""
    i = 0
    while path.startswith("./", i):
        i += 2
    return path[i:] if i else path


def _url_name(url):
    if not url:
        return None
    path = url.split("?", 1)[0].split("#", 1)[0]
    if "://" in path:
        path = path.split("://", 1)[1]
        if "/" not in path:
            return None
        path = path.split("/", 1)[1]
    path = path.rstrip("/")
    name = path.rsplit("/", 1)[-1]
    return name or None


_CURL_SHORT_VALUE = frozenset("AbcCdDeEFHKmPQrtTuUwxXyYz")
_CURL_LONG_VALUE = frozenset((
    "--header", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--user", "--user-agent",
    "--referer", "--cookie", "--cookie-jar", "--max-time", "--connect-timeout", "--retry",
    "--retry-delay", "--retry-max-time", "--proxy", "--request", "--upload-file", "--form", "--range",
    "--write-out", "--cacert", "--cert", "--key", "--output-dir", "--dump-header", "--config"))
_WGET_SHORT_VALUE = frozenset("oaetTwPUiBQlARDIXu")
_WGET_LONG_VALUE = frozenset((
    "--header", "--user-agent", "--timeout", "--tries", "--directory-prefix", "--output-file",
    "--post-data", "--referer", "--load-cookies", "--wait", "--input-file", "--append-output"))


class _Fetch:
    __slots__ = ("program", "stdout", "dests")

    def __init__(self, program, stdout, dests):
        self.program = program
        self.stdout = stdout
        self.dests = dests


_INFO_LONG = ("--version", "--help", "--manual")


def _parse_fetch(program, args, redirects):
    """A curl / wget segment: does it write to standard output, and where does it save?

    ``redirects`` are the targets that receive standard output (in order). The destination is
    known only when exactly one token decides it: one output option, or one redirection of
    standard output, or none. Two or more (an option beside a redirection, repeated options,
    repeated redirections, a process substitution among them) leave the destination unknown:
    the fetch is then followed nowhere."""
    curl = program == "curl"
    short_value = _CURL_SHORT_VALUE if curl else _WGET_SHORT_VALUE
    long_value = _CURL_LONG_VALUE if curl else _WGET_LONG_VALUE
    out_short, out_long = ("o", "--output") if curl else ("O", "--output-document")
    outputs = []
    remote_name = 0
    info_only = False
    url = None
    i = 0
    n = len(args)
    while i < n:
        arg = args[i]
        i += 1
        if arg.kind != "w":
            continue
        value = arg.value
        if value.startswith("--") and len(value) > 2:
            name, eq, rest = value.partition("=")
            if _starts_one_of(name, _INFO_LONG):
                # A name that is the start of --version, --help or --manual is that option,
                # or is ambiguous and refused by the program: nothing is fetched either way.
                info_only = True
            elif name == out_long or (not curl and len(name) >= 10 and out_long.startswith(name)):
                if eq:
                    outputs.append(rest)
                elif i < n and args[i].kind == "w":
                    outputs.append(args[i].value)
                    i += 1
                else:                   # a selector whose argument is not a plain word still counts
                    outputs.append(None)
                    i += 1
            elif curl and name in ("--remote-name", "--remote-name-all"):
                remote_name += 1
            elif name == "--url" and curl:
                if eq:
                    url = rest
                elif i < n and args[i].kind == "w":
                    url = args[i].value
                    i += 1
            elif name in long_value and not eq:
                i += 1
            continue
        if len(value) > 1 and value[0] == "-":
            j = 1
            while j < len(value):
                ch = value[j]
                if ch == out_short:
                    rest = value[j + 1:]
                    if rest:
                        outputs.append(rest)
                    elif i < n and args[i].kind == "w":
                        outputs.append(args[i].value)
                        i += 1
                    else:
                        outputs.append(None)
                        i += 1
                    break
                if ch in "Vh":
                    info_only = True
                elif curl and ch == "O":
                    remote_name += 1
                elif ch in short_value:
                    if j == len(value) - 1:
                        i += 1
                    break
                j += 1
            continue
        url = value
    if info_only:        # prints its version or help text; nothing is fetched
        return _Fetch(program, False, [])
    if len(outputs) + len(redirects) + remote_name > 1:
        return _Fetch(program, False, [])      # ambiguous: no destination is claimed
    stdout = False
    dests = []
    if outputs:
        if outputs[0] is None:
            pass                                # its argument is not a plain word: no destination
        elif outputs[0] in ("-", "/dev/stdout"):
            stdout = True
        else:
            dests.append(_norm(outputs[0]))
    elif curl:
        if remote_name:
            name = _url_name(url)
            if name:
                dests.append(name)
        elif redirects:
            target = redirects[0]
            if target != "-" and not target.isdigit() and not target.startswith("/dev/"):
                dests.append(_norm(target))
        else:
            stdout = True
    else:
        name = _url_name(url)
        if name:
            dests.append(name)
    return _Fetch(program, stdout, dests)


_SHELLS = frozenset(("sh", "bash", "zsh", "dash", "ksh", "ash", "fish"))
_NODES = frozenset(("node", "nodejs"))
_PYTHON = re.compile(r"(?:python|pypy)[0-9.]*\Z")

# Per interpreter: options that only inspect or format (the program does not run its input),
# options that carry inline code, and options that take a separate value.
_INTERPRETERS = {
    "python": {"noop": "VhHZ?", "inline": "c", "module": "m", "value": "WXQ",
               "long_noop": ("--version", "--help", "--help-all")},
    "node": {"noop": "chv", "inline": "ep", "module": "", "value": "r",
             "long_noop": ("--version", "--help", "--check"),
             "long_inline": ("--eval", "--print"),
             "long_value": ("--require", "--import", "--loader", "--experimental-loader", "--input-type")},
    "perl": {"noop": "cvVh", "inline": "eE", "module": "", "value": "",
             "long_noop": ("--version", "--help")},
    "ruby": {"noop": "cvh", "inline": "e", "module": "", "value": "rICEKS",
             "long_noop": ("--version", "--help", "--copyright")},
}


def _interpreter_kind(name):
    if _PYTHON.match(name):
        return "python"
    if name in _NODES:
        return "node"
    if name in ("perl", "ruby"):
        return name
    return None


class _Run:
    """How a runner segment uses its input: mode is stdin | file | inline | none."""

    __slots__ = ("mode", "operand", "inline")

    def __init__(self, mode, operand=None, inline=None):
        self.mode = mode
        self.operand = operand
        self.inline = inline


def _run_shell(args):
    i = 0
    n = len(args)
    want_inline = False
    explicit_stdin = False
    while i < n:
        arg = args[i]
        if arg.kind != "w":
            break
        value = arg.value
        if value == "--":
            i += 1
            break
        if value in ("--noexec", "--dump-strings", "--dump-po-strings") \
                or _starts_one_of(value.partition("=")[0], ("--version", "--help")):
            return _Run("none")
        if value.startswith("--") and len(value) > 2:
            i += 2 if value in ("--rcfile", "--init-file") else 1
            continue
        if len(value) > 1 and value[0] in "-+":
            flags = value[1:]
            if value[0] == "-" and "n" in flags:
                return _Run("none")
            if "c" in flags and value[0] == "-":
                want_inline = True
            if "s" in flags and value[0] == "-":
                explicit_stdin = True
            taken = 0
            for ch in flags:
                if ch in "oO":
                    option = args[i + 1 + taken] if i + 1 + taken < n else None
                    if ch == "o" and value[0] == "-" and option is not None \
                            and option.kind == "w" and option.value == "noexec":
                        return _Run("none")      # `-o noexec` reads the commands and runs none
                    taken += 1
            i += 1 + taken
            continue
        break
    if want_inline:
        return _Run("inline", inline=args[i] if i < n and args[i].kind == "w" else None)
    if explicit_stdin or i >= n or (args[i].kind == "w" and args[i].value == "-"):
        return _Run("stdin")
    return _Run("file", operand=args[i])


def _run_interpreter(kind, args):
    spec = _INTERPRETERS[kind]
    i = 0
    n = len(args)
    inline = None
    while i < n:
        arg = args[i]
        if arg.kind != "w":
            break
        value = arg.value
        if value == "--":
            i += 1
            break
        if value == "-":
            break
        if value.startswith("--") and len(value) > 2:
            name = value.partition("=")[0]
            if _starts_one_of(name, spec["long_noop"]):
                return _Run("none")
            if name in spec.get("long_inline", ()):
                inline = args[i + 1] if i + 1 < n and args[i + 1].kind == "w" else None
                return _Run("inline", inline=inline)
            if name in spec.get("long_value", ()) and "=" not in value:
                i += 1
            i += 1
            continue
        if len(value) > 1 and value[0] == "-":
            j = 1
            while j < len(value):
                ch = value[j]
                if ch in spec["noop"]:
                    return _Run("none")
                if ch in spec["module"]:
                    return _Run("none")
                if ch in spec["inline"]:
                    rest = value[j + 1:]
                    if rest:
                        return _Run("inline")
                    inline = args[i + 1] if i + 1 < n and args[i + 1].kind == "w" else None
                    return _Run("inline", inline=inline)
                if ch in spec["value"]:
                    if j == len(value) - 1:
                        i += 1
                    break
                j += 1
            i += 1
            continue
        break
    if i >= n or (args[i].kind == "w" and args[i].value == "-"):
        return _Run("stdin")
    return _Run("file", operand=args[i])


def _evidence(link, fetch, runner):
    return {"link": link, "fetch": fetch, "runner": runner}


# Programs that write their own output and never pass on what they read: a pipe through one
# of them carries no fetched bytes to the next stage. The last group reports on its input
# (a count, a digest, a comparison) instead of repeating it.
_DISCARDS_STREAM = frozenset((
    "echo", "printf", "true", "false", ":", "date", "pwd", "ls", "seq", "yes", "hostname",
    "uname", "id", "whoami", "sleep", "logger", "notify-send", "osascript", "test", "[", "read",
    "wc", "cksum", "sum", "cmp", "md5", "md5sum", "shasum", "sha1sum", "sha224sum", "sha256sum",
    "sha384sum", "sha512sum", "b2sum",
))


# Options of the common filters that take a separate value: (short letters, long names). A word
# after one of them is that option's value, never an option of its own.
_FILTER_VALUE_OPTIONS = {
    "grep": ("efmABCdD", ("--regexp", "--file", "--max-count", "--after-context", "--before-context",
                          "--context", "--directories", "--devices", "--include", "--exclude",
                          "--exclude-from", "--exclude-dir", "--label", "--binary-files")),
    "sed": ("efl", ("--expression", "--file", "--line-length")),
    "awk": ("fvF", ("--file", "--assign", "--field-separator", "--source")),
    "head": ("nc", ("--lines", "--bytes")),
    "tail": ("ncs", ("--lines", "--bytes", "--pid", "--sleep-interval", "--max-unchanged-stats")),
    "cut": ("bcdf", ("--bytes", "--characters", "--delimiter", "--fields", "--output-delimiter")),
    "sort": ("ktTSo", ("--key", "--field-separator", "--temporary-directory", "--buffer-size",
                       "--output", "--parallel", "--files0-from", "--batch-size",
                       "--compress-program", "--random-source")),
    "uniq": ("fsw", ("--skip-fields", "--skip-chars", "--check-chars")),
    "jq": ("fL", ("--from-file", "--indent", "--arg", "--argjson", "--slurpfile", "--rawfile")),
    "cat": ("", ()), "tee": ("", ()), "tr": ("", ()), "rev": ("", ()), "tac": ("", ()),
    "nl": ("bdfhilnsvw", ("--body-numbering", "--section-delimiter", "--footer-numbering",
                          "--header-numbering", "--line-increment", "--join-blank-lines",
                          "--number-format", "--number-separator", "--starting-line-number",
                          "--number-width")),
    "fold": ("w", ("--width",)),
    "expand": ("t", ("--tabs",)), "unexpand": ("t", ("--tabs",)),
    "paste": ("d", ("--delimiters",)),
    "column": ("cslNoOREHTW", ()),
    "xxd": ("cglos", ()),
    "od": ("AjNt", ("--address-radix", "--skip-bytes", "--read-bytes", "--format")),
    "strings": ("nte", ("--bytes", "--radix", "--encoding")),
    "iconv": ("ft", ("--from-code", "--to-code")),
    "base64": ("wbo", ("--wrap",)),
}
_FILTER_VALUE_OPTIONS.update({"egrep": _FILTER_VALUE_OPTIONS["grep"], "fgrep": _FILTER_VALUE_OPTIONS["grep"],
                              "gawk": _FILTER_VALUE_OPTIONS["awk"], "mawk": _FILTER_VALUE_OPTIONS["awk"]})


_TWO_VALUE_LONG = ("--arg", "--argjson", "--slurpfile", "--rawfile")


def _option_takes_next_word(value, known):
    """How many following words the option word ``value`` of a filter with table entry ``known`` takes as values."""
    letters, longs = known
    if value.startswith("--"):
        name = value.partition("=")[0]
        if "=" in value or len(name) < 3:
            return 0
        if any(info.startswith(name) for info in ("--version", "--help")):
            return 0
        if name in _TWO_VALUE_LONG:
            return 2
        return 1 if any(option.startswith(name) for option in longs) else 0
    for position, ch in enumerate(value[1:], 1):
        if ch in letters:
            return 1 if position == len(value) - 1 else 0
    return 0


def _unlisted_option_takes_next_word(value):
    """Words taken by the option word ``value`` of a filter whose options are not listed above: a long
    option written without ``=`` is read as taking its value as the next word, except that the next word
    is never read as a value when it asks for the version or help (see ``_informational``); a short option
    is read as taking none, since most of them are plain switches."""
    name = value.partition("=")[0]
    if not value.startswith("--") or "=" in value or len(name) < 3:
        return 0
    return 0 if any(info.startswith(name) for info in ("--version", "--help")) else 1


def _informational(name, args):
    """Is the program asked to print its version or help text, which reads no input?

    A word counts only where it is an option: not the value of an option that takes one, and not
    after the ``--`` that ends the options. A pending value is consumed before ``--`` is read."""
    known = _FILTER_VALUE_OPTIONS.get(name)
    skip = 0
    for arg in args:
        if arg.kind != "w":
            skip = 0
            continue
        if skip:
            if known is None and _starts_one_of(arg.value.partition("=")[0], ("--version", "--help")):
                return True      # a guessed value never hides a request for help
            skip -= 1
            continue
        if arg.value == "--":
            break
        if _starts_one_of(arg.value.partition("=")[0], ("--version", "--help")):
            return True
        if arg.value.startswith("-"):
            skip = (_option_takes_next_word(arg.value, known) if known is not None
                    else _unlisted_option_takes_next_word(arg.value))
    return False


def _discards_stream(name, args):
    if name in _DISCARDS_STREAM or _informational(name, args):
        return True
    if name == "cat":      # `cat FILE` prints the file; only a bare `cat` passes its input on
        return any(a.kind == "w" and a.value != "-" and not a.value.startswith("-") for a in args)
    return False


def _redirect_parts(operator):
    op = operator.lstrip("0123456789")
    return operator[:len(operator) - len(op)], op


def _stdin_redirect(segment):
    """(operator, target) of the last redirection that replaces standard input, or None."""
    found = None
    for operator, target in segment.redirs:
        fd, op = _redirect_parts(operator)
        if fd not in ("", "0"):
            continue
        if op in ("<", "<<", "<<-", "<<<", "<&", "<>"):
            found = (op, target)
    return found


_STDOUT_NAMES = frozenset(("/dev/stdout", "/dev/fd/1", "/proc/self/fd/1"))


def _stdout_redirects(segment):
    """Every target that takes standard output off the pipe, in order ("-" for a process substitution)."""
    found = []
    for operator, target in segment.redirs:
        if target is None or target.kind not in ("w", "ps"):
            continue
        fd, op = _redirect_parts(operator)
        if op.startswith("&>") and not fd or (op in (">", ">>", ">|", ">&") and fd in ("", "1")):
            if target.kind == "ps":
                found.append("-")
            elif target.value in _STDOUT_NAMES or (op == ">&" and target.value == "1"):
                continue                # standard output sent to itself stays on the pipe
            else:
                found.append(target.value)
    return found


def _stdout_redirect(segment):
    """The target word of the last redirection that moves standard output off the pipe, or None."""
    found = _stdout_redirects(segment)
    return found[-1] if found else None


def _input_of(segment, stream, downloaded, depth):
    """(link, fetch program) for the bytes the segment reads on standard input, or None.

    A redirection replaces the pipe: the program reads what the redirection names."""
    redirect = _stdin_redirect(segment)
    if redirect is None:
        return ("pipe", stream) if stream else None
    op, target = redirect
    if target is None:
        return None
    if op == "<<<" and target.kind == "w" and target.lead:
        for body in target.subs:
            fetched = _fetches_to_stdout(body, depth + 1)
            if fetched:
                return ("command_substitution", fetched)
    elif op == "<" and target.kind == "ps":
        fetched = _fetches_to_stdout(target.value, depth + 1)
        if fetched:
            return ("process_substitution", fetched)
    elif op == "<" and target.kind == "w" and _norm(target.value) in downloaded:
        return ("download_then_run", downloaded[_norm(target.value)])
    return None


def _emit(segment, out, downloaded):
    """The fetch program whose bytes the segment writes to the pipe, after its own redirections.

    Output sent to a file leaves the pipe empty and leaves the file holding those bytes."""
    dest = _stdout_redirect(segment)
    if dest is None:
        return out
    if out and dest != "-" and not dest.isdigit() and not dest.startswith("/dev/"):
        downloaded[_norm(dest)] = out
    return None


def _forget_overwritten(segment, name, args, downloaded):
    """A later write to a downloaded file replaces what was downloaded."""
    for operator, target in segment.redirs:
        if target is None or target.kind != "w":
            continue
        op = operator.lstrip("0123456789&")
        if op in (">", ">|") or (op == ">&" and not target.value.isdigit() and target.value != "-"):
            downloaded.pop(_norm(target.value), None)
    if name in ("cp", "mv", "install"):
        operands = [a.value for a in args if a.kind == "w" and not a.value.startswith("-")]
        if len(operands) >= 2:
            dest = _norm(operands[-1])
            sources = [_norm(s) for s in operands[:-1]]
            fetched = next((downloaded[s] for s in sources if s in downloaded), None)
            if name == "mv":
                for s in sources:
                    downloaded.pop(s, None)
            if fetched:
                downloaded[dest] = fetched
            else:
                downloaded.pop(dest, None)


def _walk(cmd, depth, downloaded, links=True):
    """(evidence, emitted) for ``cmd``.

    evidence is the first fetch-and-run link as a dict, or None. emitted is the fetch program
    whose bytes reach the command's standard output, or None; a substitution is judged by it.
    With ``links`` off the walk only follows the bytes (used inside a substitution)."""
    try:
        segments = _segments(_lex(cmd))
    except (_Syntax, RecursionError):
        return None, None
    downloaded = dict(downloaded)       # normalised path -> fetch program
    carried = None                      # fetch program whose bytes reach the next piped segment
    emitted = None
    dead_and = dead_or = stopped = False
    for segment in segments:
        before = segment.sep_before
        piped = before in ("|", "|&")
        if carried and not piped:       # the pipeline before this segment has ended
            emitted = emitted or carried
        # word-level reachability: `false && x`, `true || x`, and everything after `exit`
        if stopped:
            break
        if dead_and and before == "&&":
            carried = None
            continue
        dead_and = False
        if dead_or and before == "||":
            carried = None
            continue
        dead_or = False
        stream = carried if piped else None
        carried = None
        located = _program(segment.words)
        if located is None:
            _forget_overwritten(segment, None, (), downloaded)     # `> file` empties the file
            continue
        head, args = located
        name = _base(head.value)
        if name in ("exit", "return"):
            stopped = True
            continue
        if name == "false" and segment.sep_after == "&&":
            dead_and = True
            continue
        if name in ("true", ":") and segment.sep_after == "||":
            dead_or = True
            continue
        if name in ("curl", "wget"):
            _forget_overwritten(segment, name, args, downloaded)   # every `>` target is emptied first
            fetch = _parse_fetch(name, args, _stdout_redirects(segment))
            for path in fetch.dests:
                downloaded[path] = name
            carried = name if fetch.stdout else None
            continue
        _forget_overwritten(segment, name, args, downloaded)
        got = _input_of(segment, stream, downloaded, depth)
        if name == "tee":
            if _informational(name, args):
                continue
            appends = any(a.kind == "w" and (a.value in ("-a", "--append") or
                                             (a.value.startswith("-") and not a.value.startswith("--")
                                              and "a" in a.value)) for a in args)
            for arg in args:
                if arg.kind == "w" and not arg.value.startswith("-"):
                    if got:
                        downloaded[_norm(arg.value)] = got[1]
                    elif not appends:
                        downloaded.pop(_norm(arg.value), None)
            carried = _emit(segment, got[1] if got else None, downloaded)
            continue
        if links:
            # a direct run of a file that was downloaded earlier in the chain
            if _norm(head.value) in downloaded and not _is_known_program(name):
                return _evidence("download_then_run", downloaded[_norm(head.value)], name), emitted
            run = None
            if name in _SHELLS:
                run = _run_shell(args)
            elif name in ("source", "."):
                operand = next((a for a in args if a.kind == "ps" or not a.value.startswith("-")), None)
                run = _Run("file", operand=operand) if operand is not None else _Run("none")
            elif name == "eval":
                run = _Run("inline", inline=args[0] if args and args[0].kind == "w" else None)
            else:
                kind = _interpreter_kind(name)
                if kind:
                    run = _run_interpreter(kind, args)
            if run is not None:
                found = _link(run, name, args, got, downloaded, depth)
                if found:
                    return found, emitted
                continue
        elif _is_known_program(name):
            continue                    # what a runner writes is not the bytes it was given
        # an ordinary filter keeps the bytes flowing; a printer replaces them
        out = None if got is None or _discards_stream(name, args) else got[1]
        carried = _emit(segment, out, downloaded)
    if carried:
        emitted = emitted or carried
    return None, emitted


def _analyze(cmd, depth, downloaded):
    """First fetch-and-run link in ``cmd`` as an evidence dict, or None."""
    return _walk(cmd, depth, downloaded)[0]


def _fetches_to_stdout(body, depth):
    """Does a substitution body write fetched bytes to its standard output? The program, or None."""
    if depth > _MAX_NESTED_COMMANDS:
        return None
    return _walk(body, depth, {}, links=False)[1]


def _is_known_program(name):
    return name in _SHELLS or name in ("source", ".", "eval") or _interpreter_kind(name) is not None


def _link(run, name, args, got, downloaded, depth):
    if run.mode == "stdin":
        return _evidence(got[0], got[1], name) if got else None
    if run.mode == "file":
        operand = run.operand
        if operand.kind == "ps":
            fetched = _fetches_to_stdout(operand.value, depth + 1)
            if fetched:
                return _evidence("process_substitution", fetched, name)
            return None
        if operand.lead:
            for body in operand.subs:
                fetched = _fetches_to_stdout(body, depth + 1)
                if fetched:
                    return _evidence("command_substitution", fetched, name)
        path = _norm(operand.value)
        if path in downloaded:
            return _evidence("download_then_run", downloaded[path], name)
        return None
    if run.mode == "inline":
        word = run.inline
        if word is None:
            return None
        if word.lead:
            for body in word.subs:
                fetched = _fetches_to_stdout(body, depth + 1)
                if fetched:
                    return _evidence("command_substitution", fetched, name)
        if name in _SHELLS or name == "eval":
            if depth < _MAX_NESTED_COMMANDS:
                text = word.value if name != "eval" else " ".join(a.value for a in args if a.kind == "w")
                return _analyze(text, depth + 1, downloaded)
    return None


def classify_command(cmd):
    """Evidence dict for a hook command that downloads code and runs it, else None."""
    if not isinstance(cmd, str):
        return None
    try:
        return _analyze(cmd, 0, {})
    except RecursionError:
        return None


# ----------------------------------------------------------------------- settings side

_ALLOWS_THE_WHOLE_SHELL = frozenset(("Bash", "Bash(*)", "Bash(:*)", "*"))

# Blocks that the address registries reserve, carried here so that "public" means the same
# thing on every interpreter (the parser's own notion of a global address has moved between
# releases). In IPv6 only 2000::/3 is global unicast; these are the blocks inside it that are not.
_V4_NOT_PUBLIC = tuple(ipaddress.ip_network(block) for block in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"))
_V6_GLOBAL = ipaddress.ip_network("2000::/3")
_V6_NOT_PUBLIC = tuple(ipaddress.ip_network(block) for block in (
    "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"))

_TUNNEL_SUFFIXES = tuple(
    f"{name}.{tld}" for name in ("ngrok", "ngrok-free") for tld in ("io", "app", "dev")
) + ("trycloudflare.com", "loca.lt")

# A host longer than this is neither a name nor an address; it is not parsed.
_MAX_HOST = 253


def _is_port(text):
    """An empty port, or ASCII digits whose value is at most 65535. The digits are measured before
    they are converted, so a very long run is read the same, and costs time in proportion to its
    length, whether or not the interpreter limits integer string conversion (the default limit is
    4300 digits and some runtimes have none)."""
    if text == "":
        return True
    if not (text.isascii() and text.isdigit()):
        return False
    digits = text.lstrip("0")
    return len(digits) <= 5 and int(digits or "0") <= 65535


def _v4(host):
    """The address a dotted-decimal host spells, else None. Four plain decimal parts, no leading
    zeros: the forms that every URL parser reads the same way."""
    parts = host.split(".")
    if len(parts) != 4:
        return None
    for part in parts:
        if not (part.isascii() and part.isdigit() and len(part) <= 3 and int(part) <= 255
                and (part == "0" or part[0] != "0")):
            return None
    return ipaddress.IPv4Address(host)


def _host_kind(url):
    """``("public_ip" | "tunnel", host)`` when the base URL's host is one of those, else None."""
    if any(char <= " " or char == "\x7f" or char == "\\" for char in url):
        return None
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.netloc.isascii():
        return None
    authority = parts.netloc.rpartition("@")[2]
    if authority.startswith("["):
        host, closed, rest = authority[1:].partition("]")
        if not closed or (rest and rest[0] != ":") or not _is_port(rest[1:]):
            return None
        if not host or len(host) > _MAX_HOST or "%" in host:
            return None
        try:
            address = ipaddress.IPv6Address(host)
        except ValueError:
            return None
        if address not in _V6_GLOBAL or any(address in block for block in _V6_NOT_PUBLIC):
            return None
        return "public_ip", host
    host, _, port = authority.partition(":")
    if not host or len(host) > _MAX_HOST or not _is_port(port):
        return None
    host = host.lower()
    address = _v4(host)
    if address is not None:
        if any(address in block for block in _V4_NOT_PUBLIC):
            return None
        return "public_ip", host
    name = host[:-1] if host.endswith(".") else host
    for suffix in _TUNNEL_SUFFIXES:
        if name == suffix or name.endswith("." + suffix):
            return "tunnel", name
    return None


def _not_json(constant):
    """``parse_constant`` hook: NaN, Infinity and -Infinity are not JSON."""
    raise ValueError(constant)


def _small_int(digits):
    """``parse_int`` hook: no setting is a number, so a long integer is read as 0 rather than
    converted (the conversion is the part that is slow, and that some interpreters refuse)."""
    return int(digits) if len(digits) <= 18 else 0


def _settings_document(text):
    """The text as one JSON object, else None."""
    if text.startswith("\ufeff"):
        text = text[1:]
    try:
        document = json.loads(text, parse_constant=_not_json, parse_int=_small_int)
    except (ValueError, RecursionError):
        return None
    return document if isinstance(document, dict) else None


# --------------------------------------------------------------------------- validators

class HookFetchAndRun:
    """GLS-STRUCT-001: a hook command downloads code and hands it to a shell or interpreter."""

    id = "GLS-STRUCT-001"
    name = "Hook command fetches and runs remote code"
    category = "supply_chain"
    severity = "critical"
    channel = ["message", "file", "tool_output", "web_content"]
    description = ("A hook command in this configuration reads as one that downloads code and hands "
                   "it to a shell or an interpreter, which would run whatever the server sends next, "
                   "with the user's rights, when the hook's event fires.")

    def pregate(self, text):
        # The program names are not tested here: a shell reads `cu''rl` and `c\url` as curl,
        # so only the JSON structure is required. `\u` allows for JSON escapes that spell a
        # key differently.
        if "{" not in text:
            return False
        has_key = "hooks" in text or "\\u" in text
        has_command = "command" in text or "\\u" in text
        return has_key and has_command

    def run(self, text):
        commands = []
        for candidate in _json_candidates(text):
            commands.extend(_hook_commands(candidate))
        findings = []
        for cmd in dict.fromkeys(commands):
            evidence = classify_command(cmd)
            if evidence is None:
                continue
            findings.append({
                "id": self.id,
                "name": self.name,
                "category": self.category,
                "severity": self.severity,
                "channel": list(self.channel),
                "description": self.description,
                "matched_text": cmd[:50],
                "structural": True,
                "evidence": evidence,
            })
        return findings


class SettingsWithoutPrompts:
    """GLS-STRUCT-004: a Claude Code settings file removes the safety prompts."""

    id = "GLS-STRUCT-004"
    name = "Claude Code settings that remove the safety prompts"
    category = "agent_workflow_security"
    severity = "low"
    channel = ["file", "tool_output"]
    description = ("A Claude Code settings file that switches the permission prompts off, allows every "
                   "shell command, or sends the API traffic to a public IP address or a tunnel host. "
                   "The file's owner can write the same lines, so this is a notice to look at, "
                   "not a verdict.")

    _KEYS = ("permissions", "skipDangerousModePermissionPrompt", "ANTHROPIC_BASE_URL")

    def pregate(self, text):
        # One JSON object and nothing around it; a key may be spelled with \u escapes, so the
        # key names are tested only when there are none.
        body = text.strip()
        if body.startswith("\ufeff"):
            body = body[1:].lstrip()
        if body[:1] != "{" or body[-1:] != "}":
            return False
        return "\\u" in body or any(key in body for key in self._KEYS)

    def _finding(self, matched, **evidence):
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "channel": list(self.channel),
            "description": self.description,
            "matched_text": matched[:50],
            "structural": True,
            "evidence": evidence,
        }

    def run(self, text):
        document = _settings_document(text)
        if document is None:
            return []
        findings = []
        permissions = document.get("permissions")
        if isinstance(permissions, dict) and permissions.get("defaultMode") == "bypassPermissions":
            findings.append(self._finding("defaultMode: bypassPermissions", shape="default_mode"))
        if document.get("skipDangerousModePermissionPrompt") is True:
            findings.append(self._finding("skipDangerousModePermissionPrompt: true", shape="skip_prompt"))
        if isinstance(permissions, dict) and isinstance(permissions.get("allow"), list):
            rule = next((item for item in permissions["allow"]
                         if isinstance(item, str) and item in _ALLOWS_THE_WHOLE_SHELL), None)
            if rule is not None:
                findings.append(self._finding("allow: " + rule, shape="allow_every_shell"))
        env = document.get("env")
        if isinstance(env, dict) and isinstance(env.get("ANTHROPIC_BASE_URL"), str):
            judged = _host_kind(env["ANTHROPIC_BASE_URL"])
            if judged is not None:
                kind, host = judged
                findings.append(self._finding("ANTHROPIC_BASE_URL: " + host, shape="base_url", host_kind=kind))
        return findings


# ----------------------------------------------------------------------- Python tree side

_MAX_FENCES = 20
_FENCE_OPEN = re.compile(r"^ {0,3}(`{3,}|~{3,})[ \t]*([^\s`]*)")
_PYTHON_TAG = re.compile(r"(?:python3?|py)(?![\w+-])", re.I)
_FENCE_SHUT = re.compile(r"^ {0,3}(`{3,}|~{3,})[ \t]*$")

_BUILTINS = frozenset((
    "print", "open", "dict", "list", "tuple", "sorted", "str", "repr", "ascii", "format", "map",
    "any", "all", "sum", "min", "max", "set", "frozenset", "exit", "quit",
))
_BARE_MODULES = frozenset(("os", "sys", "json", "logging", "requests", "httpx", "pprint"))
_MAX_NAMES = 256           # environment-bound names tracked in one scope
_EXIT_CALLS = frozenset(("sys.exit", "os._exit", "builtins.exit", "builtins.quit"))
_LOG_HIGH = {"warning": 30, "warn": 30, "error": 40, "exception": 40, "critical": 50, "fatal": 50}
_LOG_LOW = {"debug": 10, "info": 20}
_LOG_NUMBERS = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "WARN": 30, "ERROR": 40, "CRITICAL": 50, "FATAL": 50,
                "NOTSET": 0}
_HTTP_VERBS = frozenset(("get", "post", "put", "patch", "delete", "head", "options", "request"))
_HTTP_MODULES = ("requests", "httpx")
_PERCENT = re.compile(r"%(\([^)]*\))?([#0\- +]*)(\*|\d+)?(?:\.(\*|\d*))?[hlL]?([a-zA-Z%])")
_WIDTH_ONLY = re.compile(r"^[<>^]?\d{0,4}s?$")
_WRITE_MODE = re.compile(r"^[rwax+]*[wax+][rwax+]*$")


_ENV_WORD = re.compile(r"\benviron\b")     # the word a read of the environment has to spell


class _Found(Exception):
    """The reader found a sink that shows the environment; ``args[0]`` is the evidence."""


class _Kind:
    """What a mapping, view or list made from ``os.environ`` is.

    ``shape`` is ``map`` (a mapping of every variable), ``items`` (name/value pairs), ``values`` or
    ``keys``. ``concrete`` is a real ``dict`` or ``list``; otherwise it is the environ object itself or
    a live view of it. ``on_env`` says the object or view stands on ``os.environ``, whose text form
    carries every value even for a view of the names."""

    __slots__ = ("shape", "concrete", "on_env")

    def __init__(self, shape, concrete, on_env):
        self.shape = shape
        self.concrete = concrete
        self.on_env = on_env

    def in_text(self):
        """Whether ``str(x)`` carries values."""
        if self.shape == "keys":
            return self.on_env and not self.concrete
        return True

    def in_iteration(self):
        """Whether iterating ``x`` yields values."""
        return self.shape in ("items", "values")

    def in_json(self):
        """Whether ``json.dumps(x)`` works and carries values."""
        return self.concrete and self.shape in ("map", "items", "values")


class _Ctx:
    """Names that hold the environment's values in the loop or comprehension being read."""

    __slots__ = ("keys", "values", "pairs")

    def __init__(self, keys=frozenset(), values=frozenset(), pairs=frozenset()):
        self.keys = keys
        self.values = values
        self.pairs = pairs

    def live(self):
        return bool(self.keys or self.values or self.pairs)

    def names(self):
        return self.keys | self.values | self.pairs


_NO_CTX = _Ctx()


def _fenced_python(text):
    """The bodies of the fenced blocks tagged python; one pass over the lines."""
    return _fenced_blocks(text, _PYTHON_TAG)


def _fenced_blocks(text, wanted, starts=None):
    """The bodies of the fenced blocks whose tag matches ``wanted``; one pass over the lines.

    ``starts``, when given, receives the 1-based line of each body's first line.
    """
    blocks = []
    body = None
    fence = None
    other = None            # the marker of an open fence that is not python: what it holds is not a block
    for number, line in enumerate(text.splitlines(), 1):
        if other is not None:
            shut = _FENCE_SHUT.match(line)
            if shut and shut.group(1)[0] == other[0] and len(shut.group(1)) >= len(other):
                other = None
            continue
        if body is None:
            opened = _FENCE_OPEN.match(line)
            if opened:
                if wanted.match(opened.group(2)):
                    fence = opened.group(1)
                    body = []
                    if starts is not None:
                        starts.append(number + 1)
                else:
                    other = opened.group(1)
            continue
        shut = _FENCE_SHUT.match(line)
        if shut and shut.group(1)[0] == fence[0] and len(shut.group(1)) >= len(fence):
            blocks.append("\n".join(body))
            body = None
            if len(blocks) >= _MAX_FENCES:
                break
        else:
            body.append(line)
    if body is not None and len(blocks) < _MAX_FENCES:
        blocks.append("\n".join(body))  # a fence left open runs to the end of the text, as in markdown
    return blocks


def _parse(source):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return ast.parse(source)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        # a text the interpreter itself cannot parse (too deep, parser stack full) is not a program
        return None


def _python_trees(text):
    """The text as one module; if it is not Python, each fenced python block on its own."""
    tree = _parse(text)
    if tree is not None:
        return [(text, tree)]
    trees = []
    for block in _fenced_python(text):
        source = textwrap.dedent(block)
        tree = _parse(source)
        if tree is not None:
            trees.append((source, tree))
    return trees


def _is_text(node):
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _empty_body(node):
    """True for a request body that is absent, ``None``, another falsy constant or an empty list, tuple, set or
    dict (requests then sends ``json=``)."""
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return not node.elts
    if isinstance(node, ast.Dict):
        return not node.keys
    return node is None or (isinstance(node, ast.Constant) and not node.value)


def _truth(test):
    """True / False for a test that is a constant, else None. No name is taken for a constant, ``TYPE_CHECKING``
    included: whether it is the typing flag depends on how it was bound."""
    if isinstance(test, ast.Constant):
        return bool(test.value)
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        inner = _truth(test.operand)
        return None if inner is None else not inner
    return None


def _count_loads(node, names):
    """Whether the expression or statement mentions one of ``names``."""
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in names:
            return True
    return False


def _percent_slots(fmt):
    """The conversions of a ``%`` format as (shows the argument, ok) pairs, or None when the format is
    one this reader does not follow (named keys, ``*`` widths, a bad conversion)."""
    slots = []
    position = 0
    while True:
        position = fmt.find("%", position)
        if position < 0:
            return slots
        found = _PERCENT.match(fmt, position)
        if found is None:
            return None
        position = found.end()
        named, _flags, width, precision, conv = found.groups()
        if conv == "%":
            continue
        if named is not None or width == "*" or precision == "*":
            return None
        slots.append(conv in "sra" and precision is None)


def _brace_slots(fmt):
    """The fields of a ``str.format`` format as a list of (key, shows the argument, needs a string), where
    key is an index or a keyword, or None when the format is one this reader does not follow. A spec with no
    conversion before it raises for anything but a string, so such a field shows a string value only."""
    try:
        parts = list(string.Formatter().parse(fmt))
    except ValueError:
        return None
    slots = []
    auto = 0
    explicit = False
    for _literal, field, spec, conv in parts:
        if field is None:
            continue
        if any(ch in field for ch in ".[") or conv not in (None, "s", "r", "a") or "{" in (spec or ""):
            return None
        if field == "":
            key = auto
            auto += 1
        elif field.isascii() and field.isdigit():
            if len(field) > 9:
                return None         # an index no argument list reaches; not converted (no unbounded int())
            key = int(field)
            explicit = True
        else:
            key = field
        slots.append((key, bool(_WIDTH_ONLY.match(spec or "")), bool(spec) and conv is None))
    if auto and explicit:
        return None
    return slots


class _EnvironmentReader:
    """Reads one module tree for code that shows or sends every environment variable."""

    def __init__(self, tree):
        self.tree = tree
        self.targets = {}      # imported name -> {what it stands for}
        self.stores = {}       # name -> times it is bound by anything but an import
        self.files = {}        # name -> times it is bound to a file opened for writing
        self.loggers = set()   # names bound once to logging.getLogger(...)
        self.sessions = {}     # names bound once to a requests session (``requests``) or httpx client (``httpx``)
        self.levels = []       # logging levels set anywhere: ints, None when not a literal
        self.logging_off = False
        self.exits = {}        # id(loop) -> the loop body can leave early
        self.replaced = False  # os.environ is assigned to in the file: it is no longer the process environment
        self._else_memo = {}   # id(loop) -> its else arm can run
        self._continues = None  # ids of the nodes with a continue below them, filled when a loop else needs it
        self._collect()

    # ------------------------------------------------------------------ name facts

    def _store(self, name, count=1):
        self.stores[name] = self.stores.get(name, 0) + count

    def _collect(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name.split(".")[0]
                    what = alias.name if alias.asname else alias.name.split(".")[0]
                    self.targets.setdefault(name, set()).add(what)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    name = alias.asname or alias.name
                    what = (node.module or "") + "." + alias.name if node.module and not node.level else "?"
                    self.targets.setdefault(name, set()).add(what)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                self._store(node.id)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self._store(node.name)
            elif isinstance(node, ast.arg):
                self._store(node.arg)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                self._store(node.name)
            elif type(node).__name__ in ("MatchAs", "MatchStar") and getattr(node, "name", None):
                self._store(node.name)
            elif type(node).__name__ == "MatchMapping" and getattr(node, "rest", None):
                self._store(node.rest)
        calls = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                self._note_binding(node.targets[0].id, node.value)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if isinstance(item.optional_vars, ast.Name):
                        self._note_binding(item.optional_vars.id, item.context_expr)
            elif isinstance(node, ast.Call):
                calls.append(node)
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)) \
                    and self.qual(node) == "os.environ":
                self.replaced = True            # the program binds os.environ to something of its own
        for call in calls:
            self._note_logging_call(call)
        self._note_exits()

    def _note_binding(self, name, value):
        if self._opened_for_writing(value):
            self.files[name] = self.files.get(name, 0) + 1
        elif isinstance(value, ast.Call):
            made = self.qual(value.func)
            if made == "logging.getLogger":
                self.loggers.add(name)
            elif made in ("requests.Session", "requests.session", "httpx.Client"):
                self.sessions[name] = made.split(".")[0]

    def _note_logging_call(self, call):
        made = self.qual(call.func)
        if made == "logging.disable":
            self.logging_off = True
        elif made == "logging.basicConfig":
            for keyword in call.keywords:
                if keyword.arg == "level":
                    self.levels.append(self._level(keyword.value))
        elif isinstance(call.func, ast.Attribute) and call.func.attr == "setLevel" and call.args \
                and self._is_logger(call.func.value):
            self.levels.append(self._level(call.args[0]))

    def _is_logger(self, node):
        """A logger the file made with ``getLogger`` (or the root logger), not some object with a ``setLevel``."""
        if isinstance(node, ast.Call):
            return self.qual(node.func) == "logging.getLogger"
        if isinstance(node, ast.Name):
            return self._bound_once(node, self.loggers)
        return self.qual(node) == "logging.root"

    def _level(self, node):
        if isinstance(node, ast.Constant):
            if isinstance(node.value, int) and not isinstance(node.value, bool):
                return node.value
            if isinstance(node.value, str):
                return _LOG_NUMBERS.get(node.value.upper())
        made = self.qual(node)
        if made and made.startswith("logging."):
            return _LOG_NUMBERS.get(made.split(".")[-1])
        return None

    def _else_runs(self, node):
        """Whether the ``else`` arm of a loop can run: never after ``while <true>``, and never after a ``for`` over
        a non-empty literal whose body always leaves with no ``continue`` in it."""
        if not node.orelse:
            return True
        runs = self._else_memo.get(id(node))
        if runs is None:
            runs = self._else_memo[id(node)] = self._else_decision(node)
        return runs

    def _else_decision(self, node):
        if isinstance(node, ast.While):
            return _truth(node.test) is not True
        source = node.iter
        if isinstance(source, (ast.List, ast.Tuple, ast.Set)) and source.elts \
                and not any(isinstance(e, ast.Starred) for e in source.elts) \
                and any(isinstance(s, (ast.Break, ast.Return, ast.Raise)) for s in node.body):
            return id(node) in self._with_continue()
        return True

    def _with_continue(self):
        """The ids of the nodes with a ``continue`` somewhere below them, from one pass over the tree."""
        if self._continues is None:
            order = list(ast.walk(self.tree))
            parent = {id(child): node for node in order for child in ast.iter_child_nodes(node)}
            found = set()
            for node in reversed(order):
                if isinstance(node, ast.Continue) or id(node) in found:
                    found.add(id(node))
                    above = parent.get(id(node))
                    if above is not None:
                        found.add(id(above))
            self._continues = found
        return self._continues

    def _note_exits(self):
        """Fill ``self.exits``: whether each ``for`` body can leave the loop early or skip an item (a filter)."""
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.For, ast.AsyncFor)):
                self.exits[id(node)] = self._leaves(node.body, False)

    def _leaves(self, stmts, inner):
        """Whether the statements can end the loop they sit in, or skip the rest of an item (a filter): a
        ``return``, a ``raise``, an exit call, or a ``break`` / ``continue`` that is not a nested loop's own. A
        branch that never runs does not count, and a nested function or class is another scope."""
        for node in stmts:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(node, (ast.Return, ast.Raise)):
                return True
            if isinstance(node, (ast.Break, ast.Continue)):
                if not inner:
                    return True
                continue
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                if self.qual(node.value.func) in _EXIT_CALLS:
                    return True
                continue
            if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                live = not (isinstance(node, ast.While) and _truth(node.test) is False)
                if (live and self._leaves(node.body, True)) \
                        or (self._else_runs(node) and self._leaves(node.orelse, inner)):
                    return True
                continue
            if isinstance(node, ast.If):
                truth = _truth(node.test)
                if (truth is not False and self._leaves(node.body, inner)) \
                        or (truth is not True and self._leaves(node.orelse, inner)):
                    return True
                continue
            for children in (getattr(node, "body", None), getattr(node, "orelse", None),
                             getattr(node, "finalbody", None)):
                if isinstance(children, list) and self._leaves(children, inner):
                    return True
            for group in (getattr(node, "handlers", ()), getattr(node, "cases", ())):
                if any(self._leaves(child.body, inner) for child in group
                       if getattr(child, "guard", None) is None or _truth(child.guard) is not False):
                    return True
        return False

    def builtin(self, name):
        return name in _BUILTINS and name not in self.stores and name not in self.targets

    def qual(self, node):
        """The dotted name a Name or Attribute chain stands for, or None."""
        if isinstance(node, ast.Name):
            whats = self.targets.get(node.id)
            if whats is not None:
                if len(whats) == 1 and node.id not in self.stores:
                    return next(iter(whats))
                return None
            if node.id in _BUILTINS and node.id not in self.stores:
                return "builtins." + node.id
            if node.id in _BARE_MODULES and node.id not in self.stores:
                return node.id  # a fenced fragment that leaves out its import
            return None
        if isinstance(node, ast.Attribute):
            base = self.qual(node.value)
            return base + "." + node.attr if base else None
        return None

    def _opened_for_writing(self, node):
        if not (isinstance(node, ast.Call) and self.qual(node.func) == "builtins.open" and node.args):
            return False
        mode = node.args[1] if len(node.args) > 1 else next((k.value for k in node.keywords if k.arg == "mode"), None)
        if not (isinstance(mode, ast.Constant) and isinstance(mode.value, str)):
            return False
        if "b" in mode.value or not _WRITE_MODE.match(mode.value):
            return False
        target = node.args[0]
        if isinstance(target, ast.Constant) and isinstance(target.value, str) and target.value == "/dev/null":
            return False
        return self.qual(target) != "os.devnull"

    # ------------------------------------------------------------------ what the environment is

    def env(self, node):
        """The ``_Kind`` of an expression made from ``os.environ``, or None."""
        if isinstance(node, (ast.Name, ast.Attribute)):
            return _Kind("map", False, True) if self.qual(node) == "os.environ" and not self.replaced else None
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if key is None and (inner := self.env(value)) is not None and inner.shape == "map":
                    return _Kind("map", True, False)
            return None
        if not isinstance(node, ast.Call):
            return None
        func = node.func
        if isinstance(func, ast.Attribute) and not node.keywords:
            inner = self.env(func.value)
            if inner is not None and inner.shape == "map" and not node.args:
                if func.attr == "copy":
                    return _Kind("map", True, False)
                if func.attr in ("items", "values", "keys"):
                    return _Kind(func.attr, False, inner.on_env)
            return None
        made = self.qual(func)
        if made == "builtins.dict" and len(node.args) == 1 and not isinstance(node.args[0], ast.Starred):
            inner = self.env(node.args[0])
            if inner is not None and inner.shape in ("map", "items"):
                return _Kind("map", True, False)
        if made in ("builtins.list", "builtins.tuple", "builtins.sorted") and node.args \
                and not isinstance(node.args[0], ast.Starred) and (made == "builtins.sorted" or len(node.args) == 1):
            if made != "builtins.sorted" and node.keywords:
                return None
            inner = self.env(node.args[0])
            if inner is not None:
                return _Kind("keys" if inner.shape == "map" else inner.shape, True, False)
        return None

    # ------------------------------------------------------------------ what is shown

    def string_valued(self, node, ctx):
        """Whether the expression is a ``str`` (a write needs one; a print does not)."""
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp):
            return isinstance(node.op, (ast.Add, ast.Mod))
        if isinstance(node, ast.Name):
            return node.id in ctx.values
        if isinstance(node, ast.Subscript):
            return self._value_of_key(node, ctx) or self._pair_value(node, ctx)
        if isinstance(node, ast.Call):
            made = self.qual(node.func)
            if made in ("builtins.str", "builtins.repr", "builtins.ascii", "builtins.format", "json.dumps",
                        "pprint.pformat", "urllib.parse.urlencode"):
                return True
            if isinstance(node.func, ast.Attribute) and node.func.attr in ("format", "join") \
                    and isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str):
                return True
            if isinstance(node.func, ast.Attribute) and node.func.attr == "get" and node.args:
                return self._value_of_key(node, ctx)
        return False

    def _value_of_key(self, node, ctx):
        """``E[k]`` or ``E.get(k)`` for a name ``k`` that is one of the environment's names."""
        if isinstance(node, ast.Subscript):
            base, key = node.value, node.slice
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get" \
                and node.args and not node.keywords:
            base, key = node.func.value, node.args[0]
        else:
            return False
        inner = self.env(base)
        return inner is not None and inner.shape == "map" and isinstance(key, ast.Name) and key.id in ctx.keys

    def _pair_value(self, node, ctx):
        """``pair[1]`` for a name bound to a whole name/value pair."""
        return (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id in ctx.pairs
                and isinstance(node.slice, ast.Constant) and node.slice.value == 1)

    def shows(self, node, ctx, as_json=False):
        """Whether the text of the expression carries an environment value."""
        if isinstance(node, ast.Constant):
            return False
        kind = self.env(node)
        if kind is not None:
            return kind.in_json() if as_json else kind.in_text()
        if isinstance(node, ast.Name):
            return node.id in ctx.values or node.id in ctx.pairs
        if isinstance(node, ast.Subscript) or (isinstance(node, ast.Call) and self._value_of_key(node, ctx)):
            return self._value_of_key(node, ctx) or self._pair_value(node, ctx)
        if isinstance(node, ast.JoinedStr):
            return any(self._field_shows(part, ctx) for part in node.values if isinstance(part, ast.FormattedValue))
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Add):
                return self.shows(node.left, ctx) or self.shows(node.right, ctx)
            if isinstance(node.op, ast.Mod) and _is_text(node.left):
                slots = _percent_slots(node.left.value)
                args = node.right.elts if isinstance(node.right, ast.Tuple) else [node.right]
                if slots is None or len(slots) != len(args) or any(isinstance(a, ast.Starred) for a in args):
                    return False
                return any(shown and self.shows(arg, ctx) for shown, arg in zip(slots, args))
            return False
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return any(self._element_shows(elt, ctx, as_json) for elt in node.elts)
        if isinstance(node, ast.Dict):
            return any(self.shows(part, ctx, as_json) for pair in zip(node.keys, node.values) for part in pair
                       if part is not None) or (self.env(node) is not None and self.env(node).in_text())
        if isinstance(node, (ast.ListComp, ast.SetComp)):
            return self._comprehension_shows(node, node.elt, ctx)
        if isinstance(node, ast.DictComp):
            return self._comprehension_shows(node, ast.Tuple(elts=[node.key, node.value], ctx=ast.Load()), ctx)
        if isinstance(node, ast.Call):
            return self._call_shows(node, ctx)
        return False

    def _element_shows(self, elt, ctx, as_json=False):
        if isinstance(elt, ast.Starred):
            kind = self.env(elt.value)
            return kind.in_iteration() if kind is not None else self.shows(elt.value, ctx, as_json)
        return self.shows(elt, ctx, as_json)

    def _field_shows(self, field, ctx):
        spec = field.format_spec
        if spec is not None:
            if not all(isinstance(part, ast.Constant) for part in spec.values):
                return False
            text = "".join(part.value for part in spec.values)
            if not _WIDTH_ONLY.match(text):
                return False
            if text and field.conversion == -1 and not self._is_value(field.value, ctx):
                return False
        return self.shows(field.value, ctx)

    def _is_value(self, node, ctx):
        """Whether the expression is one environment value (a ``str``), which takes a format spec."""
        if isinstance(node, ast.Name):
            return node.id in ctx.values
        return self._value_of_key(node, ctx) or self._pair_value(node, ctx)

    def _comprehension_shows(self, node, elt, ctx):
        inner = ctx
        for generator in node.generators:
            inner = self.bind(inner, generator.target, generator.iter)
            for cond in generator.ifs:
                if _truth(cond) is False:
                    return False            # nothing gets past a filter that is never true
                if _count_loads(cond, inner.names()):
                    inner = _NO_CTX
        return self.shows(elt, inner)

    def _call_shows(self, call, ctx):
        made = self.qual(call.func)
        args = call.args
        plain = not call.keywords and not any(isinstance(a, ast.Starred) for a in args)
        if made in ("builtins.str", "builtins.repr", "builtins.ascii", "pprint.pformat") and len(args) == 1 \
                and not any(isinstance(a, ast.Starred) for a in args):
            return self.shows(args[0], ctx)
        if made == "builtins.format" and len(args) == 1 and plain:
            return self.shows(args[0], ctx)
        if made == "json.dumps" and args and not isinstance(args[0], ast.Starred):
            if any(k.arg is None or k.arg == "cls" for k in call.keywords):
                return False
            return self.shows(args[0], ctx, as_json=True)
        if made == "urllib.parse.urlencode" and args and not isinstance(args[0], ast.Starred):
            kind = self.env(args[0])
            return kind is not None and kind.shape in ("map", "items")
        func = call.func
        if isinstance(func, ast.Attribute) and func.attr == "encode" and not args:
            return self.shows(func.value, ctx)
        if isinstance(func, ast.Attribute) and _is_text(func.value):
            if func.attr == "format":
                return self._format_shows(func.value.value, call, ctx)
            if func.attr == "join" and len(args) == 1 and not call.keywords:
                return self._join_shows(args[0], ctx)
        return False

    def _format_shows(self, fmt, call, ctx):
        slots = _brace_slots(fmt)
        if slots is None or any(isinstance(a, ast.Starred) for a in call.args) \
                or any(k.arg is None for k in call.keywords):
            return False
        keyword = {k.arg: k.value for k in call.keywords}
        for key, _plain, _needs_text in slots:      # a field with no argument raises before anything is shown
            if (key >= len(call.args)) if isinstance(key, int) else (key not in keyword):
                return False
        for key, plain, needs_text in slots:
            argument = call.args[key] if isinstance(key, int) else keyword[key]
            if plain and self.shows(argument, ctx) and (not needs_text or self._is_value(argument, ctx)):
                return True
        return False

    def _join_shows(self, argument, ctx):
        if isinstance(argument, (ast.ListComp, ast.GeneratorExp)):
            return self._comprehension_shows(argument, argument.elt, ctx)
        if isinstance(argument, (ast.List, ast.Tuple)):
            return any(self._element_shows(elt, ctx) for elt in argument.elts)
        kind = self.env(argument)
        return kind is not None and kind.in_iteration()

    # ------------------------------------------------------------------ names that carry values

    def bind(self, ctx, target, iterable):
        """The context inside ``for target in iterable``; names the target rebinds stop carrying values."""
        kind = self.env(iterable)
        if kind is not None:
            added = 2 if kind.shape == "items" and isinstance(target, (ast.Tuple, ast.List)) else 1
            if len(ctx.keys) + len(ctx.values) + len(ctx.pairs) + added > _MAX_NAMES:
                kind = None                 # names past the cap are not tracked: a set copied per step stays cheap
        if kind is None:
            if not ctx.live():
                return ctx
            gone = {n.id for n in ast.walk(target) if isinstance(n, ast.Name)}
            return _Ctx(ctx.keys - gone, ctx.values - gone, ctx.pairs - gone)
        if kind.shape == "items":
            if isinstance(target, ast.Name):
                return _Ctx(ctx.keys, ctx.values, ctx.pairs | {target.id})
            if isinstance(target, (ast.Tuple, ast.List)) and len(target.elts) == 2 \
                    and all(isinstance(e, ast.Name) for e in target.elts):
                key, value = target.elts
                return _Ctx(ctx.keys | {key.id}, ctx.values | {value.id}, ctx.pairs)
        elif kind.shape == "values" and isinstance(target, ast.Name):
            return _Ctx(ctx.keys, ctx.values | {target.id}, ctx.pairs)
        elif kind.shape in ("map", "keys") and isinstance(target, ast.Name):
            return _Ctx(ctx.keys | {target.id}, ctx.values, ctx.pairs)
        return ctx

    # ------------------------------------------------------------------ sinks

    def _stream(self, node):
        """Whether the expression is a text stream the output is visible on or kept in."""
        if node is None or (isinstance(node, ast.Constant) and node.value is None):
            return True
        made = self.qual(node)
        if made in ("sys.stdout", "sys.stderr"):
            return True
        if isinstance(node, ast.Name):
            return self.files.get(node.id) == 1 and self.stores.get(node.id) == 1
        return self._opened_for_writing(node)

    def _logging_shows(self, level):
        """Whether a record at ``level`` is shown. With no literal level set in the file the default
        (warning and above) applies; with one, the lowest literal level set; a level the reader cannot
        read hides debug and info. Never after ``logging.disable``."""
        if self.logging_off:
            return False
        known = [value for value in self.levels if value is not None]
        if None in self.levels and level < 30:
            return False
        return level >= (min(known) if known else 30)

    def _log_message_shows(self, call, ctx, skip):
        args = call.args[skip:]
        if not args or any(isinstance(a, ast.Starred) for a in call.args):
            return False
        message, extra = args[0], args[1:]
        if isinstance(message, ast.Constant) and isinstance(message.value, str):
            slots = _percent_slots(message.value)
            if not extra or slots is None or len(slots) != len(extra):
                return False
            return any(shown and self.shows(arg, ctx) for shown, arg in zip(slots, extra))
        return not extra and self.shows(message, ctx)

    def sink(self, call, ctx):
        """The name of the output call if ``call`` shows the environment, else None."""
        made = self.qual(call.func)
        args = call.args
        if made == "builtins.print":
            if any(k.arg is None for k in call.keywords):
                return None
            file = next((k.value for k in call.keywords if k.arg == "file"), None)
            if self._stream(file) and any(self._element_shows(a, ctx) for a in args):
                return "print"
            return None
        if made == "builtins.map" and len(args) == 2 and self.qual(args[0]) == "builtins.print":
            kind = self.env(args[1])
            return "print" if kind is not None and kind.in_iteration() else None
        if made in ("pprint.pprint", "pprint.pp"):
            stream = next((k.value for k in call.keywords if k.arg == "stream"), args[1] if len(args) > 1 else None)
            if args and not isinstance(args[0], ast.Starred) and self._stream(stream) and self.shows(args[0], ctx):
                return "pprint"
            return None
        if made == "json.dump" and len(args) >= 2 and not any(isinstance(a, ast.Starred) for a in args):
            if self._stream(args[1]) and self.shows(args[0], ctx, as_json=True):
                return "json.dump"
            return None
        if made and made.startswith("logging."):
            return self._log_sink(call, ctx, made.split(".")[-1], 0)
        func = call.func
        if isinstance(func, ast.Attribute):
            if func.attr == "write" and args and not isinstance(args[0], ast.Starred) and self._stream(func.value):
                return "write" if self.string_valued(args[0], ctx) and self.shows(args[0], ctx) else None
            if func.attr == "write_text" and args and isinstance(func.value, ast.Call) \
                    and self.qual(func.value.func) == "pathlib.Path" and not isinstance(args[0], ast.Starred):
                where = func.value.args[0] if func.value.args else None
                if (isinstance(where, ast.Constant) and where.value == "/dev/null") or self.qual(where) == "os.devnull":
                    return None
                return "write_text" if self.string_valued(args[0], ctx) and self.shows(args[0], ctx) else None
            receiver = func.value
            logger = self._bound_once(receiver, self.loggers) \
                or (isinstance(receiver, ast.Call) and self.qual(receiver.func) == "logging.getLogger")
            if logger:
                return self._log_sink(call, ctx, func.attr, 0)
            if self._bound_once(receiver, self.sessions) and func.attr in _HTTP_VERBS:
                return self._http_sink(call, ctx, func.attr, self.sessions[receiver.id])
        if made:
            module, _dot, verb = made.rpartition(".")
            if module in _HTTP_MODULES and verb in _HTTP_VERBS:
                return self._http_sink(call, ctx, verb, module)
        return None

    def _bound_once(self, node, names):
        """Whether the expression is a name that is bound exactly once, and that to one of ``names``."""
        return isinstance(node, ast.Name) and node.id in names and self.stores.get(node.id) == 1

    def _log_sink(self, call, ctx, method, skip):
        if method == "log" and call.args:
            level = self._level(call.args[0])
            if not self._logging_shows(20 if level is None else level):
                return None
            return "logging" if self._log_message_shows(call, ctx, 1) else None
        level = _LOG_HIGH.get(method) or _LOG_LOW.get(method)
        if level is None or not self._logging_shows(level):
            return None
        return "logging" if self._log_message_shows(call, ctx, skip) else None

    def _http_sink(self, call, ctx, verb, module):
        keyword = {k.arg: k.value for k in call.keywords if k.arg}
        if any(k.arg is None for k in call.keywords) or any(isinstance(a, ast.Starred) for a in call.args):
            return None
        sent = []
        if "data" in keyword:
            sent.append(keyword["data"])
        # requests takes a body second for post/put/patch and params second for get; httpx takes neither
        elif module == "requests" and verb in ("post", "put", "patch") and len(call.args) > 1:
            sent.append(call.args[1])
        if "params" in keyword:
            sent.append(keyword["params"])
        elif module == "requests" and verb == "get" and len(call.args) > 1:
            sent.append(call.args[1])
        for body in sent:
            kind = self.env(body)
            if kind is not None:
                if kind.shape == "map" or (kind.shape == "items" and kind.concrete):
                    return "http"
            elif self.shows(body, ctx):
                return "http"
        if "json" in keyword and all(_empty_body(keyword.get(name)) for name in ("data", "files")) \
                and self.shows(keyword["json"], ctx, as_json=True):
            return "http"
        return None

    # ------------------------------------------------------------------ the walk

    def read(self):
        """The evidence of the first sink that shows the environment, or None."""
        try:
            self._block(self.tree.body, _NO_CTX)
        except _Found as found:
            return found.args[0]
        return None

    def _block(self, stmts, ctx):
        for stmt in stmts:
            self._stmt(stmt, ctx)
            if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                return

    @staticmethod
    def _rebinds(body, names):
        """Whether the statements assign, delete or import any of ``names``."""
        for stmt in body:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id in names:
                    return True
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    if any((alias.asname or alias.name.split(".")[0]) in names for alias in node.names):
                        return True
        return False

    def _stmt(self, node, ctx):
        if isinstance(node, (ast.For, ast.AsyncFor)):
            self._expr(node.iter, ctx)
            inner = ctx
            if isinstance(node, ast.For) and not self.exits.get(id(node), False):
                inner = self.bind(ctx, node.target, node.iter)
                if inner.names() - ctx.names() and self._rebinds(node.body, inner.names()):
                    inner = _NO_CTX
            self._block(node.body, inner)
            if self._else_runs(node):
                self._block(node.orelse, ctx)
        elif isinstance(node, ast.While):
            self._expr(node.test, ctx)
            if _truth(node.test) is not False:
                self._block(node.body, _NO_CTX if _count_loads(node.test, ctx.names()) else ctx)
            if self._else_runs(node):
                self._block(node.orelse, ctx)
        elif isinstance(node, ast.If):
            self._expr(node.test, ctx)
            truth = _truth(node.test)
            inner = _NO_CTX if ctx.live() and _count_loads(node.test, ctx.names()) else ctx
            if truth is not False:
                self._block(node.body, inner)
            if truth is not True:
                self._block(node.orelse, inner)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for decorator in node.decorator_list:
                self._expr(decorator, ctx)
            self._block(node.body, _NO_CTX)
        elif type(node).__name__ == "Match":
            self._expr(node.subject, ctx)
            inner = _NO_CTX if ctx.live() and _count_loads(node.subject, ctx.names()) else ctx
            for case in node.cases:
                body = inner
                if case.guard is not None:
                    self._expr(case.guard, inner)
                    if inner.live() and _count_loads(case.guard, inner.names()):
                        body = _NO_CTX          # the guard picks which names get this case
                    if _truth(case.guard) is False:
                        continue                # a case that never matches
                self._block(case.body, body)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                self._expr(item.context_expr, ctx)
            self._block(node.body, ctx)
        elif type(node).__name__ in ("Try", "TryStar"):
            self._block(node.body, ctx)
            for handler in node.handlers:
                self._block(handler.body, ctx)
            self._block(node.orelse, ctx)
            self._block(node.finalbody, ctx)
        else:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    self._expr(child, ctx)

    def _expr(self, node, ctx):
        if isinstance(node, ast.Call):
            shown = self.sink(node, ctx)
            if shown is not None:
                raise _Found({"sink": shown, "line": node.lineno,
                              "shape": "loop" if ctx.live() else "whole_environment"})
        if isinstance(node, ast.IfExp):
            self._expr(node.test, ctx)
            truth = _truth(node.test)
            inner = _NO_CTX if ctx.live() and _count_loads(node.test, ctx.names()) else ctx
            if truth is not False:
                self._expr(node.body, inner)
            if truth is not True:
                self._expr(node.orelse, inner)
        elif isinstance(node, ast.BoolOp):
            inner = ctx
            for value in node.values:
                self._expr(value, inner)
                if _truth(value) is isinstance(node.op, ast.Or):
                    break                   # the rest is never evaluated
                if inner.live() and _count_loads(value, inner.names()):
                    inner = _NO_CTX
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            inner = ctx
            self._expr(node.generators[0].iter, inner)      # the first iterable is evaluated at once, always
            for index, generator in enumerate(node.generators):
                if index:
                    self._expr(generator.iter, inner)
                inner = self.bind(inner, generator.target, generator.iter)
                for cond in generator.ifs:
                    self._expr(cond, inner)
                    if _truth(cond) is False:
                        return              # nothing gets past a filter that is never true
                    if inner.live() and _count_loads(cond, inner.names()):
                        inner = _NO_CTX
            for part in ((node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,)):
                self._expr(part, inner)
        elif isinstance(node, ast.Lambda):
            self._expr(node.body, _NO_CTX)
        else:
            for child in ast.iter_child_nodes(node):
                self._expr(child, ctx)


class EnvironmentDumpedByPython:
    """GLS-STRUCT-005: Python code that shows or sends every environment variable."""

    id = "GLS-STRUCT-005"
    name = "Python program prints or sends the whole environment"
    category = "exfiltration"
    severity = "medium"
    channel = ["file", "code"]
    description = ("Python code that reads as one that prints, logs, writes or sends every environment "
                   "variable, with its value, where an agent or whoever reads the output will see the "
                   "secrets (API keys, tokens). It is a judgment from the syntax tree, not proof that the "
                   "code runs: a debug helper that dumps the environment is the dump it is, so this is a "
                   "finding to look at, not a block.")

    def pregate(self, text):
        return _ENV_WORD.search(text) is not None

    def run(self, text):
        for source, tree in _python_trees(text):
            evidence = _EnvironmentReader(tree).read()
            if evidence is None:
                continue
            lines = source.splitlines()
            line = lines[evidence["line"] - 1].strip() if evidence["line"] <= len(lines) else ""
            return [{
                "id": self.id,
                "name": self.name,
                "category": self.category,
                "severity": self.severity,
                "channel": list(self.channel),
                "description": self.description,
                "matched_text": line[:50],
                "structural": True,
                "evidence": evidence,
            }]
        return []


# ------------------------------------------------------------------- registry redirect, shell side

_MAX_NESTED = 22            # scripts read inside the one being read: $(...), sh -c strings, heredoc-fed shells
_MAX_NESTING = 3
_MAX_BAD_LINES = 8          # lines the lexer may skip before it reads the rest one line at a time
_UNKNOWN = "\x01"           # stands for a value the script does not let us read (command output, unset variable)
_SHELL_TAG = re.compile(r"(?:sh|bash|shell|zsh|console|dockerfile)(?![\w+-])", re.I)
_PROMPT = re.compile(r"(?m)^([ \t]*)\$ ")
_VARIABLE = re.compile(r"\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-=+?])([^}]*))?\})")
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")
_AUTHORITY = re.compile(r"[^/?#\\]*")
_LEAD_WORDS = frozenset(("RUN", "ONBUILD", "-", "run:"))

_CONFIG_FILES = {
    ".npmrc": "npm", ".yarnrc": "yarn", ".yarnrc.yml": "yarn_berry",
    "pip.conf": "pip", "pip.ini": "pip", ".pypirc": "pypirc",
}
_FILE_MANAGER = {"yarn_berry": "yarn", "pypirc": "pip"}
_PUBLIC_HOSTS = frozenset((
    "registry.npmjs.org", "registry.yarnpkg.com", "npm.pkg.github.com",
    "pypi.org", "files.pythonhosted.org", "pypi.python.org",
))
_PUBLIC_UPLOAD_HOSTS = frozenset(("upload.pypi.org", "test.pypi.org"))
_DOCUMENTATION_HOSTS = ("example.com", "example.org", "example.net")      # reserved: nobody can own a name under them
_MANAGERS = {"npm": "npm", "pnpm": "pnpm", "yarn": "yarn", "pip": "pip", "pip3": "pip"}
_PIP_NAME = re.compile(r"pip3(?:\.\d+)?\Z")
_MANAGER_VALUE_OPTIONS = frozenset((
    "--prefix", "--userconfig", "--globalconfig", "--workspace", "-w", "--cache", "--loglevel", "--location",
    "--registry", "--scope", "--otp", "--tag", "--dir", "-C", "--filter", "-F", "--file", "--config", "--cwd",
    "--cafile", "--ca", "--proxy", "--https-proxy", "--before", "--retries", "--timeout", "--trusted-host",
    "--cert", "--client-cert", "--cache-dir", "--log", "--python", "--exists-action", "--mutex",
))
_NPM_KEY = re.compile(r"(?:registry|@[^\s:]+:registry)\Z")
_YARN_KEY = re.compile(r"(?:registry|@[^\s:]+:registry|npmRegistryServer|npmScopes\.[^.\s]+\.npmRegistryServer)\Z")
_PIP_KEY = re.compile(r"(?:[a-z0-9_-]+\.)?(?:extra[-_])?index[-_]url\Z", re.I)
_NPMRC_LINE = re.compile(r"\s*(registry|@[^\s:=]+:registry)\s*=(.*)")
_YARNRC_LINE = re.compile(r"\s*\"?(registry|@[^\s:\"=]+:registry)\"?(?:\s*[:=]\s*|\s+)(.*)")
_BERRY_LINE = re.compile(r"\s*[\"']?npmRegistryServer[\"']?\s*:(.*)")
_PIP_LINE = re.compile(r"\s*(index[-_]url|extra[-_]index[-_]url)\s*[=:](.*)", re.I)
_PYPIRC_LINE = re.compile(r"\s*repository\s*[=:](.*)", re.I)
_PRINTF_SLOT = re.compile(r"%[sbd%]")


def _heredoc_body(text, i, opener, strip):
    """Read the lines of a here-document from ``text[i]`` to its delimiter; returns the index after it."""
    n = len(text)
    lines = []
    while i < n:
        end = text.find("\n", i)
        line = text[i:n if end < 0 else end]
        i = n if end < 0 else end + 1
        if strip:
            line = line.lstrip("\t")
        if line == opener.value:
            break
        lines.append(line)
    opener.body = "\n".join(lines)
    return i


def _lex_script(text, base=0, alone=False):
    """``_lex`` for a whole script.

    It keeps the body of each here-document on its delimiter token, records where every token starts, and
    skips a line it cannot read, so one bad line (a stray apostrophe in prose) does not hide the rest.
    After ``_MAX_BAD_LINES`` such lines the rest is read one line at a time, which keeps a text of
    unclosed brackets from costing a scan to the end for every line."""
    toks = []
    n = len(text)
    i = 0
    openers = []
    bad = 0
    while i < n:
        c = text[i]
        if c in " \t\r\f\v":
            i = _WS.match(text, i).end()
            continue
        if c == "\\" and text.startswith("\n", i + 1):
            i += 2
            continue
        if c == "#":
            end = text.find("\n", i)
            i = n if end < 0 else end
            continue
        if c == "\n":
            tok = _Tok("op", "\n")
            tok.at = base + i
            toks.append(tok)
            i += 1
            for opener, strip in openers:
                i = _heredoc_body(text, i, opener, strip)
            openers = []
            continue
        start = i
        made = []
        try:
            if c in "<>" and text.startswith("(", i + 1):
                end = _balanced(text, i + 1)
                made.append(_Tok("ps", text[i + 2:end - 1]))
                i = end
            else:
                redir = _REDIR.match(text, i)
                op = _OP.match(text, i) if not redir else None
                if redir:
                    made.append(_Tok("redir", redir.group()))
                    i = redir.end()
                    here = _redirect_parts(redir.group())[1] in ("<<", "<<-")
                    if here:
                        while i < n and text[i] in " \t":
                            i += 1
                        word, j = _word(text, i, True)
                        word.expand = not any(ch in text[i:j] for ch in "'\"\\")
                        word.at = base + i
                        made.append(word)
                        i = j
                        openers.append((word, redir.group().endswith("<<-")))
                elif op:
                    made.append(_Tok("op", op.group()))
                    i = op.end()
                else:
                    word, i = _word(text, i, True)
                    made.append(word)
        except (_Syntax, RecursionError):
            bad += 1
            if bad > _MAX_BAD_LINES and not alone:
                pos = start
                while pos < n:
                    end = text.find("\n", pos)
                    end = n if end < 0 else end
                    toks.extend(_lex_script(text[pos:end], base + pos, True))
                    if end < n:
                        newline = _Tok("op", "\n")
                        newline.at = base + end
                        toks.append(newline)
                    pos = end + 1
                return toks
            end = text.find("\n", start)
            i = n if end < 0 else end
            continue
        made[0].at = base + start
        toks.extend(made)
    return toks


def _expand(value, env, depth=0):
    """``value`` with the variables the script set replaced; what it cannot read becomes ``_UNKNOWN``."""
    if "$" not in value and "`" not in value and _DOLLAR not in value:
        return value

    def fill(match):
        name = match.group(1) or match.group(2)
        mode, word = match.group(3), match.group(4)
        current = env.get(name)
        assigned = name in env
        if mode is None:
            return current if assigned else _UNKNOWN
        colon = mode.startswith(":")
        sign = mode[-1]
        usable = assigned and (current != "" or not colon)
        if sign == "+":
            return _expand(word, env, depth + 1) if usable and depth < 4 else ""
        if usable:
            return current
        if sign == "?":
            return _UNKNOWN
        fallback = _expand(word, env, depth + 1) if depth < 4 else _UNKNOWN
        if sign == "=":
            env[name] = fallback
        return fallback

    result = _VARIABLE.sub(fill, value)
    return result.replace("$", _UNKNOWN).replace("`", _UNKNOWN).replace(_DOLLAR, "$")


def _registry_host(url, public=_PUBLIC_HOSTS):
    """(host, quiet) of an ``scheme://authority/...`` value, or None when it is not a readable URL.

    The authority runs to the first ``/ ? # \\``; user-info is everything up to the last ``@`` in it. A
    host is quiet when it is exactly one of ``public`` (after one ``www.``), or a name under a reserved
    documentation domain; never by its prefix."""
    scheme = _SCHEME.match(url)
    if not scheme:
        return None
    authority = _AUTHORITY.match(url, scheme.end()).group()
    if _UNKNOWN in authority or "$" in authority:
        return None
    hostport = authority.rpartition("@")[2]
    if hostport.startswith("["):
        host = hostport[:hostport.find("]") + 1] if "]" in hostport else hostport
    else:
        head, colon, port = hostport.rpartition(":")
        host = head if colon and (port.isdigit() or not port) else hostport
    host = urllib.parse.unquote(host).lower()
    if host.endswith("."):
        host = host[:-1]
    bare = host[4:] if host.startswith("www.") else host
    return host, host in public or bare in public or host.endswith(_DOCUMENTATION_HOSTS) and (
        host in _DOCUMENTATION_HOSTS or host.endswith(tuple("." + d for d in _DOCUMENTATION_HOSTS)))


def _setting_value(raw):
    raw = raw.strip()
    if raw[:1] in ("'", '"'):
        end = raw.find(raw[0], 1)
        return raw[1:end] if end > 0 else raw[1:]
    return raw.split(None, 1)[0] if raw else ""


def _file_settings(kind, content):
    """(key, value) of each registry setting in ``content``, read as the config file ``kind``."""
    follows = False
    for line in content.split("\n"):
        stripped = line.strip()
        if not stripped or stripped[0] in "#;":
            continue
        if kind == "npm":
            found = _NPMRC_LINE.match(line)
            if found:
                yield found.group(1), _setting_value(found.group(2))
        elif kind == "yarn":
            found = _YARNRC_LINE.match(line)
            if found:
                yield found.group(1), _setting_value(found.group(2))
        elif kind == "yarn_berry":
            found = _BERRY_LINE.match(line)
            if found:
                yield "npmRegistryServer", _setting_value(found.group(1))
        elif kind == "pip":
            found = _PIP_LINE.match(line)
            if found:
                follows = True
                yield found.group(1).lower(), _setting_value(found.group(2))
            elif follows and line[0] in " \t" and _SCHEME.match(stripped):
                yield "extra-index-url", _setting_value(stripped)
            else:
                follows = False
        else:
            found = _PYPIRC_LINE.match(line)
            if found:
                yield "repository", _setting_value(found.group(1))


def _lead_words(words):
    """The words of a command line past the lead words of a Dockerfile / CI list item."""
    i = 0
    while i < len(words) and words[i].kind == "w" and words[i].value in _LEAD_WORDS:
        i += 1
    if i and words[i - 1].value in ("RUN", "ONBUILD"):
        while i < len(words) and words[i].kind == "w" and words[i].value.startswith("--"):
            i += 1
    return words[i:] if i else words


def _assignments(words):
    """(name, value word) of the leading assignments of a command, and whether a command follows them."""
    found = []
    i = 0
    while i < len(words) and words[i].kind == "w":
        value = words[i].value
        if value in _KEYWORDS:
            i += 1
        elif _ASSIGN.match(value):
            found.append((value.partition("=")[0], value.partition("=")[2]))
            i += 1
        else:
            break
    return found, i < len(words)


def _unescape(text):
    return text.replace("\\n", "\n").replace("\\t", "\t")


class _ShellReader:
    """Reads a shell script for the commands that point a package manager at another registry."""

    def __init__(self):
        self.nested = _MAX_NESTED

    def read(self, text, line=1, depth=0, env=None):
        """Read ``text`` as one script; raises ``_Found`` at the first redirect to a non-public registry."""
        env = {} if env is None else env
        previous = None
        for seg in _segments(_lex_script(text)):
            if seg.sep_before not in ("|", "|&"):
                previous = None
            words = _lead_words(seg.words)
            for tok in words + [t for _, t in seg.redirs if t is not None]:
                for body in (tok.subs if tok.kind == "w" else (tok.value,)):
                    self._into(body, tok, text, line, depth, env)
            assigned, has_command = _assignments(words)
            if not has_command:
                for name, value in assigned:
                    env[name] = _expand(value, env)
                previous = None
                continue
            program = _program(words)
            if program is None:
                previous = None
                continue
            word, args = program
            name = _base(word.value)
            stdin = self._stdin(seg, previous, env)
            if name in ("export", "declare", "local", "readonly", "typeset"):
                for arg in args:
                    if arg.kind == "w" and _ASSIGN.match(arg.value):
                        key, _, value = arg.value.partition("=")
                        env[key] = _expand(value, env)
                previous = None
            elif name == "unset":
                for arg in args:
                    env.pop(arg.value, None)
                previous = None
            elif name in ("read", "for"):
                for arg in args[:1] if name == "for" else args:
                    if arg.kind == "w" and not arg.value.startswith("-") and _ASSIGN.match(arg.value + "="):
                        env[arg.value] = _UNKNOWN
                previous = None
            elif name in _MANAGERS or _PIP_NAME.match(name) or _PYTHON.match(name):
                self._manager(name, args, env, word, text, line)
                previous = None
            elif name in _SHELLS:
                self._shell(args, stdin, word, text, line, depth, env)
                previous = None
            else:
                shown = self._printed(name, args, stdin, env)
                self._writes(name, seg, args, shown, env, text, line)
                previous = None if _stdout_redirects(seg) else shown

    def _line(self, text, at, line):
        """(line number, the line's text) of offset ``at`` in ``text``, which starts at line ``line``."""
        start = text.rfind("\n", 0, at) + 1
        end = text.find("\n", at)
        end = len(text) if end < 0 else end
        return line + text.count("\n", 0, at), text[start:end].strip()[:50]

    def _into(self, body, tok, text, line, depth, env):
        if depth >= _MAX_NESTING or self.nested <= 0 or not body:
            return
        self.nested -= 1
        self.read(body, self._line(text, tok.at, line)[0], depth + 1, dict(env))

    def _stdin(self, seg, previous, env):
        """The text a command reads on standard input: its here-document or here-string, else the pipe."""
        redirect = _stdin_redirect(seg)
        if redirect is None:
            return previous
        op, target = redirect
        if target is None or target.kind != "w":
            return None
        if op in ("<<", "<<-") and target.body is not None:
            if not target.expand:
                return target.body
            return _expand(target.body.replace("\\$", _DOLLAR), env)
        if op == "<<<":
            return _expand(target.value, env)
        return None

    def _shell(self, args, stdin, word, text, line, depth, env):
        run = _run_shell(args)
        if run.mode == "inline" and run.inline is not None:
            self._into(_expand(run.inline.value, env), run.inline, text, line, depth, env)
        elif run.mode == "stdin" and stdin:
            self._into(stdin, word, text, line, depth, env)

    def _printed(self, name, args, stdin, env):
        """The text a content command writes to standard output, or None when we cannot know it."""
        words = [a for a in args if a.kind == "w"]
        if name == "echo":
            i = 0
            while i < len(words) and re.match(r"-[neE]+\Z", words[i].value):
                i += 1
            return _unescape(" ".join(_expand(w.value, env) for w in words[i:]))
        if name == "printf":
            if not words:
                return None
            values = [_expand(w.value, env) for w in words]
            fmt, rest = _unescape(values[0]), values[1:]
            slots = sum(1 for m in _PRINTF_SLOT.findall(fmt) if m != "%%")
            if slots <= 0:
                return _PRINTF_SLOT.sub(lambda m: "%" if m.group() == "%%" else "", fmt)
            out = []
            for first in range(0, max(len(rest), 1), slots):
                chunk = iter(rest[first:first + slots])
                out.append(_PRINTF_SLOT.sub(lambda m: "%" if m.group() == "%%" else next(chunk, ""), fmt))
            return "".join(out)
        if name == "tee":
            return stdin
        if name == "cat":
            return None if any(w.value != "-" and not w.value.startswith("-") for w in words) else stdin
        return None

    def _writes(self, name, seg, args, shown, env, text, line):
        """A command that writes what it prints to a package-manager config file."""
        if shown is None:
            return
        targets = []
        for operator, target in seg.redirs:
            fd, op = _redirect_parts(operator)
            if target is not None and target.kind == "w" and (
                    (op in (">", ">>", ">|", ">&") and fd in ("", "1")) or (op in ("&>", "&>>") and not fd)):
                targets.append(target)
        if name == "tee":
            for arg in args:
                if arg.kind == "w" and not arg.value.startswith("-"):
                    targets.append(arg)
        for target in targets:
            path = _expand(target.value, env)
            kind = _CONFIG_FILES.get(path.rsplit("/", 1)[-1])
            if kind is None:
                continue
            public = _PUBLIC_HOSTS | _PUBLIC_UPLOAD_HOSTS if kind == "pypirc" else _PUBLIC_HOSTS
            for key, value in _file_settings(kind, shown):
                self._judge("file_write", _FILE_MANAGER.get(kind, kind), key, value, public, target, text, line)

    def _manager(self, name, args, env, word, text, line):
        """``npm|pnpm|yarn|pip config set <registry key> <value>`` (``python -m pip`` included)."""
        if _PYTHON.match(name):
            options = [a for a in args if a.kind == "w"]
            if len(options) > 1 and options[0].value == "-m" and options[1].value == "pip":
                args = args[args.index(options[1]) + 1:]
                name = "pip"
            else:
                return
        manager = _MANAGERS.get(name) or "pip"
        words = []
        i, ended = 0, False
        while i < len(args) and args[i].kind == "w":
            tok = args[i]
            i += 1
            value = _expand(tok.value, env)
            if not ended and value == "--":
                ended = True
            elif not ended and len(value) > 1 and value[0] == "-":
                if value in ("--help", "-h"):
                    return
                if value in _MANAGER_VALUE_OPTIONS:
                    i += 1
            else:
                words.append((value, tok))
        values = [v for v, _ in words]
        if manager in ("npm", "pnpm") and values[:1] == ["set"]:
            rest = values[1:]
        elif values[:1] in (["config"], ["c"]) and values[1:2] == ["set"] and (values[0] == "config" or manager == "npm"):
            rest = values[2:]
        else:
            return
        if not rest:
            return
        key, value = rest[0], rest[1] if len(rest) > 1 else ""
        if not value and "=" in key and manager in ("npm", "pnpm"):
            key, _, value = key.partition("=")
        keys = {"npm": _NPM_KEY, "pnpm": _NPM_KEY, "yarn": _YARN_KEY, "pip": _PIP_KEY}[manager]
        if keys.match(key) and value:
            self._judge("config_set", manager, key, value, _PUBLIC_HOSTS, word, text, line)

    def _judge(self, sink, manager, key, value, public, tok, text, line):
        parsed = _registry_host(value, public)
        if parsed is None or parsed[1]:
            return
        number, shown = self._line(text, tok.at, line)
        raise _Found({"sink": sink, "manager": manager, "key": key, "host": parsed[0][:80], "line": number}, shown)


def _without_fence_lines(text):
    """The text with every markdown fence line emptied (line numbers kept): ``` would read as backticks."""
    return "\n".join("" if _FENCE_OPEN.match(line) else line for line in text.split("\n"))


class RegistryRedirectInShell:
    """GLS-STRUCT-006: a shell script points a package manager at a registry that is not public."""

    id = "GLS-STRUCT-006"
    name = "Shell points a package manager at a registry that is not public"
    category = "supply_chain"
    severity = "medium"
    channel = ["file", "code"]
    description = ("A shell script in this text points a package manager (npm, pnpm, yarn or pip) at a "
                   "registry that is not one of the public ones, with a config-set command or by writing "
                   "its config file. Every later install then comes from that host. A project mirror "
                   "looks the same as a hijack, so this is a finding for judgment, not proof of intent.")

    def pregate(self, text):
        low = text.lower()
        return (any(w in low for w in ("registry", "index-url", "index_url", "repository"))
                and any(w in low for w in ("config", "npmrc", "yarnrc", "pip.conf", "pip.ini", "pypirc", "set")))

    def run(self, text):
        reader = _ShellReader()
        try:
            reader.read(_without_fence_lines(text))
            starts = []
            for block, start in zip(_fenced_blocks(text, _SHELL_TAG, starts), starts):
                reader.read(_PROMPT.sub(r"\1", block), start)
        except _Found as found:
            evidence, shown = found.args
            return [{
                "id": self.id,
                "name": self.name,
                "category": self.category,
                "severity": self.severity,
                "channel": list(self.channel),
                "description": self.description,
                "matched_text": shown,
                "structural": True,
                "evidence": evidence,
            }]
        return []


VALIDATORS = (HookFetchAndRun(), SettingsWithoutPrompts(), EnvironmentDumpedByPython(),
              RegistryRedirectInShell())
