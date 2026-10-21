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

This is a reader of words, not a shell. It does not model reachability beyond a few
word-level cases (``false && ...``, ``exit``), heredoc bodies, functions, other downloaders,
interpreter-native fetches, array-form commands, or hook formats that are not JSON. Those are
documented limits; the carriers still run.
"""
from __future__ import annotations

import json
import re

__all__ = ["HookFetchAndRun", "VALIDATORS", "classify_command"]

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
    __slots__ = ("kind", "value", "subs", "lead")

    def __init__(self, kind, value, subs=(), lead=False):
        self.kind = kind      # 'w' word | 'ps' process substitution | 'redir' | 'op'
        self.value = value    # word text with quotes removed; ps/command body; operator text
        self.subs = subs      # bodies of $(...) and backticks inside a word
        self.lead = lead      # a substitution is the first thing in the word


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


def _word(s, i):
    """Read one shell word at ``s[i]``; returns (token, next index)."""
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
            parts.append(s[i + 1:end])
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
                        buf.append(nxt)
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
                    parts.append(s[i + 1])
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


VALIDATORS = (HookFetchAndRun(),)
