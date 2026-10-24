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
"""
from __future__ import annotations

import bisect
import ipaddress
import json
import re
import urllib.parse
from array import array

__all__ = ["HookFetchAndRun", "SettingsWithoutPrompts", "EnvironmentToHttpClient", "VALIDATORS",
           "classify_command"]

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


# ---------------------------------------------------------------------- source-code side
#
# GLS-STRUCT-002 reads Python and Node source. The reader below is not a parser of either
# language: it masks what is never code (comments, string bodies), matches brackets once, and
# answers three questions about a call by walking tokens: which call it is, which of its
# arguments carry data, and whether the whole process environment reaches that argument.

_ENV_MAX_DEPTH = 200      # brackets nested deeper than this are not paired (calls inside are not read)
_ENV_MAX_FINDINGS = 20

_LEX_SPECIAL = re.compile(r"[#'\"`/{}]")
_PREFIX_LETTERS = "rRbBuUfF"
_BLANK = "\x01"


def _body_pattern(quote, triple, hole):
    escape = r"\\[\s\S]"
    closer = re.escape(quote * 3 if triple else quote)
    parts = [escape]
    if not triple:
        parts.append(r"\n")
    parts.append(closer)
    if hole == "f":
        parts.extend([r"\{\{", r"\{"])
    elif hole == "template":
        parts.append(r"\$\{")
    return re.compile("|".join(parts))


_BODY = {}
for _q in ("'", '"'):
    for _t in (False, True):
        _BODY[(_q, _t, "")] = _body_pattern(_q, _t, "")
        _BODY[(_q, _t, "f")] = _body_pattern(_q, _t, "f")
_BODY[("`", False, "template")] = re.compile(r"\\[\s\S]|`|\$\{")


def _scan_body(s, p, spec):
    """Walk a string body from ``p``. Returns (how, blank_to, resume): how is 'close', 'eol',
    'eof' or 'hole'. A hole is a replacement field of an f-string or a ``${`` of a template."""
    pattern = _BODY[spec]
    while True:
        m = pattern.search(s, p)
        if m is None:
            return "eof", len(s), len(s)
        g = m.group()
        if g[0] == "\\" or g == "{{":
            p = m.end()
        elif g == "\n":
            return "eol", m.start(), m.start()
        elif g in ("{", "${"):
            return "hole", m.start(), m.end()
        else:
            return "close", m.end(), m.end()


def _mask_source(s):
    """Same-length copy of ``s``: comments are spaces, string bodies are ``\\x01``. The fields
    of an f-string and the ``${}`` of a template stay code. Also returns the one-piece string
    literals, {start: end}, so that a host can be read back from the original text."""
    n = len(s)
    out = []
    literals = {}
    holes = []            # [spec, brace depth] of strings suspended inside a replacement field
    pos = 0

    def string(start, p, spec, whole):
        """Blank one piece of a string from ``start``; returns where code resumes."""
        how, blank_to, resume = _scan_body(s, p, spec)
        out.append(_BLANK * (blank_to - start))
        if how == "hole":
            opener = s[blank_to:resume]
            out.append(" {" if opener == "${" else "{")
            holes.append([spec, 0])
        elif how == "close" and whole:
            literals[start] = resume
        return resume

    while True:
        m = _LEX_SPECIAL.search(s, pos)
        if m is None:
            out.append(s[pos:])
            break
        i = m.start()
        c = s[i]
        if c == "#" or (c == "/" and s[i + 1:i + 2] == "/"):
            e = s.find("\n", i)
            e = n if e < 0 else e
            out.append(s[pos:i])
            out.append(" " * (e - i))
            pos = e
        elif c == "/":
            if s[i + 1:i + 2] == "*":
                e = s.find("*/", i + 2)
                e = n if e < 0 else e + 2
                out.append(s[pos:i])
                out.append(" " * (e - i))
                pos = e
            else:
                out.append(s[pos:i + 1])
                pos = i + 1
        elif c == "{":
            if holes:
                holes[-1][1] += 1
            out.append(s[pos:i + 1])
            pos = i + 1
        elif c == "}":
            out.append(s[pos:i + 1])
            if holes and holes[-1][1] == 0:
                spec = holes.pop()[0]
                pos = string(i + 1, i + 1, spec, False)
            else:
                if holes:
                    holes[-1][1] -= 1
                pos = i + 1
        elif c == "`":
            out.append(s[pos:i])
            pos = string(i, i + 1, ("`", False, "template"), False)
        else:
            j = i
            while j > pos and i - j < 2 and s[j - 1] in _PREFIX_LETTERS:
                j -= 1
            if j > 0 and (s[j - 1].isalnum() or s[j - 1] in "_$"):
                j = i
            prefix = s[j:i]
            triple = s[i:i + 3] == c * 3
            spec = (c, triple, "f" if "f" in prefix.lower() else "")
            out.append(s[pos:j])
            pos = string(j, i + (3 if triple else 1), spec, True)
    return "".join(out), literals


_ENV_TOKEN = re.compile(r"\x01+|[A-Za-z_$][\w$]*|\d[\w.]*|\S")

_ROOTS = frozenset(("requests", "httpx", "aiohttp", "axios", "got", "fetch", "urllib", "urllib2",
                    "urllib3", "urlopen"))
_GLOBALS = frozenset(("global", "globalThis", "window", "self"))
_CTORS = frozenset(("Session", "Client", "AsyncClient", "PoolManager", "ProxyManager",
                    "ClientSession", "create", "extend"))
_RECEIVERS = frozenset((
    "requests", "httpx", "aiohttp", "axios", "got", "urllib3",
    "requests.Session()", "requests.sessions.Session()", "httpx.Client()", "httpx.AsyncClient()",
    "aiohttp.ClientSession()", "urllib3.PoolManager()", "urllib3.ProxyManager()",
    "axios.create()", "got.extend()"))
_METHODS = frozenset(("get", "post", "put", "patch", "delete", "head", "options", "request", "stream"))
_BARE = frozenset(("fetch", "axios", "got", "urlopen", "urllib.request.urlopen", "urllib2.urlopen",
                   "urllib.request.Request", "urllib2.Request"))
_DATA_KEYWORDS = frozenset(("json", "data", "params", "headers", "files", "content", "body", "cookies"))
_LOCAL_HOSTS = frozenset(("localhost", "127.0.0.1", "::1"))

_ENV_PICKS = frozenset(("get", "getlist", "pop", "filter", "keys", "has", "includes"))
_ENV_COPIES = frozenset(("items", "values", "copy"))
_PASS_NAMES = frozenset((
    "dict", "str", "repr", "ascii", "bytes", "bytearray", "OrderedDict", "collections.OrderedDict",
    "copy", "copy.copy", "copy.deepcopy", "deepcopy", "Map", "URLSearchParams",
    "Object.assign", "Object.fromEntries", "Object.entries", "Object.values"))
_PASS_LAST = frozenset(("dumps", "stringify", "urlencode", "fromEntries", "entries", "assign",
                        "deepcopy", "URLSearchParams"))
_KEYS_NAMES = frozenset(("list", "sorted", "set", "tuple", "len", "frozenset", "reversed",
                         "Object.keys", "Object.getOwnPropertyNames", "Reflect.ownKeys"))

_MOCK_PATCH = re.compile(r"(?<![\w$])patch\s*\(\s*(\x01+)\s*[,)]")
_MOCK_PATCH_OBJECT = re.compile(r"(?<![\w$])patch\s*\.\s*object\s*\(\s*([\w$.]+)\s*,\s*(\x01+)\s*[,)]")
_MOCK_SPY = re.compile(r"(?<![\w$])(?:spyOn|stub)\s*\(\s*([\w$.]+)\s*,\s*(\x01+)\s*[,)]")
_MOCK_ASSIGN = re.compile(
    r"(?<![\w$.])([A-Za-z_$][\w$.]*)\s*=(?!=)\s*(?:[A-Za-z_$][\w$]*\s*\.\s*)*"
    r"(?:Mock|MagicMock|AsyncMock|fn|stub|spy)\b")
_MOCK_WORDS = ("patch", "spyOn", "stub", "Mock", "fn", "spy")

_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})([^\n]*)$", re.M)
_URL_HEAD = re.compile(r"(?:https?|wss?)://([^/?#]*)", re.I)
_PORT = re.compile(r"\d{0,5}")


def _fenced_segments(text, channel):
    """Split ``text`` into (start, end, fenced). A real code fence (three or more backticks or
    tildes at the start of a line, closed by the same character) of a prose text is its own
    segment; the ``code`` channel is never split, it is source."""
    if channel == "code" or ("```" not in text and "~~~" not in text):
        return [(0, len(text), False)]
    segments = []
    cursor = 0
    opened = None
    for m in _FENCE.finditer(text):
        ticks, info = m.group(1), m.group(2)
        if opened is None:
            if ticks[0] == "`" and "`" in info:
                continue
            opened = (ticks[0], len(ticks), min(m.end() + 1, len(text)))
            segments.append((cursor, m.start(), False))
        elif ticks[0] == opened[0] and len(ticks) >= opened[1] and not info.strip():
            segments.append((opened[2], m.start(), True))
            cursor = min(m.end() + 1, len(text))
            opened = None
    if opened is None:
        segments.append((cursor, len(text), False))
    else:
        segments.append((opened[2], len(text), True))
    return [seg for seg in segments if seg[1] > seg[0]]


def _is_local_url(url):
    """True for a literal http(s)/ws(s) URL whose host, after userinfo and port, is the local machine."""
    m = _URL_HEAD.match(url)
    if m is None:
        return False
    authority = m.group(1)
    if any(ch in authority for ch in "\\ \t\r\n\x00"):
        return False
    host = authority.rpartition("@")[2]
    if host.startswith("["):
        end = host.find("]")
        if end < 0 or not _PORT.fullmatch(host[end + 1:].lstrip(":")) or host[end + 1:end + 2] not in ("", ":"):
            return False
        host = host[1:end]
    else:
        host, sep, port = host.partition(":")
        if sep and not _PORT.fullmatch(port):
            return False
    return host.lower() in _LOCAL_HOSTS


def _literal_text(original):
    """The text between the quotes of a string literal as it was written."""
    i = 0
    while original[i] in _PREFIX_LETTERS:
        i += 1
    quote = original[i]
    width = 3 if original[i:i + 3] == quote * 3 else 1
    return original[i + width:len(original) - width]


class _Reader:
    """Tokens, bracket pairs and the environment references of one piece of source."""

    def __init__(self, seg):
        self.seg = seg
        self.masked, self.literals = _mask_source(seg)
        masked = self.masked
        starts, ends = array("l"), array("l")
        kinds = bytearray()                  # 0 punctuation, 1 name, 2 string, 3 number
        match, parent = array("l"), array("l")
        flags = bytearray()                  # per opening bracket: 1 holds `for`, 2 holds `if` after it
        stack = []
        too_deep = 0
        closers = {")": "(", "]": "[", "}": "{"}
        self.calls = []                      # token index of every name that can start a client call
        self.envs = []                       # (first, last) token index of each environment reference
        for mt in _ENV_TOKEN.finditer(masked):
            a, b = mt.span()
            c = masked[a]
            idx = len(starts)
            starts.append(a)
            ends.append(b)
            match.append(-1)
            parent.append(stack[-1] if stack else -1)
            flags.append(0)
            if c == _BLANK:
                kinds.append(2)
            elif c.isalpha() or c in "_$":
                kinds.append(1)
                word = masked[a:b]
                if word in _ROOTS:
                    self.calls.append(idx)
                elif word == "environ" or word == "env":
                    owner = "os" if word == "environ" else "process"
                    if idx >= 2 and masked[starts[idx - 1]:ends[idx - 1]] == "." \
                            and masked[starts[idx - 2]:ends[idx - 2]] == owner:
                        self.envs.append((idx - 2, idx))
                elif stack and word == "for":
                    flags[stack[-1]] |= 1
                elif stack and word == "if" and flags[stack[-1]] & 1:
                    flags[stack[-1]] |= 2
            elif c.isdigit():
                kinds.append(3)
            else:
                kinds.append(0)
                if c in "([{":
                    if len(stack) >= _ENV_MAX_DEPTH:
                        too_deep += 1          # left unpaired; its closer is skipped below
                    else:
                        stack.append(idx)
                elif c in closers and too_deep:
                    too_deep -= 1
                elif c in closers and stack and masked[starts[stack[-1]]] == closers[c]:
                    opener = stack.pop()
                    match[opener] = idx
                    match[idx] = opener
                    parent[idx] = parent[opener]
        self.starts, self.ends, self.kinds = starts, ends, kinds
        self.match, self.parent, self.flags = match, parent, flags
        self.count = len(starts)
        self.env_first = [e[0] for e in self.envs]
        self.need = {}
        self.group = {}

    def word(self, i):
        return self.masked[self.starts[i]:self.ends[i]]

    def is_name(self, i):
        return 0 <= i < self.count and self.kinds[i] == 1

    def is_punct(self, i, ch):
        return 0 <= i < self.count and self.kinds[i] == 0 and self.masked[self.starts[i]] == ch

    # ---- which call

    def callee(self, t):
        """(key, index of the name before the argument list) for a client call starting at name
        ``t``, or None. A constructor in the chain reads as ``Name()``. A dot is member access only
        when it touches the name: a sentence's full stop before a line of code is not one."""
        if t > 0 and self.is_punct(t - 1, ".") and self.starts[t - 1] + 1 == self.starts[t]:
            if not (t >= 2 and self.is_name(t - 2) and self.word(t - 2) in _GLOBALS):
                return None
        parts = [self.word(t)]
        j = t
        while True:
            if self.is_punct(j + 1, ".") and self.is_name(j + 2):
                parts.append(self.word(j + 2))
                j += 2
            elif self.is_punct(j + 1, "(") and parts[-1] in _CTORS and self.match[j + 1] != -1 \
                    and self.is_punct(self.match[j + 1] + 1, "."):
                parts[-1] += "()"
                j = self.match[j + 1]
            else:
                break
        if not self.is_punct(j + 1, "(") or self.match[j + 1] == -1:
            return None
        key = ".".join(parts)
        receiver, _, method = key.rpartition(".")
        if key in _BARE or (receiver in _RECEIVERS and method in _METHODS):
            return key, j
        return None

    def arguments(self, opener):
        """[(first token, end token)] for the top-level arguments between ``opener`` and its closer."""
        close = self.match[opener]
        out = []
        lo = opener + 1
        i = lo
        while i < close:
            if self.kinds[i] == 0:
                ch = self.masked[self.starts[i]]
                if ch in "([{" and self.match[i] != -1:
                    i = self.match[i] + 1
                    continue
                if ch == ",":
                    out.append((lo, i))
                    lo = i + 1
            i += 1
        out.append((lo, close))
        return out

    def dotted_before(self, o):
        """Start index and text of the dotted name written right before the bracket at ``o``."""
        j = o - 1
        if not self.is_name(j):
            return None
        while j >= 2 and self.is_punct(j - 1, ".") and self.is_name(j - 2):
            j -= 2
        return j, ".".join(self.word(k) for k in range(j, o, 2))

    # ---- does the whole environment reach the argument

    def _level(self, a, b, keys_view):
        """One step outward from the unit of tokens a..b: what is written after it, then the
        bracket around it. Returns ('stop', need) when something there selects (``need`` is the
        first token the argument must start at for that selection to count), ('root',) when no
        bracket is left, or ('up', start, close, keys_view) for the group the unit became."""
        while True:                            # methods and attributes written after the unit
            nxt = b + 1
            if self.is_punct(nxt, "["):
                return ("stop", a)
            if self.is_punct(nxt, ".") and self.is_name(nxt + 1):
                name = self.word(nxt + 1)
                if self.is_punct(nxt + 2, "(") and self.match[nxt + 2] != -1:
                    if name in _ENV_PICKS:
                        return ("stop", a)
                    if name in _ENV_COPIES:
                        keys_view = False
                    b = self.match[nxt + 2]
                    continue
                return ("stop", a)             # one named variable
            break
        o = self.parent[a]
        if o == -1:
            return ("root",)
        kind = self.word(o)
        close = self.match[o]
        flag = self.flags[o]
        if close == -1 or flag == 3:           # unclosed, or a comprehension with a condition
            return ("stop", o)
        if flag & 1 and keys_view:             # iterating names only
            return ("stop", o)
        start = o
        if kind == "(":
            found = self.dotted_before(o)
            if found is not None:
                start, name = found
                last = name.rpartition(".")[2]
                if name == "filter":
                    return ("stop", o)
                if name in _KEYS_NAMES or last == "keys":
                    if keys_view:
                        return ("stop", o)
                elif name in _PASS_NAMES or last in _PASS_LAST:
                    keys_view = False
                elif not (a == o + 1 and b == close - 1):
                    return ("stop", o)         # unknown function with other arguments
        elif kind == "[":
            if o > 0 and (self.kinds[o - 1] in (1, 2, 3) or self.is_punct(o - 1, ")")
                          or self.is_punct(o - 1, "]")):
                return ("stop", o)             # an index into something else
            keys_view = False
        else:
            keys_view = False
        return ("up", start, close, keys_view)

    def need_for(self, e):
        """For environment reference ``e``: None when the whole environment reaches the root of
        any argument unselected, else the token index ``need`` such that an argument starting at
        or before ``need`` sees a selection and one starting after it does not. Climbs are shared
        between references (memoised per bracket), so the cost is linear in the text."""
        if e in self.need:
            return self.need[e]
        a, b = self.envs[e]
        result = self._level(a, b, True)
        path = []
        while result[0] == "up":
            key = (result[1], result[3])
            if key in self.group:
                outcome = self.group[key]
                break
            path.append(key)
            result = self._level(result[1], result[2], result[3])
        else:
            outcome = result[1] if result[0] == "stop" else None
        for key in path:
            self.group[key] = outcome
        self.need[e] = outcome
        return outcome


_EVIDENCE_NOTE = "environment"


class EnvironmentToHttpClient:
    """GLS-STRUCT-002: source code hands the whole process environment to an HTTP client."""

    id = "GLS-STRUCT-002"
    name = "Code sends the whole process environment to an HTTP client"
    category = "exfiltration"
    severity = "high"
    channel = ["file", "code", "tool_output", "message", "web_content"]
    reads_channel = True
    description = ("Python or Node source in which the whole process environment is an argument "
                   "that an HTTP client call sends: every variable the process holds, including "
                   "tokens and keys, leaves the machine in one request.")
    _EXAMPLE = ("A call in a code block of a document that hands the whole process environment "
                "to an HTTP client. The text shows the call; this is a notice, not a verdict.")

    _CLIENT_WORDS = ("requests", "httpx", "aiohttp", "urllib", "axios", "fetch", "got", "urlopen")

    def pregate(self, text):
        if "environ" not in text and not ("process" in text and "env" in text):
            return False
        return any(word in text for word in self._CLIENT_WORDS)

    def run(self, text, channel="file"):
        findings = []
        for start, end, fenced in _fenced_segments(text, channel):
            segment = text[start:end]
            if "environ" not in segment and "env" not in segment:
                continue
            findings.extend(self._read(text, start, segment, fenced))
            if len(findings) >= _ENV_MAX_FINDINGS:
                break
        return findings[:_ENV_MAX_FINDINGS]

    def _mocks(self, reader):
        """{name: first position} of the places a client call is replaced by a double: the
        patch, spy, stub and assignment forms. A dotted name is kept under each of its dotted
        endings, so ``patch("pkg.requests.post")`` replaces ``requests.post``."""
        masked, seg = reader.masked, reader.seg
        found = {}
        if not any(word in masked for word in _MOCK_WORDS):
            return found

        def add(name, at):
            for prefix in ("global.", "globalThis.", "window.", "self."):
                if name.startswith(prefix):
                    name = name[len(prefix):]
            parts = name.split(".")
            for k in range(max(len(parts) - 1, 1)):
                ending = ".".join(parts[k:])
                found[ending] = min(at, found.get(ending, at))

        for m in _MOCK_PATCH.finditer(masked):
            add(_literal_text(seg[m.start(1):m.end(1)]), m.start())
        for m in _MOCK_PATCH_OBJECT.finditer(masked):
            target = m.group(1)
            name = _literal_text(seg[m.start(2):m.end(2)])
            add(name if target in ("global", "globalThis", "window") else target + "." + name, m.start())
        for m in _MOCK_SPY.finditer(masked):
            target = m.group(1)
            name = _literal_text(seg[m.start(2):m.end(2)])
            add(name if target in ("global", "globalThis", "window") else target + "." + name, m.start())
        for m in _MOCK_ASSIGN.finditer(masked):
            add(m.group(1), m.start())
        return found

    def _read(self, text, offset, segment, fenced):
        reader = _Reader(segment)
        if not reader.envs or not reader.calls:
            return []
        mocks = self._mocks(reader)
        findings = []
        for t in reader.calls:
            if len(findings) >= _ENV_MAX_FINDINGS:
                break
            hit = reader.callee(t)
            if hit is None:
                continue
            key, last = hit
            opener = last + 1
            close = reader.match[opener]
            k = bisect.bisect_right(reader.env_first, opener)
            if k >= len(reader.env_first) or reader.env_first[k] >= close:
                continue
            if mocks.get(key, len(segment)) < reader.starts[t]:
                continue
            method = key.rpartition(".")[2]
            receiver = key.rpartition(".")[0]
            if method == "request" and receiver not in ("axios", "got", "axios.create()", "got.extend()"):
                first_data, url_at = 2, 1
            elif key == "axios" or key == "axios.request" or method == "request" and "axios" in receiver:
                first_data, url_at = 0, -1
            else:
                first_data, url_at = 1, 0
            regions = []
            url_arg = None
            positional = 0
            for lo, hi in reader.arguments(opener):
                if lo >= hi:
                    continue
                if reader.is_name(lo) and reader.is_punct(lo + 1, "=") and not reader.is_punct(lo + 2, "="):
                    name = reader.word(lo)
                    if name in ("url", "fullurl"):
                        url_arg = (lo + 2, hi)
                    elif name in _DATA_KEYWORDS:
                        regions.append((lo + 2, hi, name))
                    continue
                if positional == url_at:
                    url_arg = (lo, hi)
                if positional >= first_data:
                    regions.append((lo, hi, "argument %d" % (positional + 1)))
                positional += 1
            if not regions:
                continue
            if url_arg is not None and url_arg[1] - url_arg[0] == 1:
                u = url_arg[0]
                begin = reader.starts[u]
                if reader.kinds[u] == 2 and reader.literals.get(begin) == reader.ends[u] \
                        and _is_local_url(_literal_text(segment[begin:reader.ends[u]])):
                    continue
            for lo, hi, label in regions:
                e = bisect.bisect_left(reader.env_first, lo)
                hit_at = None
                while e < len(reader.env_first) and reader.env_first[e] < hi:
                    need = reader.need_for(e)
                    if need is None or lo > need:
                        hit_at = reader.starts[reader.envs[e][0]]
                        break
                    e += 1
                if hit_at is not None:
                    findings.append(self._finding(text, offset, segment, reader.starts[t], key, label, fenced))
                    break
        return findings

    def _finding(self, text, offset, segment, at, key, label, fenced):
        line = text.count("\n", 0, offset + at) + 1
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "severity": "low" if fenced else self.severity,
            "channel": list(self.channel),
            "description": self._EXAMPLE if fenced else self.description,
            "matched_text": segment[at:at + 50],
            "structural": True,
            "evidence": {"call": key, "argument": label, "line": line,
                         "shape": "fenced_example" if fenced else "environment_to_client"},
        }


VALIDATORS = (HookFetchAndRun(), SettingsWithoutPrompts(), EnvironmentToHttpClient())
