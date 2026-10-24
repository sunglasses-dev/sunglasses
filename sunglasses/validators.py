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

import ipaddress
import json
import re
import urllib.parse

__all__ = ["CredentialFileUpload", "HookFetchAndRun", "SettingsWithoutPrompts", "VALIDATORS", "classify_command"]

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


class _TooDeep(_Syntax):
    """Quotes and substitutions nested deeper than the reader follows; the text itself is valid."""


_MAX_QUOTE_DEPTH = 200


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


def _skip_double_quote(s, i, depth=0):
    """Index just after the double-quoted string that opens at ``s[i]``."""
    if depth > _MAX_QUOTE_DEPTH:
        raise _TooDeep
    n = len(s)
    j = i + 1
    while j < n:
        c = s[j]
        if c == "\\":
            j += 2
        elif c == '"':
            return j + 1
        elif c == "$" and s.startswith("$(", j):
            j = _balanced(s, j + 1, depth + 1)
        elif c == "`":
            j = _closing_backtick(s, j) + 1
        else:
            j += 1
    raise _Syntax


def _balanced(s, i, nesting=0):
    """Index just after the ``)`` that closes the ``(`` at ``s[i]``."""
    if nesting > _MAX_QUOTE_DEPTH:
        raise _TooDeep
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
            pos = _skip_double_quote(s, at, nesting + 1)
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


def _lex(cmd, sink=None):
    """Split a command line into word / ps / redir / op tokens.

    With ``sink`` (a list) the tokens are appended to it as they are read, so a caller that
    catches the error still holds every token before the word that could not be read."""
    toks = [] if sink is None else sink
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


# ------------------------------------------------------------------------- upload side

# A credential file is named by its own file name, never by a directory above it. The words
# below are whole tokens of that name (split at `.`, `_` and `-`), so `secretsauce` is not one.
_CREDENTIAL_TOKENS = frozenset(("credential", "credentials", "secret", "secrets", "apikey", "apikeys"))
_CREDENTIAL_PAIRS = frozenset((("api", "key"), ("api", "keys"), ("private", "key"), ("private", "keys")))
_PRIVATE_KEYS = frozenset(("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk"))
_CREDENTIAL_FILES = frozenset((".netrc", "_netrc", ".pgpass", ".npmrc", ".pypirc", ".dockercfg", ".htpasswd"))
_KEY_EXTENSIONS = frozenset(("key", "p12", "pfx", "ppk", "jks", "keystore"))
_PEM_WORDS = frozenset(("private", "priv", "privkey", "key", "secret"))
# A name that says it is a document or a stand-in. `test`, `local`, `prod`, `live` and
# `backup` are not here: `.env.test` can hold working credentials.
_PUBLIC_TOKENS = frozenset((
    "example", "examples", "sample", "samples", "template", "templates", "fixture", "fixtures",
    "schema", "schemas", "reference", "manual", "doc", "docs", "documentation", "mock", "mocks",
    "public", "report", "reports", "audit", "audits", "release", "releases", "final", "spec", "specs",
    "guide", "guides", "manuals", "references", "dist", "document", "documents"))
# The stand-in words that clear a key or certificate file: a narrower list, because `release.key`
# and `final.key` can be the real signing key.
_STANDIN_TOKENS = frozenset((
    "example", "examples", "sample", "samples", "template", "templates", "fixture", "fixtures",
    "mock", "mocks", "public"))
# A public word followed by one of these still names a working file: `.env.example.local`.
_LIVE_TOKENS = frozenset(("test", "local", "prod", "production", "live", "backup", "dev", "staging"))
_DOCUMENT_EXTENSIONS = frozenset(("md", "markdown", "rst", "adoc", "html", "htm"))
_READERS = frozenset(("cat", "tac", "head", "tail", "base64", "gzip", "bzip2", "xz", "zstd", "xxd", "od",
                      "strings", "openssl"))
_DOC_MARKER = re.compile(
    r"\b(?:never|do not|don't|dont|must not|forbidden|avoid|unsafe|insecure|wrong|dangerous|example)\b", re.I)
_UPLOAD_NAME = re.compile(r"curl|wget")
_FORM_FILE = re.compile(r"[^=]*=([@<])([^;]*)")
_URLENCODE_FILE = re.compile(r"[^=@]*@(.*)\Z", re.S)
_PROSE_END = (":", ".", ",", ";", "!")
_MAX_UPLOAD_FINDINGS = 50
_CREDENTIAL_HINTS = ("env", "cred", "secret", "key", "id_", "netrc", "pgpass", "npmrc", "pypirc",
                     "dockercfg", "htpasswd", "pem", "p12", "pfx", "ppk", "jks")


def _says_public(tokens, words=_PUBLIC_TOKENS):
    """A public word in the name, with no live word after it."""
    for index, token in enumerate(tokens):
        if token in words:
            return not any(later in _LIVE_TOKENS for later in tokens[index + 1:])
    return False


def _credential_name(path):
    """Is the file's own name that of a credential file, and not of a document about one?"""
    base = path.rstrip("/").rsplit("/", 1)[-1].lower()
    if not base or base in (".", ".."):
        return False
    tokens = [t for t in re.split(r"[._\-\s]+", base) if t]
    if not tokens:
        return False
    stem, dot, ext = base.rpartition(".")
    ext = ext if dot and stem else ""
    environment = base == ".env" or base.startswith(".env.") or (ext == "env" and stem)
    if environment:
        return not _says_public(tokens)
    if base in _PRIVATE_KEYS or base in _CREDENTIAL_FILES:
        return True
    if ext in _KEY_EXTENSIONS:
        return not _says_public(tokens, _STANDIN_TOKENS)
    if ext == "pem":
        named = any(t in _PEM_WORDS for t in tokens) or base.startswith("id_")
        return named and not _says_public(tokens, _STANDIN_TOKENS)
    named = any(t in _CREDENTIAL_TOKENS for t in tokens) \
        or any(pair in _CREDENTIAL_PAIRS for pair in zip(tokens, tokens[1:]))
    if not named:
        return False
    if ext in _DOCUMENT_EXTENSIONS:
        return False
    return not _says_public(tokens)


def _upload_operands(program, args):
    """[(kind, value)] for the words of a curl / wget command that carry the payload.

    kind is "file" (a file named by the word), "stdin" (`@-` or `-` read from standard input)
    or "subst" (the body of a substitution inside a data word). `--data-raw` takes its text
    literally, so an `@` there names nothing; a substitution in it is still expanded first."""
    curl = program == "curl"
    out = []
    long_value = _CURL_LONG_VALUE if curl else _WGET_LONG_VALUE
    short_value = _CURL_SHORT_VALUE if curl else _WGET_SHORT_VALUE
    data_long = ("--data", "--data-ascii", "--data-binary", "--data-raw", "--json", "--data-urlencode")
    file_long = ("--upload-file",) if curl else ("--post-file", "--body-file")

    def operand(name, value, word):
        if name in file_long or name == "-T":
            out.append(("stdin", None) if value == "-" and curl else ("file", value))
        elif name in ("--form", "-F"):
            match = _FORM_FILE.match(value)
            if match:
                out.append(("stdin", None) if match.group(2) == "-" else ("file", match.group(2)))
        elif name == "--data-urlencode":
            match = _URLENCODE_FILE.match(value)
            if match:
                out.append(("stdin", None) if match.group(1) == "-" else ("file", match.group(1)))
        elif name != "--data-raw" and name in data_long + ("-d",) and value.startswith("@"):
            out.append(("stdin", None) if value == "@-" else ("file", value[1:]))
        if name in data_long or name in ("-d", "-F", "--form"):
            for body in word.subs:
                out.append(("subst", body))

    i = 0
    n = len(args)
    while i < n:
        arg = args[i]
        i += 1
        if arg.kind != "w":
            continue
        value = arg.value
        if value == "--":
            break
        if value.startswith("--") and len(value) > 2:
            name, eq, rest = value.partition("=")
            if name in data_long + ("--form",) + file_long and (curl or name in file_long):
                if eq:
                    operand(name, rest, arg)
                elif i < n and args[i].kind == "w":
                    operand(name, args[i].value, args[i])
                    i += 1
            elif name in long_value and not eq:
                i += 1
            continue
        if curl and len(value) > 1 and value[0] == "-":
            j = 1
            while j < len(value):
                ch = value[j]
                if ch in short_value:
                    rest = value[j + 1:]
                    if ch in "dFT":
                        if rest:
                            operand("-" + ch, rest, arg)
                        elif i < n and args[i].kind == "w":
                            operand("-" + ch, args[i].value, args[i])
                            i += 1
                    elif not rest:
                        i += 1
                    break
                j += 1
    return out


def _dumps_environment(words):
    """`env` or `printenv` alone (options allowed): the whole environment goes to the output.
    `env` is also a wrapper word, so a command that holds no program is looked at here."""
    if not words or words[0].kind != "w" or _base(words[0].value) not in ("env", "printenv"):
        return False
    return all(w.kind == "w" and w.value.startswith("-") for w in words[1:])


_UPLOADERS = ("curl", "wget")
# Programs that pass what they read on standard input along, changed: a credential file
# piped through one of them still reaches the next stage.
_FILTERS = frozenset(("tr", "sed", "awk", "cut", "grep", "egrep", "fgrep", "sort", "uniq", "tee", "rev",
                      "fold", "nl", "column", "expand", "unexpand"))
_PRODUCERS = _READERS | _FILTERS | frozenset(("env", "printenv"))
# Programs that run the text they are given as a command.
_WRAPPERS = _SHELLS | frozenset(("eval",))
# The first operand of these is the pattern or script, unless an option gave it; the letters
# are the options that give it.
_PATTERN_LETTERS = {"grep": "ef", "egrep": "ef", "fgrep": "ef", "sed": "ef",
                    "awk": "f", "gawk": "f", "mawk": "f"}
_PATTERN_LONGS = ("--regexp", "--file", "--expression", "--source")
# Words that mark the command after them as something not to run.
_MARKER_WORDS = frozenset(("never", "not", "don't", "dont", "forbidden", "avoid", "unsafe", "insecure",
                           "wrong", "dangerous", "example"))
_MARKER_STRIP = " \t.,;:!?()[]'\"*_`"


def _file_operands(name, args):
    """The words of a reader or filter that name an input file: the values of its options are
    not inputs, and the first operand of grep, sed and awk is the pattern or script unless
    `-e`, `-f` or a long form of them gave it. `tr` takes no file; `-` is standard input."""
    if name == "tr":
        return []
    known = _FILTER_VALUE_OPTIONS.get(name)
    letters = _PATTERN_LETTERS.get(name, "")
    given = False
    out = []
    skip = 0
    ended = False
    for arg in args:
        if arg.kind != "w":
            skip = 0
            continue
        value = arg.value
        if skip:
            skip -= 1
            continue
        if not ended and value == "--":
            ended = True
            continue
        if not ended and value.startswith("-") and value != "-":
            if letters:
                if value.startswith("--"):
                    option = value.partition("=")[0]
                    given = given or (len(option) > 2 and any(c.startswith(option) for c in _PATTERN_LONGS))
                elif known is not None:
                    for ch in value[1:]:
                        if ch in known[0]:
                            given = given or ch in letters
                            break
            skip = (_option_takes_next_word(value, known) if known is not None
                    else _unlisted_option_takes_next_word(value))
            continue
        out.append(value)
    if name in _PATTERN_LETTERS and not given and out:
        out = out[1:]
    if name == "openssl" and out:
        out = out[1:]
    return out


def _marks(word):
    return word.kind == "w" and word.value.strip(_MARKER_STRIP).lower() in _MARKER_WORDS


def _locate(words, names):
    """(program word, argument words) of the first command among ``names`` that a segment
    starts: its own program, or one that follows prose or a prompt on the same line
    (`Run this: curl ...`, `$ curl ...`, `Never curl ...`)."""
    located = _program(words)
    if located is not None and _base(located[0].value) in names:
        return located
    for k in range(1, len(words)):
        prev, word = words[k - 1], words[k]
        if prev.kind != "w" or word.kind != "w":
            continue
        if not (prev.value.endswith(_PROSE_END) or prev.value == "$" or _marks(prev)):
            continue
        if _base(word.value) in names:
            inner = _program(words[k:])
            if inner is not None and _base(inner[0].value) in names:
                return inner
    return None


def _warned(words, stop=None):
    """Does a word of warning stand among ``words`` (before ``stop``)? Two plain words together
    count (`do not`); a word that holds a substitution also holds the command inside it, whose
    own words are not a warning about it."""
    prev = ""
    for word in words:
        if word is stop:
            return False
        if word.kind != "w" or word.subs:
            prev = ""
            continue
        if _DOC_MARKER.search(word.value) or _DOC_MARKER.search(prev + " " + word.value):
            return True
        prev = word.value
    return False


def _output_of(segment, stdin):
    """What the segment writes to the pipe: "file" (a credential file), "environment" or None."""
    if _stdout_redirects(segment):
        return None
    if _dumps_environment(segment.words):
        return "environment"
    located = _locate(segment.words, _PRODUCERS)
    if located is None:
        return stdin if not segment.words else None
    head, args = located
    name = _base(head.value)
    if _informational(name, args):
        return None
    if name in ("env", "printenv"):
        named = [a for a in args if a.kind == "w" and not a.value.startswith("-") and not a.value.isdigit()]
        return None if named else "environment"
    if name == "tee":
        return stdin
    operands = _file_operands(name, args)
    if any(o != "-" and _credential_name(o) for o in operands):
        return "file"
    return stdin if not operands or "-" in operands else None


def _flows(segments):
    """(inputs, outputs): for each segment what its standard input carries and what it writes to
    the pipe, each "file", "environment" or None. One pass forward, so a source reaches an
    uploader through any number of filters; a redirection replaces the pipe, and a producer
    with a file of its own does not pass the pipe on."""
    ins = []
    outs = []
    carried = None
    for segment in segments:
        redirect = _stdin_redirect(segment)
        if redirect is not None:
            op, target = redirect
            stdin = "file" if (op == "<" and target is not None and target.kind == "w"
                               and _credential_name(target.value)) else None
        elif segment.sep_before in ("|", "|&"):
            stdin = carried
        else:
            stdin = None
        ins.append(stdin)
        carried = _output_of(segment, stdin)
        outs.append(carried)
    return ins, outs


def _substitution_reads(body, depth):
    """What the output of a substitution body carries; bodies nest to the same depth as commands."""
    if depth > _MAX_NESTED_COMMANDS:
        return None
    try:
        segments = _segments(_lex(body))
        ins, outs = _flows(segments)
        for index, segment in enumerate(segments):
            if segment.sep_after not in ("|", "|&") and outs[index]:
                return outs[index]
            for word in segment.words:
                if word.kind == "w":
                    for inner in word.subs:
                        found = _substitution_reads(inner, depth + 1)
                        if found:
                            return found
    except (_Syntax, RecursionError):
        return None
    return None


class _Findings(list):
    """The findings of one run; ``unread`` is true when part of the text could not be read."""

    unread = False


class _Scan:
    """Budget and state of one run: at most ``_MAX_UPLOAD_FINDINGS`` of each kind (a block, a
    notice), so a pile of notices never hides a block, and each finding once per line."""

    def __init__(self, soft):
        self.soft = soft
        self.fenced = False
        self.line = ""
        self.unread = False
        self.left = {False: _MAX_UPLOAD_FINDINGS, True: _MAX_UPLOAD_FINDINGS}
        self.seen = set()
        self.found = []

    def done(self):
        return not (self.left[False] or self.left[True])

    def add(self, evidence, marked):
        low = self.fenced or (self.soft and marked)
        if not self.left[low]:
            return
        key = (self.line, low, tuple(sorted(evidence.items())))
        if key in self.seen:
            return
        self.seen.add(key)
        self.left[low] -= 1
        self.found.append((evidence, low))


def _upload_evidence(stdin, name, args, depth, scan):
    for kind, value in _upload_operands(name, args):
        if scan.done():
            return
        if kind == "file":
            if _credential_name(value):
                yield {"program": name, "carrier": "file operand", "source": "file",
                       "file": value.rstrip("/").rsplit("/", 1)[-1][:60]}
        elif kind == "stdin":
            if stdin:
                yield {"program": name, "carrier": "standard input", "source": stdin}
        elif kind == "subst":
            source = _substitution_reads(value, depth + 1)
            if source:
                yield {"program": name, "carrier": "read substitution", "source": source}


def _scan_tokens(toks, depth, marked, scan):
    try:
        segments = _segments(toks)
        ins, _ = _flows(segments)
        carry = False       # a warning stands across a parenthesis and along a pipeline
        for index, segment in enumerate(segments):
            if scan.done():
                return
            words = segment.words
            marked_here = marked or carry
            carry = (marked_here or _warned(words)) \
                if segment.sep_after in ("(", ")", "|", "|&") else False
            started = _locate(words, _UPLOADERS)
            if started is not None:
                here = marked_here or _warned(words, started[0])
                for evidence in _upload_evidence(ins[index], _base(started[0].value), started[1], depth, scan):
                    scan.add(evidence, here)
            if depth < _MAX_NESTED_COMMANDS:
                seen = marked_here
                prev = ""
                for word in words:
                    if word.kind != "w":
                        prev = ""
                        continue
                    for body in word.subs:
                        _scan_upload_text(body, depth + 1, seen, scan)
                    if word.subs:
                        prev = ""
                    else:
                        seen = seen or bool(_DOC_MARKER.search(word.value)
                                            or _DOC_MARKER.search(prev + " " + word.value))
                        prev = word.value
                located = _locate(words, _WRAPPERS)
                if located is not None:
                    head, args = located
                    here = marked_here or _warned(words, head)
                    name = _base(head.value)
                    if name in _SHELLS:
                        run = _run_shell(args)
                        if run.mode == "inline" and run.inline is not None and run.inline.kind == "w":
                            _scan_upload_text(run.inline.value, depth + 1, here, scan)
                    elif name == "eval":
                        joined = " ".join(a.value for a in args if a.kind == "w")
                        if joined:
                            _scan_upload_text(joined, depth + 1, here, scan)
    except RecursionError:
        return


def _has_uploader(toks):
    return any(t.kind == "w" and _base(t.value) in _UPLOADERS for t in toks)


def _scan_upload_text(line, depth, marked, scan):
    """Scan one logical line. Words read before a quote that cannot be read still count; a line
    whose reading failed before its first curl or wget is read again from there. Text that is
    valid but nested deeper than the reader follows sets ``scan.unread``."""
    sink = []
    try:
        toks = _lex(line, sink)
        failed = False
    except _TooDeep:
        scan.unread = True
        toks, failed = sink, True
    except (_Syntax, RecursionError):
        toks, failed = sink, True
    _scan_tokens(toks, depth, marked, scan)
    if not failed or _has_uploader(toks):
        return
    match = _UPLOAD_NAME.search(line)
    if match is None:
        return
    rest = []
    try:
        _lex(line[match.start():], rest)
    except _TooDeep:
        scan.unread = True
    except (_Syntax, RecursionError):
        pass
    _scan_tokens(rest, depth, marked or bool(_DOC_MARKER.search(line[:match.start()])), scan)


def _logical_lines(text):
    """The commands of a text as the shell reads lines: a backslash before the line break joins
    the next line with nothing between, and a line that ends in a pipe or `&&` / `||` continues
    on the next. List-accumulated, so the cost stays linear."""
    lines = []
    parts = []
    for physical in text.split("\n"):
        stripped = physical[:-1] if physical.endswith("\r") else physical
        if (len(stripped) - len(stripped.rstrip("\\"))) % 2:
            parts.append(stripped[:-1])
            continue
        parts.append(stripped)
        if stripped.rstrip(" \t").endswith(("|", "&&", "||")):
            parts.append(" ")
            continue
        lines.append("".join(parts))
        parts = []
    if parts:
        lines.append("".join(parts))
    return lines


def _plain(text):
    """The text with quotes and backslashes removed: a name written as `c"u"rl` or `cu\\rl` still
    holds `curl`."""
    return text.replace("\\\r\n", "").replace("\\\n", "").replace("'", "").replace('"', "").replace("\\", "")


_CODE_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})([^\n]*)$", re.M)
_FENCE_LEAD = re.compile(r"^ {0,3}(?:`{3,}|~{3,})[ \t]*", re.M)
# A fence, or a word of warning before the command, marks documentation only where a person
# wrote it. A tool result and a fetched page are what an attacker hands the agent, and the
# marker costs a few characters there.
_NOTICE_CHANNELS = ("file", "message")


def _upload_segments(text, channel):
    """[(segment, fenced)]: a real code fence (three or more backticks or tildes opening a line,
    closed by the same character) of a prose text is its own segment, so the fence lines are never
    read as part of a command and the words after the opening ticks (the info string) are read as
    ordinary text; it is `fenced` (a notice) only in a `file` or `message` text. The `code`
    channel is source and is never split; an opening fence is cut from the front of its line."""
    if "```" not in text and "~~~" not in text:
        return [(text, False)]
    if channel == "code":
        return [(_FENCE_LEAD.sub("", text), False)]
    softened = channel in _NOTICE_CHANNELS
    out = []
    cursor = 0
    opened = None
    for m in _CODE_FENCE.finditer(text):
        ticks, info = m.group(1), m.group(2)
        if opened is None:
            if ticks[0] == "`" and "`" in info:
                continue
            opened = (ticks[0], len(ticks), min(m.end() + 1, len(text)))
            out.append((text[cursor:m.start()], False))
            out.append((info, False))
        elif ticks[0] == opened[0] and len(ticks) >= opened[1] and not info.strip():
            out.append((text[opened[2]:m.start()], softened))
            cursor = min(m.end() + 1, len(text))
            opened = None
    out.append((text[cursor:], False) if opened is None else (text[opened[2]:], softened))
    return out


class CredentialFileUpload:
    """GLS-STRUCT-003: a curl or wget command sends a credential file or the whole environment."""

    id = "GLS-STRUCT-003"
    name = "Command uploads a credential file"
    category = "exfiltration"
    severity = "high"
    channel = ["message", "file", "code", "tool_output", "web_content"]
    description = ("A curl or wget command in this text reads as one that sends a credential file, "
                   "or the whole environment, to a remote address: the payload word names the file, "
                   "reads standard input that carries it through any number of filters, or takes it "
                   "from a substitution. In a file or message text, a command that follows a warning "
                   "word or sits inside a fenced block is a notice, not a verdict.")

    def pregate(self, text):
        plain = _plain(text)
        if "curl" not in plain and "wget" not in plain:
            return False
        lowered = plain.lower()
        return any(hint in lowered for hint in _CREDENTIAL_HINTS)

    reads_channel = True

    def run(self, text, channel="file"):
        scan = _Scan(channel in _NOTICE_CHANNELS)
        for segment, fenced in _upload_segments(text, channel):
            scan.fenced = fenced
            for line in _logical_lines(segment):
                if scan.done():
                    break
                plain = _plain(line)
                if "curl" not in plain and "wget" not in plain:
                    continue
                scan.line = line
                _scan_upload_text(line, 0, False, scan)
            if scan.done():
                break
        findings = _Findings()
        findings.unread = scan.unread
        for evidence, low in scan.found:
            label = evidence["program"] + " " + evidence["carrier"]
            findings.append({
                "id": self.id,
                "name": self.name,
                "category": self.category,
                "severity": "low" if low else self.severity,
                "channel": list(self.channel),
                "description": self.description,
                "matched_text": label[:50],
                "structural": True,
                "evidence": evidence,
            })
        return findings


VALIDATORS = (HookFetchAndRun(), SettingsWithoutPrompts(), CredentialFileUpload())
