"""Which other agents on this machine have MCP servers configured, read-only.

`doctor --agents` prints what this module returns. It opens a short fixed list of
config files, one per agent and scope, and reports each as present, absent or
UNREADABLE. It writes nothing, starts nothing and uses no network.

Three rules carry the whole module:

* Absent is a file that is not there (ENOENT) and nothing else. A file that is
  there and cannot be read, or is not what its format says, is UNREADABLE and says
  why. "Could not look" must never print as "nothing there".
* Nothing a config file holds for a server is shown except its name, how it is
  reached, the command's file name or the URL's host. `env`, `args` and `headers`
  values are never read into a row, so they cannot reach the output.
* A server's state is `install.classify`'s answer, the same one `doctor` gives for
  the Claude files: WRAPPED only for an entry that really runs this install's proxy.
* A file is read only when it resolves to a regular file inside the home folder or
  the project, and is opened without blocking, so a link out of those folders or a
  FIFO cannot make the list read or hang on something else.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import pathlib
import re
import stat
from urllib.parse import urlsplit

from .. import install as _install
from . import doctor as _doctor

try:  # Python 3.11 and newer; older versions have no TOML reader in the standard library
    import tomllib as _tomllib
except ImportError:  # pragma: no cover - exercised by setting the name to None in tests
    _tomllib = None

PRESENT = "present"
ABSENT = "absent"
UNREADABLE = "UNREADABLE"

DIRECT = "DIRECT"
UNVERIFIED = "UNVERIFIED"

MAX_BYTES = 1 << 20          # a config larger than this is reported, not parsed
MAX_SERVERS = 500            # servers listed per file; the rest are counted
_NAME_LIMIT = 80
_LEAVES = "a link that leaves the home folder and the project"

JSON = "json"
TOML = "toml"


def _files(home, cwd):
    """(agent, scope, label, path, format, key, key_required) for every file read.

    Locations are the ones each vendor's own documentation names. A tool whose
    documentation does not name a file is not on this list, and neither is a file
    that an older version of a page named and the current page does not.
    """
    return [
        ("claude-code", "user", "", home / ".claude.json", JSON, "mcpServers", True),
        ("claude-code", "project", "", cwd / ".mcp.json", JSON, "mcpServers", True),
        ("cursor", "user", "", home / ".cursor" / "mcp.json", JSON, "mcpServers", False),
        ("cursor", "project", "", cwd / ".cursor" / "mcp.json", JSON, "mcpServers", False),
        ("codex", "user", "", home / ".codex" / "config.toml", TOML, "mcp_servers", False),
        ("codex", "project", "", cwd / ".codex" / "config.toml", TOML, "mcp_servers", False),
        ("gemini-cli", "user", "", home / ".gemini" / "settings.json", JSON, "mcpServers", False),
        ("gemini-cli", "project", "", cwd / ".gemini" / "settings.json", JSON, "mcpServers", False),
        ("windsurf", "user", "editor discovery, stable",
         home / ".codeium" / "windsurf" / "mcp_config.json", JSON, "mcpServers", False),
        ("windsurf", "user", "editor discovery, next",
         home / ".codeium" / "windsurf-next" / "mcp_config.json", JSON, "mcpServers", False),
    ]


def _escape(ch):
    if ch.isprintable() or ch == " ":
        return ch
    return f"\\x{ord(ch):02x}" if ord(ch) < 0x100 else f"\\u{ord(ch):04x}"


def _safe(value, limit=_NAME_LIMIT):
    """Text from a config file is data: escape control characters, cap the length.

    A name cut to the limit ends in a short digest of the whole name, so two long
    names that share their first characters stay two different rows.
    """
    full = value if isinstance(value, str) else ""
    out = "".join(_escape(ch) for ch in full)
    if len(out) <= limit:
        return out
    tag = hashlib.sha1(full.encode("utf-8", "surrogatepass")).hexdigest()[:6]
    return out[:limit - 8] + "…~" + tag


def _shown(path, home, cwd, scope):
    """The path as a reader would type it: `./` for the project, `~/` for home."""
    order = ((home, "~/"), (cwd, "./")) if scope == "user" else ((cwd, "./"), (home, "~/"))
    for base, lead in order:
        try:
            return lead + path.relative_to(base).as_posix()
        except ValueError:
            continue
    return str(path)


def _inside(real, roots):
    """True when `real` lies under a root, by name or by being the same folder.

    The second test is for storage that ignores case: a link to `HOME/a.json` is the
    file under `home/` although the two names differ.
    """
    for root in roots:
        try:
            if os.path.commonpath([real, root]) == root:
                return True
        except ValueError:  # a different drive
            continue
    here = os.path.dirname(real)
    while True:
        for root in roots:
            try:
                if os.path.samefile(here, root):
                    return True
            except (OSError, ValueError):
                continue
        above = os.path.dirname(here)
        if above == here:
            return False
        here = above


def _os_reason(error):
    if isinstance(error, PermissionError):
        return "permission denied"
    if isinstance(error, IsADirectoryError):
        return "a folder, not a file"
    return "could not be opened"



def _open_flags():
    """Open flags this platform has: no blocking, no final link, binary, close-on-exec."""
    flags = 0
    try:
        flags |= os.O_NONBLOCK
    except AttributeError:
        pass
    try:
        flags |= os.O_NOFOLLOW
    except AttributeError:
        pass
    try:
        flags |= os.O_BINARY
    except AttributeError:
        pass
    try:
        flags |= os.O_CLOEXEC
    except AttributeError:
        pass
    return flags


_OPEN_FLAGS = _open_flags()

def _read(path, home, cwd):
    """(bytes, None, id), (None, "", None) for a file that is not there, or
    (None, reason, None). Absent is a missing file and nothing else.

    The path is resolved in full, every component, and must land inside the home
    folder or the project; it is then opened without following a final link and
    without blocking, and the descriptor, not the name, is checked to be a regular
    file before a byte is read.
    """
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None, "", None
    except (OSError, ValueError, RuntimeError) as error:
        return None, _os_reason(error), None
    linked = stat.S_ISLNK(info.st_mode)
    try:
        roots = [os.path.realpath(root) for root in (home, cwd)]
        real = os.path.realpath(path)
        if not _inside(real, roots):
            return None, _LEAVES, None
        target = os.stat(real)
    except FileNotFoundError:
        return None, ("a link whose target cannot be read" if linked else ""), None
    except (OSError, ValueError, RuntimeError) as error:
        return None, _os_reason(error), None
    if stat.S_ISDIR(target.st_mode):
        return None, "a folder, not a file", None
    if not stat.S_ISREG(target.st_mode):
        return None, "not a regular file", None
    flags = os.O_RDONLY | _OPEN_FLAGS
    try:
        fd = os.open(real, flags)
    except FileNotFoundError:
        return None, "", None
    except (OSError, ValueError) as error:
        return None, _os_reason(error), None
    try:
        handle = os.fdopen(fd, "rb")
    except OSError:
        os.close(fd)
        return None, "could not be opened", None
    with handle:
        try:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode):
                return None, "not a regular file", None
            if not os.path.samestat(target, opened):
                return None, "changed while it was being opened", None
            if os.path.realpath(path) != real:
                return None, "changed while it was being opened", None
            raw = handle.read(MAX_BYTES + 1)
        except (OSError, ValueError, RuntimeError) as error:
            return None, _os_reason(error), None
    if len(raw) > MAX_BYTES:
        return None, "larger than 1 MiB", None
    return raw, None, (target.st_dev, target.st_ino)


def _servers(doc, key, required, fmt):
    """(mapping, "") or (None, reason). A missing key is an empty mapping unless required."""
    if not isinstance(doc, dict):
        return None, "the top level is not an object" if fmt == JSON else "the top level is not a table"
    if key not in doc:
        if required:
            return None, f"no {key} object"
        return {}, ""
    found = doc[key]
    if not isinstance(found, dict):
        return None, f"{key} is not an object" if fmt == JSON else f"{key} is not a table"
    return found, ""


def _command_name(command):
    """The command's file name, or `?` when it cannot be told from the string alone.

    A command that holds a space, a quote or an `=` may be a path with a folder name in
    it or a value placed in front of the program, so nothing of it is shown. A path in
    either separator style is cut at its last component.
    """
    if not command or "=" in command or '"' in command or "'" in command \
            or any(ch.isspace() for ch in command):
        return "?"
    name = re.split(r"[\\/:]", command)[-1]
    return _safe(name) if name else "?"


def _state(spec, artifact):
    """`install.classify`'s answer, so this block and `doctor` never disagree."""
    try:
        return _install.classify(spec, artifact=artifact)
    except (TypeError, ValueError, AttributeError, OSError):
        return UNVERIFIED


_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\Z")


def _host(url):
    """The URL's host name when it is one, else `?`.

    The parser's hostname is not a check: it keeps a backslash, an encoded slash, an
    `=` or a space inside what it calls the host, it erases a tab or a line break
    before anything can look at it, and the secret a caller put there would be shown.
    So the raw authority is looked at first (no control character, no space), then
    each label is checked on its own: letters, digits and inner hyphens, 1 to 63
    characters, 253 in all. A name with other letters is shown in its ASCII (punycode)
    form. An IP literal in square brackets must parse as an address.
    """
    rest = url.split("//", 1)[1] if "//" in url else ""
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
    if any(ch == " " or not ch.isprintable() for ch in authority):
        return "?"
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
    except ValueError:
        return "?"
    if not host:
        return "?"
    if parts.netloc.rpartition("@")[2].startswith("["):
        if "%" in host:
            return "?"
        try:
            return str(ipaddress.IPv6Address(host))
        except ValueError:
            return "?"
    try:
        ascii_host = host if host.isascii() else host.encode("idna").decode("ascii")
    except UnicodeError:
        return "?"
    ascii_host = ascii_host.lower()
    if ascii_host.endswith("."):
        ascii_host = ascii_host[:-1]
    if not ascii_host or len(ascii_host) > 253:
        return "?"
    if not all(_LABEL.match(label) for label in ascii_host.split(".")):
        return "?"
    return ascii_host


def _server_row(name, spec, artifact):
    """One server: name, how it is reached, command file name or URL host. Nothing else."""
    row = {"name": _safe(name if isinstance(name, str) else str(name)),
           "transport": "unknown", "via": "", "state": _state(spec, artifact)}
    if not isinstance(spec, dict):
        return row
    command = spec.get("command")
    if isinstance(command, str) and command.strip():
        row["transport"] = "stdio"
        row["via"] = _command_name(command)
        return row
    for field in ("url", "httpUrl", "serverUrl"):
        url = spec.get(field)
        if isinstance(url, str) and url.strip():
            row["transport"] = "remote"
            row["via"] = _host(url)
            return row
    return row


def _tell_apart(rows):
    """Rows are in the order of their raw names; give two that print alike a number each.

    A control character and its escape, or two long names cut to the same digest, print
    the same. Numbering them in raw-name order keeps every row its own and the output
    the same on every run.
    """
    count = {}
    for row in rows:
        count[row["name"]] = count.get(row["name"], 0) + 1
    used = {row["name"] for row in rows if count[row["name"]] == 1}
    seen = {}
    for row in rows:
        shown = row["name"]
        if count[shown] == 1:
            continue
        number = seen.get(shown, 0)
        while True:
            number += 1
            candidate = f"{shown} #{number}"
            if candidate not in used:
                break
        seen[shown] = number
        used.add(candidate)
        row["name"] = candidate


def _row(agent, scope, label, path, home, cwd, fmt, key, required, artifact):
    """(row, id). The id is the file's device and inode, for telling two names of one file apart."""
    base = {"agent": agent, "scope": scope, "label": label,
            "path": _shown(path, home, cwd, scope), "state": ABSENT, "reason": "", "servers": []}
    raw, problem, ident = _read(path, home, cwd)
    if raw is None and problem == "":
        return base, None
    if raw is None:
        return {**base, "state": UNREADABLE, "reason": problem}, None
    if fmt == TOML:
        if _tomllib is None:
            return {**base, "state": UNREADABLE,
                    "reason": "toml parser unavailable on this Python"}, ident
        try:
            doc = _tomllib.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return {**base, "state": UNREADABLE, "reason": "not valid TOML"}, ident
        except RecursionError:
            return {**base, "state": UNREADABLE, "reason": "nested too deeply to read"}, ident
    else:
        try:
            doc = _install._parse(raw, path)
        except (OSError, _install.ConfigIOError):
            return {**base, "state": UNREADABLE,
                    "reason": "not valid JSON (comments are not accepted)"}, ident
        except RecursionError:
            return {**base, "state": UNREADABLE, "reason": "nested too deeply to read"}, ident
    servers, problem = _servers(doc, key, required, fmt)
    if servers is None:
        return {**base, "state": UNREADABLE, "reason": problem}, ident
    names = sorted(servers, key=lambda n: str(n))
    rows = [_server_row(n, servers[n], artifact) for n in names[:MAX_SERVERS]]
    _tell_apart(rows)
    rows.sort(key=lambda r: r["name"])
    reason = f"no {key} key" if key not in doc else ""
    if len(names) > MAX_SERVERS:
        reason = f"{len(names) - MAX_SERVERS} more servers not listed"
    return {**base, "state": PRESENT, "reason": reason, "servers": rows}, ident


def discover(home=None, cwd=None, artifact=None):
    """Every listed file, in a fixed order, each as one row."""
    home = pathlib.Path(home) if home is not None else pathlib.Path.home()
    cwd = pathlib.Path(cwd) if cwd is not None else pathlib.Path.cwd()
    artifact = artifact if artifact is not None else _doctor.artifact_path()[0]
    rows, seen, seen_ids = [], set(), set()
    for agent, scope, label, path, fmt, key, required in _files(home, cwd):
        # In the home folder the project file and the user file are one file.
        name = os.path.abspath(path)
        if name in seen:
            continue
        seen.add(name)
        row, ident = _row(agent, scope, label, path, home, cwd, fmt, key, required, artifact)
        # Two names for one file (a link, or a case difference) are one row.
        if ident is not None:
            if ident in seen_ids:
                continue
            seen_ids.add(ident)
        rows.append(row)
    rows.sort(key=lambda r: (r["agent"], r["scope"], r["path"]))
    return rows
