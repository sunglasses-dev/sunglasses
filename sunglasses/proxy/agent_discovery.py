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
* A server found in another agent's file is DIRECT or UNVERIFIED. Only the Claude
  install marker can make an entry WRAPPED, and that path is `doctor`'s own report.
"""
from __future__ import annotations

import os
import pathlib
import stat
from urllib.parse import urlsplit

from .. import install as _install

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
_NAME_LIMIT = 80

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
    """Text from a config file is data: escape control characters, cap the length."""
    out = "".join(_escape(ch) for ch in (value if isinstance(value, str) else ""))
    return out if len(out) <= limit else out[:limit - 1] + "…"


def _shown(path, home, cwd, scope):
    """The path as a reader would type it: `./` for the project, `~/` for home."""
    order = ((home, "~/"), (cwd, "./")) if scope == "user" else ((cwd, "./"), (home, "~/"))
    for base, prefix in order:
        try:
            return prefix + path.relative_to(base).as_posix()
        except ValueError:
            continue
    return str(path)


def _under(path, base):
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False


def _read(path, home, cwd):
    """(bytes, "") or (None, reason). A missing file is (None, "") and only that."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None, ""
    except OSError as error:
        return None, _os_reason(error)
    if stat.S_ISLNK(info.st_mode):
        try:
            target = path.resolve(strict=True)
        except OSError:
            return None, "a link whose target cannot be read"
        roots = [r.resolve() for r in (home, cwd)]
        if not any(_under(target, root) for root in roots):
            return None, "a link that leaves the home folder and the project"
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_BYTES + 1)
    except FileNotFoundError:
        return None, ""
    except OSError as error:
        return None, _os_reason(error)
    if len(raw) > MAX_BYTES:
        return None, "larger than 1 MiB"
    return raw, None


def _os_reason(error):
    if isinstance(error, PermissionError):
        return "permission denied"
    if isinstance(error, IsADirectoryError):
        return "a folder, not a file"
    return "could not be opened"


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


def _server_row(name, spec):
    """One server: name, how it is reached, command file name or URL host. Nothing else."""
    row = {"name": _safe(name if isinstance(name, str) else str(name)),
           "transport": "unknown", "via": "", "state": UNVERIFIED}
    if not isinstance(spec, dict):
        return row
    command = spec.get("command")
    if isinstance(command, str) and command.strip():
        row["transport"] = "stdio"
        first = command.split()[0]
        # `KEY=value prog` puts a value in the command string: show no name rather than the value.
        row["via"] = "?" if "=" in first else _safe(os.path.basename(first))
        row["state"] = DIRECT
        return row
    for field in ("url", "httpUrl", "serverUrl"):
        url = spec.get(field)
        if isinstance(url, str) and url.strip():
            try:
                host = urlsplit(url).hostname or ""
            except ValueError:
                host = ""
            row["transport"] = "remote"
            row["via"] = _safe(host) if host else "?"
            row["state"] = DIRECT
            return row
    return row


def _row(agent, scope, label, path, home, cwd, fmt, key, required):
    base = {"agent": agent, "scope": scope, "label": label,
            "path": _shown(path, home, cwd, scope), "state": ABSENT, "reason": "", "servers": []}
    raw, problem = _read(path, home, cwd)
    if raw is None and problem == "":
        return base
    if raw is None:
        return {**base, "state": UNREADABLE, "reason": problem}
    if fmt == TOML:
        if _tomllib is None:
            return {**base, "state": UNREADABLE,
                    "reason": "toml parser unavailable on this Python"}
        try:
            doc = _tomllib.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return {**base, "state": UNREADABLE, "reason": "not valid TOML"}
    else:
        try:
            doc = _install._parse(raw, path)
        except (OSError, _install.ConfigIOError):
            return {**base, "state": UNREADABLE,
                    "reason": "not valid JSON (comments are not accepted)"}
    servers, problem = _servers(doc, key, required, fmt)
    if servers is None:
        return {**base, "state": UNREADABLE, "reason": problem}
    rows = [_server_row(name, spec) for name, spec in servers.items()]
    rows.sort(key=lambda r: r["name"])
    reason = f"no {key} key" if key not in doc else ""
    return {**base, "state": PRESENT, "reason": reason, "servers": rows}


def discover(home=None, cwd=None):
    """Every listed file, in a fixed order, each as one row."""
    home = pathlib.Path(home) if home is not None else pathlib.Path.home()
    cwd = pathlib.Path(cwd) if cwd is not None else pathlib.Path.cwd()
    rows, seen = [], set()
    for agent, scope, label, path, fmt, key, required in _files(home, cwd):
        # In the home folder the project file and the user file are one file.
        identity = os.path.abspath(path)
        if identity in seen:
            continue
        seen.add(identity)
        rows.append(_row(agent, scope, label, path, home, cwd, fmt, key, required))
    rows.sort(key=lambda r: (r["agent"], r["scope"], r["path"]))
    return rows
