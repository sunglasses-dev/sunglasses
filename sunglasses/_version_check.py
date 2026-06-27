# SUNGLASSES version check — Path B
#
# What this module does:
#   - On package import, checks https://sunglasses.dev/version.json ONCE per 24h
#   - Compares local __version__ to latest
#   - Prints a yellow warning if 1-14 days stale, red error if 30+ days stale
#   - Caches the result at ~/.sunglasses/last_version_check.json
#   - 1-second network timeout — never blocks if site is unreachable
#   - Opt-out via env var SUNGLASSES_NO_VERSION_CHECK=1 OR config
#
# What this module does NOT:
#   - Never sends user data (GET only, no payload)
#   - Never auto-updates anything
#   - Never phones home beyond the single static file read

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

VERSION_URL = "https://sunglasses.dev/version.json"
CACHE_DIR = Path.home() / ".sunglasses"
CACHE_FILE = CACHE_DIR / "last_version_check.json"
CONFIG_FILE = CACHE_DIR / "config.toml"
CHECK_INTERVAL_SECONDS = 24 * 60 * 60
NETWORK_TIMEOUT_SECONDS = 1.0
STALE_WARN_DAYS = 14
STALE_ERROR_DAYS = 30

YELLOW = "\033[93m"
RED = "\033[91m"
DIM = "\033[2m"
RESET = "\033[0m"


def _is_disabled() -> bool:
    if os.environ.get("SUNGLASSES_NO_VERSION_CHECK") in ("1", "true", "yes"):
        return True
    if CONFIG_FILE.exists():
        try:
            text = CONFIG_FILE.read_text()
            if "[version_check]" in text and "enabled = false" in text:
                return True
        except OSError:
            pass
    return False


def _read_cache() -> dict | None:
    try:
        return json.loads(CACHE_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _write_cache(data: dict) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(data))
    except OSError:
        pass


def _parse_semver(v: str) -> tuple[int, int, int]:
    parts = v.strip().lstrip("v").split(".")
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except (IndexError, ValueError):
        return (0, 0, 0)


def _fetch_latest() -> dict | None:
    req = Request(VERSION_URL, headers={"User-Agent": "sunglasses/version-check"})
    try:
        with urlopen(req, timeout=NETWORK_TIMEOUT_SECONDS) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body)
    except (URLError, json.JSONDecodeError, OSError, TimeoutError):
        return None


def _days_since_release(released_iso: str) -> int | None:
    try:
        released = datetime.fromisoformat(released_iso.replace("Z", "+00:00"))
        if released.tzinfo is None:
            released = released.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - released
        return delta.days
    except (ValueError, TypeError):
        return None


def _print_warning(local: str, latest: str, days_stale: int | None, patterns: int | None) -> None:
    local_v = _parse_semver(local)
    latest_v = _parse_semver(latest)
    if local_v >= latest_v:
        return

    is_error = days_stale is not None and days_stale >= STALE_ERROR_DAYS
    color = RED if is_error else YELLOW
    label = "Stale filter" if is_error else "Heads up"
    icon = "!" if is_error else "⚠"

    lines = [
        f"{color}{icon} Sunglasses {label}: v{latest} is available (you have v{local}).{RESET}",
    ]
    if patterns:
        lines.append(f"{color}  Latest pattern DB: {patterns} patterns.{RESET}")
    if days_stale is not None and days_stale > 0:
        lines.append(f"{color}  Your filter is {days_stale} days behind the current release.{RESET}")
    lines.append(f"{color}  Run: pip install --upgrade sunglasses{RESET}")
    lines.append(f"{DIM}  (Disable this check: SUNGLASSES_NO_VERSION_CHECK=1){RESET}")

    for line in lines:
        print(line, file=sys.stderr)


def _needs_check_now() -> bool:
    cache = _read_cache()
    if cache is None:
        return True
    try:
        last = float(cache.get("checked_at", 0))
    except (TypeError, ValueError):
        return True
    return (time.time() - last) >= CHECK_INTERVAL_SECONDS


def check_version(local_version: str, force: bool = False) -> None:
    """Run the version check. Called once per 24h from __init__.

    Silent if:
      - SUNGLASSES_NO_VERSION_CHECK=1
      - Config file disables it
      - Within the 24h cache window
      - Network unreachable (never blocks)
      - Local version >= remote latest
    """
    if _is_disabled():
        return

    if not force and not _needs_check_now():
        return

    remote = _fetch_latest()
    if remote is None:
        # Network failure or parse failure — silently ignore. Sunglasses must never break on this.
        _write_cache({"checked_at": time.time(), "status": "unreachable"})
        return

    latest = remote.get("latest", "")
    released = remote.get("released", "")
    patterns = remote.get("pattern_count")
    days_stale = _days_since_release(released) if released else None

    _write_cache({
        "checked_at": time.time(),
        "latest_seen": latest,
        "released": released,
        "pattern_count": patterns,
    })

    _print_warning(local_version, latest, days_stale, patterns)


def run_cli_version_check(local_version: str) -> int:
    """Explicit check invoked by `sunglasses version` CLI command. Always runs, bypasses 24h cache."""
    print(f"Sunglasses v{local_version}")
    if _is_disabled():
        print("(version check disabled via env var or config)")
        return 0
    remote = _fetch_latest()
    if remote is None:
        print("Could not reach https://sunglasses.dev/version.json (offline or unreachable).")
        print("Filter still works normally — the version check is optional.")
        return 0
    latest = remote.get("latest", "")
    released = remote.get("released", "")
    patterns = remote.get("pattern_count")
    days_stale = _days_since_release(released) if released else None
    _write_cache({
        "checked_at": time.time(),
        "latest_seen": latest,
        "released": released,
        "pattern_count": patterns,
    })
    local_v = _parse_semver(local_version)
    latest_v = _parse_semver(latest)
    if local_v >= latest_v:
        print(f"You are up to date (latest: v{latest}, released {released}).")
        return 0
    _print_warning(local_version, latest, days_stale, patterns)
    return 1
