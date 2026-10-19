#!/usr/bin/env python3
"""Stamp stats/current.json with the time PyPI says a release was uploaded.

A release uploaded by the release workflow (Trusted Publishing) never ran the
local publish script, the only thing that used to write `last_updated`. So after
the upload `released` (set by the release PR) is ahead of `last_updated`, and the
site stamp gate, which requires the two dates to agree, stops on it. This writes
the two fields the workflow's upload could not:

    last_updated     the wheel's PyPI upload time, in Pacific time
    last_updated_by  "release.yml" (the uploader that actually ran)

    python3 scripts/stats_last_updated.py <version> [--root DIR] [--by NAME]
                                          [--wait SECONDS] [--pause SECONDS]

Exit codes
    0  stats/current.json was edited (exactly those two fields; the diff is the proof)
    3  nothing to do: the file already carries this upload time
    2  refused, nothing written: PyPI never listed a wheel for the version, the tree's
       stats `version` is not <version>, `released` is not the wheel's Pacific date,
       or the two fields are not present exactly once
    64 bad arguments

It edits the file in place and does nothing else: committing, pushing and opening
the pull request belong to the workflow job that calls it.
"""
from __future__ import annotations

import json
import re
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

PT = ZoneInfo("America/Los_Angeles")


def fetch_json(url):
    request = urllib.request.Request(url, headers={"User-Agent": "sunglasses-release-stats"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)


def wheel_upload(version, fetch=fetch_json):
    """(Pacific date, Pacific ISO time, UTC time) of the version's wheel on PyPI."""
    data = fetch(f"https://pypi.org/pypi/sunglasses/{version}/json")
    wheels = [u for u in data["urls"] if u.get("packagetype") == "bdist_wheel"]
    if not wheels:
        raise LookupError(f"PyPI lists no wheel for sunglasses {version}")
    raw = wheels[0]["upload_time_iso_8601"]
    utc = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    local = utc.astimezone(PT).replace(microsecond=0)
    return local.date().isoformat(), local.isoformat(), utc.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def wheel_upload_waiting(version, fetch=fetch_json, wait=300, pause=20, sleep=time.sleep):
    """PyPI can take a minute to serve a file it just accepted: retry, then give up."""
    deadline = time.monotonic() + wait
    while True:
        try:
            return wheel_upload(version, fetch)
        except Exception as error:  # network, 404 before propagation, no wheel yet
            if time.monotonic() >= deadline:
                raise LookupError(f"could not read the wheel upload time for {version} from PyPI: {error}")
            sleep(pause)


def stamp(root, version, by="release.yml", fetch=fetch_json, wait=300, pause=20, sleep=time.sleep):
    """Edit root/stats/current.json. Returns (code, message)."""
    path = Path(root) / "stats" / "current.json"
    try:
        pt_date, pt_iso, utc = wheel_upload_waiting(version, fetch, wait, pause, sleep)
    except LookupError as error:
        return 2, f"REFUSED: {error}"
    text = path.read_text(encoding="utf-8")
    current = json.loads(text)
    if current.get("version") != version:
        return 2, (f"REFUSED: stats/current.json says version {current.get('version')!r}, not {version}: "
                   "the release PR did not bump it")
    if current.get("released") != pt_date:
        return 2, (f"REFUSED: released {current.get('released')!r} is not the wheel's Pacific upload date "
                   f"{pt_date!r}; a last_updated edit would not satisfy the site stamp gate, so a person "
                   "has to look at `released`")
    if current.get("last_updated") == pt_iso and current.get("last_updated_by") == by:
        return 3, f"NOTHING TO DO: last_updated is already {pt_iso} by {by}"
    new = text
    for key, value in (("last_updated", pt_iso), ("last_updated_by", by)):
        pattern = re.compile(r'("%s":\s*)"[^"]*"' % key)
        if len(pattern.findall(new)) != 1:
            return 2, f'REFUSED: expected exactly one "{key}" in stats/current.json'
        new = pattern.sub(lambda m: f'{m.group(1)}"{value}"', new, count=1)
    json.loads(new)
    path.write_text(new, encoding="utf-8")
    return 0, f"last_updated {pt_iso} by {by} (wheel uploaded {utc})"


def main(argv, fetch=fetch_json):
    args = list(argv[1:])

    def option(name, default):
        if name in args:
            i = args.index(name)
            value = args[i + 1]
            del args[i:i + 2]
            return value
        return default

    try:
        root = option("--root", ".")
        by = option("--by", "release.yml")
        wait = int(option("--wait", "300"))
        pause = int(option("--pause", "20"))
    except (IndexError, ValueError):
        print(__doc__.split("\n\n")[0], file=sys.stderr)
        return 64
    if len(args) != 1 or not re.fullmatch(r"\d+\.\d+\.\d+", args[0]):
        print(__doc__.split("\n\n")[0], file=sys.stderr)
        return 64
    code, message = stamp(root, args[0], by, fetch, wait, pause)
    print(message)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
