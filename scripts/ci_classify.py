#!/usr/bin/env python3
"""
CI change classifier — decides whether a pull request needs the FULL
pattern-integrity matrix or may merge on the fast lane alone.

Fail-closed by construction (ASTRA review, 2026-09-10, F1/F3):
  * The default answer is FULL. Only an affirmative "every changed path is
    documentation" verdict yields docs-only.
  * Any error — git failure, unresolved base/head, empty change list,
    unparseable status line, unknown file type — yields FULL.
  * Renames contribute BOTH the old and the new path; either being code
    yields FULL.
  * The complete change list is read from git, not from GitHub's path
    filter (which only inspects a bounded window of changed files).

Documentation allowance — anything not matched here is code:
  * root:   README.md SECURITY.md CONTRIBUTING.md CHANGELOG.md CODE_OF_CONDUCT.md
            KNOWN_VERSION_GAPS.md V056_ACCEPTANCE_MATRIX.md LICENSE
  * docs/** but ONLY *.md files (docs/reader.py is code)
  * .github/ISSUE_TEMPLATE/*.yml | *.md   and   .github/PULL_REQUEST_TEMPLATE.md
  CODEOWNERS, demo/, sunglasses/, tests/, workflows, anything else → FULL.

stdlib only. Usage:
  ci_classify.py --base <sha> --head <sha>      # from git
  ci_classify.py --files a.md b.py ...          # explicit list (tests)
Prints "full=true|false" and appends the same to $GITHUB_OUTPUT when set.
Exit status 0 in both outcomes; exit 2 only on internal misuse.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

DOCS_ROOT = {
    "README.md", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md",
    "CODE_OF_CONDUCT.md", "KNOWN_VERSION_GAPS.md", "V056_ACCEPTANCE_MATRIX.md",
    "LICENSE",
}
DOCS_PATTERNS = (
    re.compile(r"^docs/(?:[^/]+/)*[^/]+\.md$"),
    re.compile(r"^\.github/ISSUE_TEMPLATE/[^/]+\.(?:yml|md)$"),
    re.compile(r"^\.github/PULL_REQUEST_TEMPLATE\.md$"),
)


def is_docs(path: str) -> bool:
    """True only for a path that is documentation by the allowance above."""
    if not path or path != path.strip() or "\\" in path or path.startswith("/") or ".." in path.split("/"):
        return False
    if path in DOCS_ROOT:
        return True
    return any(p.match(path) for p in DOCS_PATTERNS)


def classify(paths) -> bool:
    """Return True when the FULL matrix is required.

    FULL if the list is empty, or any path is not documentation.
    """
    paths = list(paths)
    if not paths:
        return True
    return not all(is_docs(p) for p in paths)


def changed_paths(base: str, head: str, repo: str = ".") -> list[str]:
    """Every path touched between base and head, renames contributing both
    names. Raises on any git problem; the caller treats that as FULL."""
    if not re.fullmatch(r"[0-9a-fA-F]{7,40}", base or "") or not re.fullmatch(r"[0-9a-fA-F]{7,40}", head or ""):
        raise ValueError("base/head must be commit shas")
    out = subprocess.run(
        ["git", "-C", repo, "diff", "--name-status", "-M", "-z", f"{base}...{head}"],
        check=True, capture_output=True, text=True,
    ).stdout
    fields = out.split("\0")
    paths: list[str] = []
    i = 0
    while i < len(fields):
        status = fields[i]
        if status == "":
            i += 1
            continue
        if status[0] in "RC":            # rename/copy: status, old, new
            if i + 2 >= len(fields):
                raise ValueError("truncated rename record")
            paths.extend([fields[i + 1], fields[i + 2]])
            i += 3
        elif status[0] in "AMDT":
            if i + 1 >= len(fields):
                raise ValueError("truncated record")
            paths.append(fields[i + 1])
            i += 2
        else:
            raise ValueError(f"unrecognised status {status!r}")
    return paths


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base")
    ap.add_argument("--head")
    ap.add_argument("--files", nargs="*")
    ap.add_argument("--repo", default=".")
    a = ap.parse_args(argv)
    reason = ""
    if a.files is not None:
        full = classify(a.files)
        reason = f"{len(a.files)} explicit path(s)"
    elif a.base and a.head:
        try:
            paths = changed_paths(a.base, a.head, a.repo)
            full = classify(paths)
            reason = f"{len(paths)} changed path(s) {a.base[:7]}...{a.head[:7]}"
        except Exception as exc:  # noqa: BLE001 — any failure is FULL, said aloud
            full = True
            reason = f"change list unavailable ({type(exc).__name__}: {exc}); defaulting to FULL"
    else:
        print("usage: --base SHA --head SHA | --files ...", file=sys.stderr)
        return 2
    print(f"full={'true' if full else 'false'}  # {reason}")
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a", encoding="utf-8") as fh:
            fh.write(f"full={'true' if full else 'false'}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
