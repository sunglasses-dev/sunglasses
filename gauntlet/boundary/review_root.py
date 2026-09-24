"""Where ASTRA's delivered review material lives: ONE key, read in ONE place.

T9 ruling 2026-09-23 (a). Five modules hardcoded a Desktop path, so the producer
could only run on one Mac, and a clean checkout either crashed on a home
directory it did not have or read a tree nobody chose. Every one now reads
`ROOT` from here.

  GAUNTLET_REVIEW_ROOT set, absolute -> that directory. The Mac nightly sets it
                                        in its launchd env; `gauntlet/conftest.py`
                                        sets it for the suites.
  unset                              -> `ABSENT`, a repo-relative directory that
                                        does not exist. A clean checkout or CI
                                        produces the honest refusal (corpus
                                        absent -> EVIDENCE_UNBOUND), never a guess.
  set but EMPTY or RELATIVE          -> `ABSENT` as well. `Path("")` is the
                                        current directory, and a relative path is
                                        whatever tree the process started in: both
                                        would WIDEN the read to something nobody
                                        named. An empty value narrows, never widens.

Delivery material never enters the repo (T9: never vendor it).
"""
from __future__ import annotations

import os
import pathlib

KEY = "GAUNTLET_REVIEW_ROOT"
ABSENT = pathlib.Path(__file__).resolve().parent / "review-root-not-configured"


def _root() -> pathlib.Path:
    value = os.environ.get(KEY, "").strip()
    if not value:
        return ABSENT
    path = pathlib.Path(value).expanduser()
    return path if path.is_absolute() else ABSENT


ROOT = _root()
GATE3 = ROOT / "GATE3_DESIGN_REVIEW_2026-09-13"
