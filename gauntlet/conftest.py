"""The ONE place a test run names this Mac's review material.

`gauntlet/boundary/review_root.py` reads GAUNTLET_REVIEW_ROOT and, unset, points
at a directory that does not exist, so production code carries no home path.
The suites were written against the delivered material on this Mac, so they
set the key here, BEFORE any test module imports a module that reads it
(pytest loads this file before collecting anything under gauntlet/).

`setdefault`: an operator who exports a different root is obeyed. The nightly
sets the same key in its launchd env, never in code.
"""
import os
import pathlib

os.environ.setdefault(
    "GAUNTLET_REVIEW_ROOT",
    str(pathlib.Path.home() / "Desktop" / "SUNGLASSES_ASTRA_REVIEW_2026-09-04"))
