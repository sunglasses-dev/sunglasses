"""Which entries in a directory match, asked one way (T9 ruling 56).

`Path.glob` answers [] when it cannot scan a directory: it swallows the
scan's OSError, PermissionError included. So a key directory or a hook chain
nobody could list read exactly like an empty one, and "no key" or "no chain"
was decided on a failure (ASTRA receipts172 r3, item 3). Every presence
decision in the receipts paths asks here instead: a directory that is not
there has no entries, and one that is there and cannot be listed raises.
Ruling 57 draws "there" at the directory entry: a file or a symlink where
the directory should be is there, and raises too.
"""
from __future__ import annotations

import fnmatch
import os
import pathlib


class Unlistable(OSError):
    """The directory exists and its entries cannot be read. Never "empty"."""

    def __init__(self, directory, cause: OSError):
        self.directory = pathlib.Path(directory)
        self.cause = cause
        super().__init__(cause.errno,
                         f"{self.directory} cannot be listed ({type(cause).__name__})")

    def __str__(self):
        return self.strerror


def listing(directory, pattern) -> list[pathlib.Path]:
    """The entries of `directory` whose names match `pattern`, sorted. Three
    outcomes, and only one of them is "nothing there" (T9 ruling 57):

    - absent: no directory entry at the path at all (os.path.lexists is
      False, a missing parent included) -> [];
    - a listable directory -> its matching entries;
    - anything else at the path -> Unlistable: a directory that cannot be
      read, and also a regular file, a dangling symlink or a symlink to a
      file standing where the directory should be. Something is there, so
      it is never read as empty."""
    directory = pathlib.Path(directory)
    try:
        names = os.listdir(directory)
    except (FileNotFoundError, NotADirectoryError) as cause:
        if not os.path.lexists(directory):
            return []              # no entry at all: nothing there to hide anything
        raise Unlistable(directory, cause) from cause
    except OSError as cause:
        raise Unlistable(directory, cause) from cause
    return sorted(directory / name for name in names
                  if fnmatch.fnmatchcase(name, pattern))
