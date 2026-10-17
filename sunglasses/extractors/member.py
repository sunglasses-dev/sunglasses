"""A file whose bytes were already read, handed to the extractors in place of a path.

A directory scan reads each file once, through its held directory handles (see
`cli._read_member`), and judges those bytes. If the extractors were given a path to a
copy instead, every step that opened it again would be a new chance for the path to lead
somewhere else, and the copy would have to be written somewhere. A `Member` carries the
bytes and the name the file is shown under, so nothing is written and nothing is opened
twice: the bytes judged are the bytes read.
"""

import os


class Member(bytes):
    """The bytes of one file, read once, plus the name it is reported under."""

    name = ""

    def __new__(cls, data, name):
        self = super().__new__(cls, data)
        self.name = name
        return self

    # An error message or a label that formats the "path" must show the name, never the
    # file's contents.
    def __str__(self):
        return self.name

    def __repr__(self):
        return repr(self.name)


def display_name(source):
    """The file name a label shows: the last part of the path, or of the member's name."""
    return os.path.basename(source.name if isinstance(source, Member) else source)
