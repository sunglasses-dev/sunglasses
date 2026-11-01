"""What a ZIP archive says about itself, read without extracting any of it.

SUNGLASSES does not unpack archives, so the files inside one are never scanned. The
archive's own table of contents is a different thing: member names and sizes sit in the
central directory at the end of the file, and reading that table decompresses nothing and
writes nothing. The names are text an agent may be shown, so they go through the scan
like any other text, and the count and declared size let a reader judge the archive
before unpacking it.

Every read here is bounded by a number that does not come from the archive: the
central directory is refused above `MAX_DIRECTORY_BYTES`, at most `MAX_NAMES` names are
kept, and a name is cut at `MAX_NAME_CHARS`. The sizes an archive declares are its own
claim (a ~1 MB file can declare 1 GiB), so they are reported as declared and never used
to decide how much to read.
"""

import io
import os
import struct
import zipfile

MAX_DIRECTORY_BYTES = 8 * 1024 * 1024   # the table of contents; 8 MiB is ~180,000 entries
MAX_NAMES = 1000                        # names kept and scanned; the count covers them all
MAX_NAME_CHARS = 255                    # longest name a common file system stores
_EOCD = b"PK\x05\x06"
_EOCD_SEARCH = 22 + 65535               # fixed record + longest allowed comment
_SHOWN_NAMES = 5
_SHOWN_CHARS = 60

# Suffixes that are ZIP containers by design. A ZIP under any other name is worth saying.
ZIP_SUFFIXES = frozenset({
    ".zip", ".jar", ".war", ".ear", ".whl", ".egg", ".apk", ".aar", ".nupkg", ".vsix",
    ".xpi", ".epub", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".kmz", ".ipa",
})


class _OverLimit(Exception):
    """The reader was asked for more bytes than a table of contents may be."""


class _Bounded:
    """The archive as `zipfile` sees it: no single read may exceed `MAX_DIRECTORY_BYTES`.

    The classic end record and the ZIP64 end record can disagree, and `zipfile` believes the
    ZIP64 one. So the size is not trusted from either: whatever the parser asks for, it gets
    nothing past the limit.
    """

    def __init__(self, inner):
        self._inner = inner

    def read(self, size=-1):
        fh = self._inner
        if size is None or size < 0:
            # "The rest of the file": some Python versions ask this of the end record's tail.
            # It is fine only when the rest is within the limit.
            here = fh.tell()
            rest = max(0, fh.seek(0, os.SEEK_END) - here)    # a cursor past the end has nothing left
            fh.seek(here)
            if rest > MAX_DIRECTORY_BYTES:
                raise _OverLimit(rest)
            return fh.read(rest)
        if size > MAX_DIRECTORY_BYTES:
            raise _OverLimit(size)
        return fh.read(size)

    def seek(self, *args):
        fh = self._inner
        return fh.seek(*args)

    def tell(self):
        return self._inner.tell()

    def seekable(self):
        return True


class Listing:
    """The table of contents of one archive: counts and names, or why it could not be read."""

    __slots__ = ("count", "declared", "names", "names_cut", "error")

    def __init__(self, count=0, declared=0, names=(), names_cut=False, error=None):
        self.count = count              # members in the archive
        self.declared = declared        # sum of the sizes the archive CLAIMS for them
        self.names = list(names)        # first MAX_NAMES names, each cut at MAX_NAME_CHARS
        self.names_cut = names_cut      # more members than names kept
        self.error = error              # None, or why no table was read


def _escape(text):
    """A member name is data, not terminal input: escape control characters."""
    return "".join(
        ch if (ch.isprintable() or ch == " ") else (
            f"\\x{ord(ch):02x}" if ord(ch) < 0x100 else f"\\u{ord(ch):04x}")
        for ch in text)


def _end_record(tail):
    """(entries, directory bytes) from the last end-of-central-directory record, or None."""
    at = tail.rfind(_EOCD)
    if at < 0 or len(tail) - at < 22:
        return None
    (_sig, _disk, _dir_disk, _here, entries, size, _offset,
     _comment) = struct.unpack("<4sHHHHIIH", tail[at:at + 22])
    return entries, size


def read_listing(source):
    """List the members of the ZIP at `source` (a path, or the file's bytes). Never extracts."""
    try:
        if isinstance(source, (bytes, bytearray)):
            tail = bytes(source[-_EOCD_SEARCH:])
            opened = io.BytesIO(source)
        else:
            with open(source, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                fh.seek(max(0, fh.tell() - _EOCD_SEARCH))
                tail = fh.read(_EOCD_SEARCH)
            opened = source
        record = _end_record(tail)
        if record is None:
            return Listing(error="no end-of-central-directory record (damaged, or part of a spanned archive)")
        _entries, directory_bytes = record
        if directory_bytes > MAX_DIRECTORY_BYTES:
            return Listing(error=f"its table of contents declares {directory_bytes:,} bytes, "
                                 f"over the {MAX_DIRECTORY_BYTES:,}-byte limit for listing")
        try:
            if isinstance(opened, (str, os.PathLike)):
                with open(opened, "rb") as fh, zipfile.ZipFile(_Bounded(fh)) as archive:
                    infos = archive.infolist()
            else:
                with zipfile.ZipFile(_Bounded(opened)) as archive:
                    infos = archive.infolist()
        except _OverLimit:
            return Listing(error=f"its table of contents is over the {MAX_DIRECTORY_BYTES:,}-byte "
                                 f"limit for listing")
    except Exception as exc:    # hostile bytes into a parser: a scan reports it, never dies of it
        return Listing(error=f"its table of contents could not be read ({exc.__class__.__name__})")
    # `orig_filename` is the name as stored; `filename` has already been cut at the first NUL.
    names = [info.orig_filename[:MAX_NAME_CHARS] for info in infos[:MAX_NAMES]]
    return Listing(count=len(infos), declared=sum(info.file_size for info in infos),
                   names=names, names_cut=len(infos) > MAX_NAMES)


def name_text(listing):
    """The member names as one text for the scanner: one name per line."""
    return "\n".join(listing.names)


def describe(listing, suffix=""):
    """The sentence(s) a not-inspected line adds for an archive, from its table of contents."""
    parts = []
    if suffix and suffix not in ZIP_SUFFIXES:
        parts.append(f"The file name ends in {_escape(suffix)} but the bytes are a ZIP archive.")
    if listing.error:
        parts.append(f"Members were not listed: {listing.error}.")
    else:
        shown = ", ".join(
            _escape(n if len(n) <= _SHOWN_CHARS else n[:_SHOWN_CHARS] + "…")
            for n in listing.names[:_SHOWN_NAMES])
        more = listing.count - min(listing.count, _SHOWN_NAMES)
        what = f"{listing.count:,} member{'s' if listing.count != 1 else ''}"
        if listing.count:
            what += f", {listing.declared:,} bytes declared by the archive"
            what += f" ({shown}{f', +{more:,} more' if more else ''})"
        scanned = (f"the names of the first {MAX_NAMES:,} were scanned" if listing.names_cut
                   else "the member names were scanned")
        parts.append(f"It lists {what}; {scanned}.")
    return " ".join(parts)
