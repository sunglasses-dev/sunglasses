"""
File → text routing for scanning.

Audit finding C1: `SunglassesEngine.scan_file()` was a raw `open().read()`, so the
CLI's `scan --file` read PDFs and images as bytes and reported "no threats detected"
on files whose payload lived in a compressed content stream. The extractors in this
package existed and worked; nothing routed to them. (The MCP `scan_file` tool was
never affected — it already went through `SunglassesScanner.scan_auto()`. Two
surfaces, two answers for the same file, which is how the audit found it.)

The routing lives here, in one place, because BOTH file-scanning entry points now
use it: `engine.scan_file()` and `SunglassesScanner.scan_fast()`. Leaving them with
separate extension tables and separate extractor calls is how the two surfaces
disagreed in the first place — one file, one owner.

Contract:
    extract_file_sources(path) -> ExtractionResult

`complete` is the field that matters. False means we could not read part of the file,
and a caller must not present the verdict as a clean bill of health. A scanner that
cannot read a file and says "clean" is worse than no scanner, so the failure is
carried in the return value rather than swallowed.
"""

import os

IMAGE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".tif", ".webp",
}
PDF_EXTENSIONS = {".pdf"}

# Set SUNGLASSES_DISABLE_EXTRACTORS=1 to force the raw-text path. Used by the test
# suite to exercise the degraded branch on a machine that has the extras installed,
# and available to a user who wants byte-level scanning on purpose.
_DISABLE_ENV = "SUNGLASSES_DISABLE_EXTRACTORS"


class ExtractionResult:
    """Text pulled out of a file, plus an honest account of what we could not read."""

    __slots__ = ("sources", "warnings", "complete")

    def __init__(self, sources, warnings=None, complete=True):
        self.sources = sources              # list[(label, text)]
        self.warnings = warnings or []      # list[str], user-facing
        self.complete = complete            # False => verdict is not a clean bill

    @property
    def text(self) -> str:
        return "\n".join(text for _, text in self.sources if text)

    @property
    def labels(self) -> list:
        return [label for label, _ in self.sources]


def _extractors_disabled() -> bool:
    return os.environ.get(_DISABLE_ENV) in ("1", "true", "yes")


def _read_raw(path: str) -> str:
    with open(path, "r", errors="ignore") as fh:
        return fh.read()


def _extract_image(path: str):
    """OCR + EXIF/text-chunk metadata + any QR codes in the image."""
    sources, warnings, complete = [], [], True

    try:
        from .image import ImageExtractor
        sources.extend(ImageExtractor().extract(path))
    except ImportError:
        complete = False
        warnings.append(
            "Image text not extracted (OCR/metadata) — install: pip install 'sunglasses[media]'"
        )
    except Exception as exc:  # a corrupt image must not take the scan down
        complete = False
        warnings.append(f"Image extraction failed ({exc.__class__.__name__}) — text not read.")

    try:
        from .qr import QRExtractor
        sources.extend(("qr:" + label, text) for label, text in QRExtractor().extract(path))
    except ImportError:
        # QR is a narrower claim than OCR; say so separately rather than lumping them.
        complete = False
        warnings.append(
            "QR codes not decoded — install: pip install 'sunglasses[media]'"
        )
    except Exception as exc:
        complete = False
        warnings.append(f"QR decoding failed ({exc.__class__.__name__}).")

    return ExtractionResult(sources, warnings, complete)


def _extract_pdf(path: str):
    """Page text + document metadata + annotations."""
    try:
        from .pdf import PDFExtractor
        return ExtractionResult(PDFExtractor().extract(path))
    except ImportError:
        # Fall back to the raw bytes so an uncompressed PDF still gets looked at —
        # but flag it, because the common case (FlateDecode) yields nothing and a
        # silent PASS here is exactly the bug this module exists to kill.
        return ExtractionResult(
            [("pdf:raw-bytes", _read_raw(path))],
            [
                "PDF text layer not extracted — install: pip install 'sunglasses[media]'. "
                "Only uncompressed text was visible; a normal PDF stores text compressed."
            ],
            complete=False,
        )
    except Exception as exc:
        return ExtractionResult(
            [],
            [f"PDF extraction failed ({exc.__class__.__name__}) — file not read."],
            complete=False,
        )


# --------------------------------------------------------------------------
# Format identification by CONTENT (v0.5.6).
#
# The extension is a claim made by whoever named the file. Routing on it meant a
# ZIP called `notes.txt` had its raw deflate bytes scanned as prose, matched
# nothing — compressed bytes never do — and was reported as a complete, clean
# scan. The suffix is now a hint; the first bytes decide.
# --------------------------------------------------------------------------

# (magic bytes, offset, label) for things we can route to a real extractor.
_MAGIC_PDF = (b"%PDF-", 0)
_MAGIC_IMAGE = [
    (b"\x89PNG\r\n\x1a\n", 0),
    (b"\xff\xd8\xff", 0),          # JPEG
    (b"GIF87a", 0), (b"GIF89a", 0),
    (b"BM", 0),                      # BMP
    (b"II*\x00", 0), (b"MM\x00*", 0),  # TIFF
]

# Containers and binaries we deliberately do NOT parse. Not scanning them is a
# defensible choice; reporting them CLEAN was not. v0.5.6 adds no archive parser —
# it stops lying about the ones it cannot read.
_MAGIC_OPAQUE = [
    (b"PK\x03\x04", 0, "ZIP archive"),
    (b"PK\x05\x06", 0, "empty ZIP archive"),
    (b"PK\x07\x08", 0, "spanned ZIP archive"),
    (b"\x1f\x8b", 0, "gzip stream"),
    (b"BZh", 0, "bzip2 stream"),
    (b"\xfd7zXZ\x00", 0, "xz stream"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip archive"),
    (b"Rar!\x1a\x07", 0, "RAR archive"),
    (b"ustar", 257, "tar archive"),
    (b"\x7fELF", 0, "ELF executable"),
    (b"MZ", 0, "PE/DOS executable"),
    (b"\xca\xfe\xba\xbe", 0, "Mach-O fat binary"),
    (b"\xcf\xfa\xed\xfe", 0, "Mach-O executable"),
    (b"\xce\xfa\xed\xfe", 0, "Mach-O executable"),
    (b"\xd0\xcf\x11\xe0", 0, "OLE compound document"),
    (b"SQLite format 3\x00", 0, "SQLite database"),
]

# Media: a real extractor exists, but only behind --deep. Without it nothing is
# transcribed, so the honest answer is "not inspected", never "clean".
_MAGIC_MEDIA = [
    (b"ID3", 0, "MP3 audio"),
    (b"\xff\xfb", 0, "MP3 audio"), (b"\xff\xf3", 0, "MP3 audio"), (b"\xff\xf2", 0, "MP3 audio"),
    (b"OggS", 0, "Ogg stream"),
    (b"fLaC", 0, "FLAC audio"),
    (b"RIFF", 0, "RIFF container (WAV/AVI)"),
    (b"ftyp", 4, "ISO media (MP4/MOV/M4A)"),
    (b"\x1a\x45\xdf\xa3", 0, "Matroska/WebM"),
    (b"FORM", 0, "AIFF audio"),
]

_SNIFF_BYTES = 512


def _sniff(path: str) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(_SNIFF_BYTES)
    except OSError:
        return b""


def _matches(head: bytes, magic: bytes, offset: int) -> bool:
    return head[offset:offset + len(magic)] == magic


def identify(path: str):
    """Return (kind, label) where kind is pdf | image | media | opaque | text.

    Content first, suffix second: a real PDF named `.txt` is still routed to the
    PDF extractor, and a ZIP named `.txt` is still refused as a container.
    """
    head = _sniff(path)
    if _matches(head, *_MAGIC_PDF):
        return "pdf", "PDF document"
    for magic, offset in _MAGIC_IMAGE:
        if _matches(head, magic, offset):
            return "image", "image"
    for magic, offset, label in _MAGIC_OPAQUE:
        if _matches(head, magic, offset):
            return "opaque", label
    for magic, offset, label in _MAGIC_MEDIA:
        if _matches(head, magic, offset):
            return "media", label

    # No signature. Fall back to the suffix so an extension-named PDF/image with an
    # unusual header still reaches its extractor, exactly as before this change.
    ext = os.path.splitext(path)[1].lower()
    if ext in PDF_EXTENSIONS:
        return "pdf", "PDF document"
    if ext in IMAGE_EXTENSIONS:
        return "image", "image"
    return "text", "text"


def _opaque_result(path: str, label: str) -> ExtractionResult:
    """We identified it, we cannot read it, and we say so."""
    return ExtractionResult(
        [],
        [f"{label} not inspected — SUNGLASSES does not extract this format, so no "
         f"content from {os.path.basename(path)} was scanned. This is not a clean result."],
        complete=False,
    )


def extract_file_sources(path: str) -> ExtractionResult:
    """Route a file to the right extractor. Text and unknown types read as text."""
    kind, label = identify(path)

    if _extractors_disabled():
        # A degradation switch may only make the answer MORE conservative. Anything
        # we identified as needing an extractor is therefore incomplete here, not
        # merely "read as bytes and cleared".
        if kind == "text":
            return ExtractionResult([("file", _read_raw(path))])
        return ExtractionResult(
            [("raw-bytes", _read_raw(path))],
            [f"Extractors disabled by {_DISABLE_ENV} — {label} read as raw bytes only. "
             f"Content that needs extraction was not inspected."],
            complete=False,
        )

    if kind == "pdf":
        return _extract_pdf(path)
    if kind == "image":
        return _extract_image(path)
    if kind == "opaque":
        return _opaque_result(path, label)
    if kind == "media":
        return ExtractionResult(
            [],
            [f"{label} not transcribed — deep scan not requested. Nothing in "
             f"{os.path.basename(path)} was inspected. Re-run with --deep."],
            complete=False,
        )

    # Text, source code, config, and anything unrecognised: read it as text. This is
    # the pre-existing behaviour and it is correct for these — no warning, because
    # nothing was skipped.
    return ExtractionResult([("file", _read_raw(path))])
