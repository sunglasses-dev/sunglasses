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


def extract_file_sources(path: str) -> ExtractionResult:
    """Route a file to the right extractor. Text and unknown types read as text."""
    ext = os.path.splitext(path)[1].lower()

    if _extractors_disabled():
        if ext in IMAGE_EXTENSIONS or ext in PDF_EXTENSIONS:
            return ExtractionResult(
                [("raw-bytes", _read_raw(path))],
                [f"Extractors disabled by {_DISABLE_ENV} — {ext} read as raw bytes only."],
                complete=False,
            )
        return ExtractionResult([("file", _read_raw(path))])

    if ext in IMAGE_EXTENSIONS:
        return _extract_image(path)
    if ext in PDF_EXTENSIONS:
        return _extract_pdf(path)

    # Text, source code, config, and anything unrecognised: read it as text. This is
    # the pre-existing behaviour and it is correct for these — no warning, because
    # nothing was skipped.
    return ExtractionResult([("file", _read_raw(path))])
