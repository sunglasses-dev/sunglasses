"""
SUNGLASSES PDF Extractor — Scans PDFs for hidden prompt injection.

Extracts text from PDFs using multiple methods:
1. Page text — visible text content on each page
2. Metadata — document properties (title, author, subject, keywords, creator)
3. Annotations — comments, notes, form fields
4. Embedded JavaScript — malicious scripts in PDF actions

Usage:
    from sunglasses.extractors.pdf import scan_pdf
    result = scan_pdf("/path/to/document.pdf")

Install: pip install sunglasses[pdf]  (requires PyPDF2)
"""

import os
from typing import List, Tuple


def _check_deps():
    """Check that PDF scanning dependencies are installed."""
    try:
        import PyPDF2  # noqa: F401
    except ImportError:
        raise ImportError(
            "PDF scanning requires PyPDF2. "
            "Install with: pip install sunglasses[pdf]"
        )


class PDFExtractor:
    """Extract text from PDFs for SUNGLASSES scanning."""

    # Populated when a sub-parser could not finish. The caller MUST treat a
    # non-empty list as incomplete coverage: a PDF whose annotations we abandoned
    # halfway is not a PDF we read.
    failures: List[str] = []

    def __init__(self):
        _check_deps()
        self.failures = []

    def extract(self, pdf_path: str) -> List[Tuple[str, str]]:
        """
        Extract all text from a PDF file.

        Returns list of (source_label, extracted_text) tuples.
        """
        import PyPDF2

        if not os.path.exists(pdf_path):
            raise FileNotFoundError(f"PDF not found: {pdf_path}")

        results = []
        # Reset per call: a failure from a previous document must never be
        # reported against this one.
        self.failures = []

        with open(pdf_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)

            # 1. Metadata
            meta_texts = self._extract_metadata(reader)
            for field, text in meta_texts:
                if text.strip():
                    results.append((f"metadata:{field}", text))

            # 2. Page text
            for i, page in enumerate(reader.pages):
                text = page.extract_text()
                if text and text.strip():
                    results.append((f"page:{i+1}", text.strip()))

            # 3. Annotations (comments, notes)
            for i, page in enumerate(reader.pages):
                annot_texts = self._extract_annotations(page)
                for label, text in annot_texts:
                    if text.strip():
                        results.append((f"page:{i+1}:{label}", text))

        return results

    def _extract_metadata(self, reader) -> List[Tuple[str, str]]:
        """Extract text from PDF metadata fields."""
        results = []
        try:
            meta = reader.metadata
        except Exception as exc:
            self.failures.append(
                f"document metadata not read ({exc.__class__.__name__}: {exc})")
            return results
        if meta:
            fields = {
                '/Title': 'title',
                '/Author': 'author',
                '/Subject': 'subject',
                '/Keywords': 'keywords',
                '/Creator': 'creator',
                '/Producer': 'producer',
            }
            for key, label in fields.items():
                value = meta.get(key)
                if value and isinstance(value, str) and len(value) > 3:
                    results.append((label, value))
        return results

    def _extract_annotations(self, page) -> List[Tuple[str, str]]:
        """Extract text from page annotations.

        v0.5.6 round 4 (ASTRA F4). This was one `try` around the WHOLE loop with
        `except Exception: pass`. A structurally valid PDF whose annotation array
        starts with a string instead of a dictionary raised on element 0, the
        `except` swallowed it, and the loop was abandoned -- so the instruction
        sitting in element 1 was never extracted and the CLI reported 0, complete,
        clean, with no warning. One malformed sibling hid every annotation after it.

        Two changes, both narrow: the guard moves INSIDE the loop so one bad
        element costs only itself, and a failure is RECORDED instead of dropped.
        Recovering a malformed annotation is explicitly not required; claiming
        complete coverage after giving up on one is the defect.
        """
        results = []
        try:
            annots = page['/Annots'] if '/Annots' in page else []
        except Exception as exc:
            self.failures.append(
                f"annotations not read ({exc.__class__.__name__}: {exc})")
            return results

        for index, annot in enumerate(annots):
            try:
                annot_obj = annot.get_object() if hasattr(annot, 'get_object') else annot
                # Get annotation content
                contents = annot_obj.get('/Contents', '')
                if contents and isinstance(contents, str) and len(contents) > 3:
                    results.append(('annotation', contents))
                # Get popup text
                t = annot_obj.get('/T', '')
                if t and isinstance(t, str) and len(t) > 3:
                    results.append(('annotation_author', t))
            except Exception as exc:
                self.failures.append(
                    f"annotation {index} not read ({exc.__class__.__name__}: {exc}); "
                    f"its text was not inspected")
        return results


def scan_pdf(pdf_path: str, engine=None) -> dict:
    """
    Convenience function: extract text from a PDF and scan with SUNGLASSES.

    Returns the canonical result document (see ``sunglasses.result``).

    v0.5.6 round 4: like the other four extractor aggregates this built its own
    per-source dictionaries and dropped the child's ``truncated`` /
    ``extraction_complete``, so a PDF whose extracted text ran past the engine's
    cap came back complete and clean. It also ignored ``PDFExtractor.failures``,
    which is how one malformed annotation could hide the next one silently.
    """
    from sunglasses.engine import SunglassesEngine
    from sunglasses.extractors.dispatch import _probe_readable
    from sunglasses.result import aggregate

    if engine is None:
        engine = SunglassesEngine()

    # Invariant B (round 3), extended to these five in round 4. A public entry
    # point probes readability BEFORE it routes, so an unreadable, missing or
    # non-regular path is an OPERATIONAL failure here exactly as it is on
    # `scan_fast`, `scan_deep` and the retained helpers. Without it these returned
    # a partial SCAN DOCUMENT for a file they had never opened -- a verdict-shaped
    # answer to a question that was never asked -- and a FIFO blocked on open.
    _probe_readable(pdf_path)

    extractor = PDFExtractor()
    texts = extractor.extract(pdf_path)

    warnings = [
        f"PDF content not fully read from {os.path.basename(pdf_path)} — {failure}."
        for failure in getattr(extractor, "failures", [])
    ]
    return aggregate(
        [(source, text, engine.scan(text, channel="file")) for source, text in texts],
        source=pdf_path,
        warnings=warnings,
        extra={"file": pdf_path},
    )
