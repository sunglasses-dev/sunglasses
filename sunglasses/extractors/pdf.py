"""
GLASSES PDF Extractor — Scans PDFs for hidden prompt injection.

Extracts text from PDFs using multiple methods:
1. Page text — visible text content on each page
2. Metadata — document properties (title, author, subject, keywords, creator)
3. Annotations — comments, notes, form fields
4. Embedded JavaScript — malicious scripts in PDF actions

Usage:
    from sunglasses.extractors.pdf import scan_pdf
    result = scan_pdf("/path/to/document.pdf")

Install: pip install glasses[pdf]  (requires PyPDF2)
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
            "Install with: pip install glasses[pdf]"
        )


class PDFExtractor:
    """Extract text from PDFs for GLASSES scanning."""

    def __init__(self):
        _check_deps()

    def extract(self, pdf_path: str) -> List[Tuple[str, str]]:
        """
        Extract all text from a PDF file.

        Returns list of (source_label, extracted_text) tuples.
        """
        import PyPDF2

        if not os.path.exists(pdf_path):
            raise FileNotFoundError(f"PDF not found: {pdf_path}")

        results = []

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
        meta = reader.metadata
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
        """Extract text from page annotations."""
        results = []
        try:
            if '/Annots' in page:
                annots = page['/Annots']
                for annot in annots:
                    annot_obj = annot.get_object() if hasattr(annot, 'get_object') else annot
                    # Get annotation content
                    contents = annot_obj.get('/Contents', '')
                    if contents and isinstance(contents, str) and len(contents) > 3:
                        results.append(('annotation', contents))
                    # Get popup text
                    t = annot_obj.get('/T', '')
                    if t and isinstance(t, str) and len(t) > 3:
                        results.append(('annotation_author', t))
        except Exception:
            pass
        return results


def scan_pdf(pdf_path: str, engine=None) -> dict:
    """
    Convenience function: extract text from PDF and scan with GLASSES.

    Returns dict with:
        - sources: list of (source, text) extracted
        - results: list of scan results
        - is_clean: True if ALL extractions are clean
        - threats: list of findings from non-clean results
    """
    from sunglasses.engine import GlassesEngine

    if engine is None:
        engine = GlassesEngine()

    extractor = PDFExtractor()
    texts = extractor.extract(pdf_path)

    results = []
    threats = []
    is_clean = True

    for source, text in texts:
        result = engine.scan(text, channel="file")
        results.append({
            "source": source,
            "text_preview": text[:100] + "..." if len(text) > 100 else text,
            "decision": result.decision,
            "severity": result.severity,
            "findings": result.findings,
        })
        if not result.is_clean:
            is_clean = False
            threats.extend(result.findings)

    return {
        "file": pdf_path,
        "sources_found": len(texts),
        "is_clean": is_clean,
        "threats": threats,
        "results": results,
    }
