"""
SUNGLASSES Image Extractor — Scans images for hidden prompt injection.

Extracts text from images using multiple methods:
1. OCR (Tesseract) — reads visible text in the image
2. EXIF metadata — reads hidden text in photo properties
3. Hidden text detection — finds suspiciously small/invisible text regions
4. Steganographic markers — basic detection of text hiding techniques

Usage:
    from sunglasses.extractors.image import ImageExtractor
    from sunglasses.engine import SunglassesEngine

    extractor = ImageExtractor()
    engine = SunglassesEngine()

    texts = extractor.extract("/path/to/image.png")
    for source, text in texts:
        result = engine.scan(text, channel="file")
        if not result.is_clean:
            print(f"Threat in {source}: {result.findings}")

Install: pip install sunglasses[image]  (requires Pillow + pytesseract + Tesseract)
"""

import os
import json
from typing import List, Tuple


def _check_deps():
    """Check that image scanning dependencies are installed."""
    missing = []
    try:
        from PIL import Image  # noqa: F401
    except ImportError:
        missing.append("Pillow")
    try:
        import pytesseract  # noqa: F401
    except ImportError:
        missing.append("pytesseract")
    if missing:
        raise ImportError(
            f"Image scanning requires: {', '.join(missing)}. "
            f"Install with: pip install sunglasses[image]"
        )


class OCRUnavailable(RuntimeError):
    """OCR could not be performed. Not a result -- an absence of one.

    Carried as an exception rather than a string so no caller can mistake it for
    extracted text. The dispatcher turns it into a named warning plus
    complete=False, which is what makes the scan report INCOMPLETE instead of clean.
    """


class ImageExtractor:
    """Extract text from images for SUNGLASSES scanning."""

    failures: List[str] = []

    def __init__(self):
        _check_deps()
        # Reset per instance; `extract()` resets again per call.
        self.failures = []

    def extract(self, image_path: str) -> List[Tuple[str, str]]:
        """
        Extract all text from an image file.

        Returns list of (source_label, extracted_text) tuples.
        Each text chunk should be scanned separately through SUNGLASSES.
        """
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Image not found: {image_path}")

        results = []
        # Populated when a sub-extractor could not run. The caller MUST treat a
        # non-empty list as incomplete coverage; losing OCR does not mean the image
        # is clean, it means we did not read the part of it OCR would have read.
        self.failures = []

        # 1. OCR — visible text in the image
        try:
            ocr_text = self._extract_ocr(image_path)
        except OCRUnavailable as exc:
            # Partial extraction, honestly labelled: EXIF and hidden-text detection
            # below still run and can still catch something, but the image is no
            # longer fully inspected and the dispatcher has to say so.
            self.failures.append(str(exc))
            ocr_text = ""
        if ocr_text.strip():
            results.append(("ocr", ocr_text))

        # 2. EXIF metadata — hidden text in photo properties
        exif_texts = self._extract_exif(image_path)
        for field, text in exif_texts:
            if text.strip():
                results.append((f"exif:{field}", text))

        # 3. Hidden text regions — suspiciously invisible text
        hidden = self._detect_hidden_text(image_path)
        if hidden:
            results.append(("hidden_text_warning", hidden))

        return results

    def extract_from_bytes(self, image_bytes: bytes, filename: str = "unknown") -> List[Tuple[str, str]]:
        """Extract text from image bytes (for in-memory processing)."""
        from PIL import Image
        import io

        img = Image.open(io.BytesIO(image_bytes))
        results = []

        # OCR
        ocr_text = self._ocr_from_pil(img)
        if ocr_text.strip():
            results.append(("ocr", ocr_text))

        # EXIF from PIL object
        exif_texts = self._exif_from_pil(img)
        for field, text in exif_texts:
            if text.strip():
                results.append((f"exif:{field}", text))

        return results

    def _extract_ocr(self, image_path: str) -> str:
        """Run OCR on the image to extract visible text.

        Raises OCRUnavailable if OCR could not run. It must NEVER return the error
        as text: the returned string is scanned as document content, so an error
        string was counted as successfully extracted content and an image whose OCR
        never ran came back inspected and clean. That is the same false-success class
        the audio transcription path was repaired for.
        """
        from PIL import Image

        try:
            img = Image.open(image_path)
        except Exception as e:
            raise OCRUnavailable(f"image could not be opened for OCR: {e}") from e
        return self._ocr_from_pil(img)

    def _ocr_from_pil(self, img) -> str:
        """Run OCR on a PIL Image object. Raises OCRUnavailable on any failure."""
        import pytesseract

        try:
            # Convert to RGB if needed (handles RGBA, palette, etc.)
            if img.mode not in ('RGB', 'L'):
                img = img.convert('RGB')
            text = pytesseract.image_to_string(img)
        except Exception as e:
            # Includes pytesseract.TesseractNotFoundError -- the executable missing
            # from PATH is exactly the case that used to return exit 0 / is_clean.
            raise OCRUnavailable(f"OCR did not run: {e}") from e
        return text.strip()

    def _extract_exif(self, image_path: str) -> List[Tuple[str, str]]:
        """Extract text-containing EXIF metadata fields.

        v0.5.6 round 4: `except Exception: return []` made "this image has no
        metadata" and "we could not read this image's metadata" the same answer.
        The second one is a coverage loss and now says so.
        """
        from PIL import Image
        try:
            img = Image.open(image_path)
        except Exception as exc:
            self.failures.append(
                f"image metadata not read ({exc.__class__.__name__}: {exc})")
            return []
        return self._exif_from_pil(img)

    def _exif_from_pil(self, img) -> List[Tuple[str, str]]:
        """Extract text from EXIF data of a PIL Image."""
        from PIL.ExifTags import TAGS

        results = []

        # Standard EXIF. A format that simply has no EXIF block (PNG, most GIFs)
        # is NOT a failure -- it is an honest absence -- so that case is detected
        # by capability rather than by catching the AttributeError it used to
        # raise into a bare `pass`. Only a real read error is a coverage loss.
        try:
            exif_data = img._getexif() if hasattr(img, "_getexif") else None
            if exif_data:
                # Fields attackers could hide text in
                text_fields = {
                    'ImageDescription', 'Make', 'Model', 'Software',
                    'Artist', 'Copyright', 'UserComment', 'XPComment',
                    'XPAuthor', 'XPKeywords', 'XPSubject', 'XPTitle',
                }
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, str(tag_id))
                    if tag_name in text_fields and isinstance(value, str) and len(value) > 5:
                        results.append((tag_name, value))
        except Exception as exc:
            self.failures.append(
                f"EXIF text fields not read ({exc.__class__.__name__}: {exc})")

        # PNG text chunks (tEXt, iTXt, zTXt)
        try:
            if hasattr(img, 'info') and img.info:
                for key, value in img.info.items():
                    if isinstance(value, str) and len(value) > 5:
                        results.append((f"png:{key}", value))
                    elif isinstance(value, bytes):
                        try:
                            decoded = value.decode('utf-8', errors='ignore')
                            if len(decoded) > 5:
                                results.append((f"png:{key}", decoded))
                        except Exception as exc:
                            self.failures.append(
                                f"embedded text chunk {key!r} not decoded "
                                f"({exc.__class__.__name__})")
        except Exception as exc:
            self.failures.append(
                f"embedded text chunks not read ({exc.__class__.__name__}: {exc})")

        return results

    def _detect_hidden_text(self, image_path: str) -> str:
        """
        Basic hidden text detection.

        Checks for signs that text might be hidden in the image:
        - Very small text regions (font-size effectively 0)
        - Text matching background color
        - Unusual amount of white/transparent space with OCR hits

        Returns warning string if suspicious, empty string if clean.
        """
        from PIL import Image
        import pytesseract

        try:
            img = Image.open(image_path)
            width, height = img.size

            # Get detailed OCR data with bounding boxes
            if img.mode not in ('RGB', 'L'):
                img = img.convert('RGB')

            data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)

            suspicious = []
            for i, text in enumerate(data['text']):
                if not text.strip():
                    continue

                w = data['width'][i]
                h = data['height'][i]
                conf = data['conf'][i]

                # Check for extremely small text (possible hidden injection)
                if h < 5 and len(text.strip()) > 3:
                    suspicious.append(f"Tiny text ({h}px): '{text.strip()}'")

                # Check for text in extreme corners/edges (hidden placement)
                x = data['left'][i]
                y = data['top'][i]
                if (x < 2 or y < 2 or x + w > width - 2 or y + h > height - 2) and len(text.strip()) > 10:
                    suspicious.append(f"Edge text at ({x},{y}): '{text.strip()[:50]}'")

            if suspicious:
                return "SUSPICIOUS: " + "; ".join(suspicious[:5])
            return ""

        except Exception as exc:
            # This pass looks for text placed to be invisible -- tiny glyphs, edge
            # placement. Swallowing its failure meant "we looked and found nothing
            # hidden" was returned by a detector that never ran.
            self.failures.append(
                f"hidden-text detection did not run ({exc.__class__.__name__}: {exc})")
            return ""


def scan_image(image_path: str, engine=None) -> dict:
    """
    Convenience function: extract text from an image and scan with SUNGLASSES.

    Returns the canonical result document (see ``sunglasses.result``).

    v0.5.6 round 4 (ASTRA F2): this returned ``is_clean: true`` with no axes and
    no warnings when OCR could not run. ``ImageExtractor`` recorded the loss in
    ``failures`` and ``extract()`` returned normally, so a caller who trusted the
    convenience function got "clean" for an image whose visible text was never
    read -- while ``scan_fast()`` on the same PNG correctly said incomplete. The
    failures are consumed here and folded by the one shared aggregate builder.
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
    _probe_readable(image_path)

    # A decoder that gives up costs COVERAGE, never the scan, and never a
    # traceback -- the same contract `dispatch` has applied to these formats since
    # round 3. Until round 4 these five let ImportError and decoder errors escape
    # to the caller, so "no traceback on any supported path" had an exemption for
    # the public API a user is most likely to call first.
    try:
        extractor = ImageExtractor()
        texts = extractor.extract(image_path)
        _failed = None
    except ImportError as exc:
        extractor, texts, _failed = None, [], (
            f"image scanning requires: pip install sunglasses[image] — nothing in "
            f"{os.path.basename(image_path)} was inspected. ({exc})")
    except Exception as exc:
        extractor, texts, _failed = None, [], (
            f"image extraction failed ({exc.__class__.__name__}) — nothing in "
            f"{os.path.basename(image_path)} was inspected.")

    warnings = [
        f"OCR/metadata text not read from {os.path.basename(image_path)} — {failure}. "
        f"That content was NOT inspected."
        for failure in getattr(extractor, "failures", None) or []
    ]
    if _failed:
        warnings.append(_failed)
    return aggregate(
        [(source, text, engine.scan(text, channel="file")) for source, text in texts],
        source=image_path,
        warnings=warnings,
        extra={"file": image_path},
    )
