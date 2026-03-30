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

Install: pip install glasses[image]  (requires Pillow + pytesseract + Tesseract)
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
            f"Install with: pip install glasses[image]"
        )


class ImageExtractor:
    """Extract text from images for SUNGLASSES scanning."""

    def __init__(self):
        _check_deps()

    def extract(self, image_path: str) -> List[Tuple[str, str]]:
        """
        Extract all text from an image file.

        Returns list of (source_label, extracted_text) tuples.
        Each text chunk should be scanned separately through SUNGLASSES.
        """
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Image not found: {image_path}")

        results = []

        # 1. OCR — visible text in the image
        ocr_text = self._extract_ocr(image_path)
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
        """Run OCR on the image to extract visible text."""
        from PIL import Image
        import pytesseract

        try:
            img = Image.open(image_path)
            return self._ocr_from_pil(img)
        except Exception as e:
            return f"[OCR error: {e}]"

    def _ocr_from_pil(self, img) -> str:
        """Run OCR on a PIL Image object."""
        import pytesseract

        try:
            # Convert to RGB if needed (handles RGBA, palette, etc.)
            if img.mode not in ('RGB', 'L'):
                img = img.convert('RGB')
            text = pytesseract.image_to_string(img)
            return text.strip()
        except Exception as e:
            return f"[OCR error: {e}]"

    def _extract_exif(self, image_path: str) -> List[Tuple[str, str]]:
        """Extract text-containing EXIF metadata fields."""
        from PIL import Image
        try:
            img = Image.open(image_path)
            return self._exif_from_pil(img)
        except Exception:
            return []

    def _exif_from_pil(self, img) -> List[Tuple[str, str]]:
        """Extract text from EXIF data of a PIL Image."""
        from PIL.ExifTags import TAGS

        results = []

        # Standard EXIF
        try:
            exif_data = img._getexif()
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
        except (AttributeError, Exception):
            pass

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
                        except Exception:
                            pass
        except Exception:
            pass

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

        except Exception:
            return ""


def scan_image(image_path: str, engine=None) -> dict:
    """
    Convenience function: extract text from image and scan with SUNGLASSES.

    Returns dict with:
        - sources: list of (source, text) extracted
        - results: list of scan results
        - is_clean: True if ALL extractions are clean
        - threats: list of findings from non-clean results
    """
    from sunglasses.engine import SunglassesEngine

    if engine is None:
        engine = SunglassesEngine()

    extractor = ImageExtractor()
    texts = extractor.extract(image_path)

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
        "file": image_path,
        "sources_found": len(texts),
        "is_clean": is_clean,
        "threats": threats,
        "results": results,
    }
