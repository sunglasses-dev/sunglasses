"""
SUNGLASSES QR Code Extractor — Scans QR codes and barcodes for prompt injection.

Extracts and scans text from:
1. QR codes in images
2. Barcodes (Code128, EAN, etc.) in images
3. Multiple codes per image

Attack vectors this catches:
- QR codes in documents containing hidden instructions
- QR code stickers placed on physical items that agents scan
- Malicious URLs or commands encoded in QR

Usage:
    from sunglasses.extractors.qr import scan_qr
    result = scan_qr("/path/to/document_with_qr.png")

Install: pip install sunglasses[qr]  (requires pyzbar + Pillow)
"""

import os
from typing import List, Tuple


def _check_deps():
    """Check that QR scanning dependencies are installed."""
    missing = []
    try:
        from pyzbar.pyzbar import decode  # noqa: F401
    except ImportError:
        missing.append("pyzbar")
    try:
        from PIL import Image  # noqa: F401
    except ImportError:
        missing.append("Pillow")
    if missing:
        raise ImportError(
            f"QR scanning requires: {', '.join(missing)}. "
            f"Install with: pip install sunglasses[qr]"
        )


class QRExtractor:
    """Extract text from QR codes and barcodes for SUNGLASSES scanning."""

    def __init__(self):
        _check_deps()

    def extract(self, image_path: str) -> List[Tuple[str, str]]:
        """
        Extract text from all QR codes/barcodes in an image.

        Returns list of (source_label, decoded_text) tuples.
        """
        from pyzbar.pyzbar import decode
        from PIL import Image

        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Image not found: {image_path}")

        img = Image.open(image_path)
        codes = decode(img)

        results = []
        for i, code in enumerate(codes):
            code_type = code.type  # QRCODE, EAN13, CODE128, etc.
            try:
                text = code.data.decode('utf-8')
            except (UnicodeDecodeError, AttributeError):
                text = str(code.data)

            if text.strip():
                results.append((f"{code_type.lower()}:{i}", text))

        return results

    def extract_from_bytes(self, image_bytes: bytes) -> List[Tuple[str, str]]:
        """Extract QR/barcode text from image bytes."""
        from pyzbar.pyzbar import decode
        from PIL import Image
        import io

        img = Image.open(io.BytesIO(image_bytes))
        codes = decode(img)

        results = []
        for i, code in enumerate(codes):
            code_type = code.type
            try:
                text = code.data.decode('utf-8')
            except (UnicodeDecodeError, AttributeError):
                text = str(code.data)
            if text.strip():
                results.append((f"{code_type.lower()}:{i}", text))

        return results


def scan_qr(image_path: str, engine=None) -> dict:
    """Convenience function: extract QR/barcode text and scan with SUNGLASSES.

    Returns the canonical result document (see ``sunglasses.result``). v0.5.6
    round 4: it used to build its own aggregate and drop the child's coverage.
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
        extractor = QRExtractor()
        texts = extractor.extract(image_path)
        _failed = None
    except ImportError as exc:
        extractor, texts, _failed = None, [], (
            f"QR/barcode scanning requires: pip install sunglasses[image] — nothing in "
            f"{os.path.basename(image_path)} was inspected. ({exc})")
    except Exception as exc:
        extractor, texts, _failed = None, [], (
            f"QR/barcode extraction failed ({exc.__class__.__name__}) — nothing in "
            f"{os.path.basename(image_path)} was inspected.")

    return aggregate(
        [(source, text, engine.scan(text, channel="file")) for source, text in texts],
        source=image_path,
        warnings=[_failed] if _failed else [],
        extra={"file": image_path},
    )
