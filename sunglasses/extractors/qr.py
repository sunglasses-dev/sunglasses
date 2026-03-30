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

Install: pip install glasses[qr]  (requires pyzbar + Pillow)
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
            f"Install with: pip install glasses[qr]"
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
    """Convenience function: extract QR/barcode text and scan with SUNGLASSES."""
    from sunglasses.engine import SunglassesEngine

    if engine is None:
        engine = SunglassesEngine()

    extractor = QRExtractor()
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
