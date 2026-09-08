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

    # The SAME cap OCR and metadata use (`ImageExtractor.MAX_OCR_FRAMES`). One
    # number for every reader of the same file: a frame budget that differs per
    # component is a frame some component silently skipped.
    MAX_QR_FRAMES = 64

    def __init__(self):
        _check_deps()
        # Read by `dispatch._extract_image` and by `scan_qr`. Anything appended
        # here costs COVERAGE -- frames we did not decode are frames we cannot
        # call clean.
        self.failures: List[str] = []

    def _decode_frames(self, img, source: str) -> List[Tuple[str, str]]:
        """Decode every frame of a possibly-animated image.

        v0.5.6 round 6 (ASTRA H1). This class used to call `decode(img)` ONCE on
        the frame Pillow happens to open first. Round 5 taught OCR and metadata to
        walk `ImageSequence`; QR was left behind, and the result was the worst
        shape this release has produced: `qr-later.gif` and `qr-later.tiff` carry a
        real injection payload in frame 1, and `scan --file` returned exit 0 with
        `inspection_complete: true, is_clean: true`. The same pixels scanned alone
        produced six findings. A missed attack reported as a clean, COMPLETE
        inspection is worse than an honest failure to read.

        The general rule this makes explicit, and the one the container table now
        carries a dimension for: **every reader of "the image" must ask WHICH
        frame.** OCR, metadata and QR each open the same file and each must either
        walk it or name what it skipped.
        """
        from pyzbar.pyzbar import decode
        from PIL import ImageSequence

        total = getattr(img, "n_frames", 1) or 1
        results: List[Tuple[str, str]] = []

        def _codes_of(frame, label_prefix: str):
            found = []
            for i, code in enumerate(decode(frame)):
                code_type = code.type  # QRCODE, EAN13, CODE128, etc.
                try:
                    text = code.data.decode('utf-8')
                except (UnicodeDecodeError, AttributeError):
                    text = str(code.data)
                if text.strip():
                    found.append((f"{code_type.lower()}:{label_prefix}{i}", text))
            return found

        if total == 1:
            # Ordinary single-frame image: the label stays exactly as it was, so
            # nothing downstream of a still image sees a renamed source.
            return _codes_of(img, "")

        for index, frame in enumerate(ImageSequence.Iterator(img)):
            if index >= self.MAX_QR_FRAMES:
                break
            try:
                # pyzbar wants a concrete image; an animated frame can be P-mode
                # with a palette, which it decodes poorly or not at all.
                target = frame.convert("RGB")
            except Exception as exc:
                self.failures.append(
                    f"frame {index} not converted for QR decoding "
                    f"({exc.__class__.__name__}: {exc}) — its codes were NOT read")
                continue
            try:
                # Frame 0 keeps the bare label for backwards compatibility; later
                # frames say which frame they came from, so a finding can be
                # located in the file it was found in.
                prefix = "" if index == 0 else f"frame:{index}:"
                results.extend(_codes_of(target, prefix))
            except Exception as exc:
                self.failures.append(
                    f"frame {index} not decoded for QR "
                    f"({exc.__class__.__name__}: {exc}) — its codes were NOT read")
                continue

        if total > self.MAX_QR_FRAMES:
            self.failures.append(
                f"{total - self.MAX_QR_FRAMES} of {total} frames not inspected for "
                f"QR codes — {source} exceeds the {self.MAX_QR_FRAMES}-frame cap")
        return results

    def extract(self, image_path: str) -> List[Tuple[str, str]]:
        """
        Extract text from all QR codes/barcodes in an image, across ALL frames.

        Returns list of (source_label, decoded_text) tuples.
        """
        from PIL import Image

        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Image not found: {image_path}")

        img = Image.open(image_path)
        return self._decode_frames(img, source=os.path.basename(image_path))

    def extract_from_bytes(self, image_bytes: bytes) -> List[Tuple[str, str]]:
        """Extract QR/barcode text from image bytes, across ALL frames.

        Walks frames for the same reason `extract()` does: the in-memory and
        on-disk paths must answer the same question about the same bytes, or one
        of them is a quieter version of H1 (see `ImageExtractor.extract_from_bytes`
        and ASTRA H5).
        """
        from PIL import Image
        import io

        img = Image.open(io.BytesIO(image_bytes))
        return self._decode_frames(img, source="image bytes")


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

    # Frames the decoder skipped are a COVERAGE loss on this surface too, not only
    # through `dispatch`. Round 6 (ASTRA H1): `scan_qr()` is a public entry point,
    # and it reported the same false completeness the CLI did.
    _warnings = [_failed] if _failed else []
    for failure in getattr(extractor, "failures", []) if extractor else []:
        _warnings.append(
            f"{os.path.basename(image_path)} not fully read — {failure}.")

    return aggregate(
        [(source, text, engine.scan(text, channel="file")) for source, text in texts],
        source=image_path,
        warnings=_warnings,
        extra={"file": image_path},
    )
