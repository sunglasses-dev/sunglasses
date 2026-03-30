"""
GLASSES Scanner — Unified interface for FAST and DEEP scanning modes.

GLASSES-FAST (always on, non-blocking):
    - Text: emails, messages, web pages, APIs, logs → <1ms
    - Inline images: EXIF metadata + quick OCR → 1-3 sec
    - Never blocks the agent workflow

GLASSES-DEEP (background, triggered by links/attachments):
    - Audio: Whisper speech-to-text → 30 sec - 6 min
    - Video: subtitles + audio + frame OCR → 1-10 min
    - Large PDFs, QR codes in documents
    - Runs separately, agent continues working

Usage:
    from glasses.scanner import GlassesScanner

    scanner = GlassesScanner()

    # FAST — always on, inline
    result = scanner.scan_text("email content here")
    result = scanner.scan_fast("path/to/image.png")

    # DEEP — background, for heavy media
    result = scanner.scan_deep("path/to/video.mp4")
    needs_deep = scanner.needs_deep_scan("path/to/file.mp3")
"""

import os
import time
from typing import Optional

from .engine import GlassesEngine


# File extensions that trigger DEEP scan
DEEP_EXTENSIONS = {
    '.mp3', '.wav', '.ogg', '.flac', '.m4a', '.aac', '.wma',  # audio
    '.mp4', '.avi', '.mov', '.mkv', '.webm', '.flv', '.wmv',  # video
}

# File extensions for FAST scan
FAST_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.webp',  # images
    '.pdf',  # PDFs
    '.txt', '.md', '.html', '.csv', '.json', '.xml',  # text
}


class GlassesScanner:
    """
    Unified GLASSES scanner with FAST and DEEP modes.

    FAST mode: text + images + small PDFs. Always on, non-blocking.
    DEEP mode: audio + video. Background process, opt-in.
    """

    def __init__(self, whisper_model: str = "base"):
        self.engine = GlassesEngine()
        self._whisper_model = whisper_model

    # =========================================================================
    # FAST MODE — Always on, <3 seconds
    # =========================================================================

    def scan_text(self, text: str, channel: str = "message"):
        """FAST: Scan text directly. <1ms."""
        return self.engine.scan(text, channel=channel)

    def scan_email(self, email_body: str, attachments: list = None):
        """
        FAST: Scan email body + small attachments.

        Returns dict with body result + per-attachment results.
        Large audio/video attachments are flagged for DEEP scan.
        """
        results = {
            "body": self.engine.scan(email_body, channel="message").to_dict(),
            "attachments": [],
            "needs_deep_scan": [],
            "is_clean": True,
        }

        body_result = self.engine.scan(email_body, channel="message")
        results["body"] = body_result.to_dict()
        if not body_result.is_clean:
            results["is_clean"] = False

        if attachments:
            for path in attachments:
                if self.needs_deep_scan(path):
                    results["needs_deep_scan"].append({
                        "file": path,
                        "reason": "Large media file — requires DEEP scan",
                        "command": f'scanner.scan_deep("{path}")',
                    })
                else:
                    att_result = self.scan_fast(path)
                    results["attachments"].append(att_result)
                    if not att_result.get("is_clean", True):
                        results["is_clean"] = False

        return results

    def scan_fast(self, file_path: str) -> dict:
        """
        FAST: Scan a file using the appropriate fast extractor.

        Handles: images (OCR + EXIF), PDFs, QR codes, text files.
        Returns dict with scan results.
        """
        ext = os.path.splitext(file_path)[1].lower()

        if ext in ('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.webp'):
            return self._scan_image_fast(file_path)
        elif ext == '.pdf':
            return self._scan_pdf(file_path)
        elif ext in ('.txt', '.md', '.html', '.csv', '.json', '.xml'):
            return self._scan_text_file(file_path)
        else:
            return {"file": file_path, "error": f"Unsupported fast scan type: {ext}"}

    def _scan_image_fast(self, path: str) -> dict:
        """FAST: Image scan (OCR + EXIF + QR codes)."""
        results = {"file": path, "sources": [], "threats": [], "is_clean": True}

        # EXIF + OCR
        try:
            from .extractors.image import ImageExtractor
            extractor = ImageExtractor()
            texts = extractor.extract(path)
            for source, text in texts:
                r = self.engine.scan(text, channel="file")
                results["sources"].append({"source": source, "decision": r.decision})
                if not r.is_clean:
                    results["is_clean"] = False
                    results["threats"].extend(r.findings)
        except ImportError:
            results["warning"] = "Image scanning requires: pip install glasses[image]"

        # QR codes in the image
        try:
            from .extractors.qr import QRExtractor
            qr = QRExtractor()
            codes = qr.extract(path)
            for source, text in codes:
                r = self.engine.scan(text, channel="file")
                results["sources"].append({"source": f"qr:{source}", "decision": r.decision})
                if not r.is_clean:
                    results["is_clean"] = False
                    results["threats"].extend(r.findings)
        except ImportError:
            pass  # QR scanning optional

        return results

    def _scan_pdf(self, path: str) -> dict:
        """FAST: PDF scan."""
        try:
            from .extractors.pdf import scan_pdf
            return scan_pdf(path, engine=self.engine)
        except ImportError:
            return {"file": path, "warning": "PDF scanning requires: pip install glasses[pdf]"}

    def _scan_text_file(self, path: str) -> dict:
        """FAST: Plain text file scan."""
        with open(path, 'r', errors='ignore') as f:
            text = f.read()
        result = self.engine.scan(text, channel="file")
        return {
            "file": path,
            "is_clean": result.is_clean,
            "decision": result.decision,
            "threats": result.findings,
        }

    # =========================================================================
    # DEEP MODE — Background, for heavy media
    # =========================================================================

    def scan_deep(self, file_path: str) -> dict:
        """
        DEEP: Scan audio/video files. Slower, runs in background.

        Returns full scan results after processing.
        """
        ext = os.path.splitext(file_path)[1].lower()
        start = time.time()

        if ext in ('.mp3', '.wav', '.ogg', '.flac', '.m4a', '.aac', '.wma'):
            result = self._scan_audio(file_path)
        elif ext in ('.mp4', '.avi', '.mov', '.mkv', '.webm', '.flv', '.wmv'):
            result = self._scan_video(file_path)
        else:
            result = {"file": file_path, "error": f"Unsupported deep scan type: {ext}"}

        result["scan_time_seconds"] = round(time.time() - start, 2)
        return result

    def _scan_audio(self, path: str) -> dict:
        """DEEP: Audio scan via Whisper."""
        try:
            from .extractors.audio import scan_audio
            return scan_audio(path, engine=self.engine, whisper_model=self._whisper_model)
        except ImportError:
            return {"file": path, "warning": "Audio scanning requires: pip install glasses[audio]"}

    def _scan_video(self, path: str) -> dict:
        """DEEP: Video scan (subtitles + audio + metadata)."""
        try:
            from .extractors.video import scan_video
            return scan_video(path, engine=self.engine, whisper_model=self._whisper_model)
        except ImportError:
            return {"file": path, "warning": "Video scanning requires: pip install glasses[video]"}

    # =========================================================================
    # HELPERS
    # =========================================================================

    def needs_deep_scan(self, file_path: str) -> bool:
        """Check if a file requires DEEP scanning (audio/video)."""
        ext = os.path.splitext(file_path)[1].lower()
        return ext in DEEP_EXTENSIONS

    def scan_auto(self, input_path: str, allow_deep: bool = False) -> dict:
        """
        Auto-detect input type and scan appropriately.

        If allow_deep=False (default), audio/video files return a
        "needs_deep_scan" notice instead of processing. Safe for
        always-on inline use — never blocks unexpectedly.
        """
        if not os.path.exists(input_path):
            return {"error": f"File not found: {input_path}"}

        if self.needs_deep_scan(input_path):
            if allow_deep:
                return self.scan_deep(input_path)
            else:
                ext = os.path.splitext(input_path)[1].lower()
                return {
                    "file": input_path,
                    "needs_deep_scan": True,
                    "reason": f"Audio/video file ({ext}) requires DEEP scan",
                    "action": "Call scanner.scan_deep() or set allow_deep=True",
                }
        else:
            return self.scan_fast(input_path)
