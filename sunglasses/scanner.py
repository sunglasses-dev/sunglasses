"""
SUNGLASSES Scanner — Unified interface for FAST and DEEP scanning modes.

SUNGLASSES-FAST (always on, non-blocking):
    - Text: emails, messages, web pages, APIs, logs → <1ms
    - Inline images: EXIF metadata + quick OCR → 1-3 sec
    - Never blocks the agent workflow

SUNGLASSES-DEEP (background, triggered by links/attachments):
    - Audio: Whisper speech-to-text → 30 sec - 6 min
    - Video: subtitles + audio + frame OCR → 1-10 min
    - Large PDFs, QR codes in documents
    - Runs separately, agent continues working

Usage:
    from sunglasses.scanner import SunglassesScanner

    scanner = SunglassesScanner()

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

from .engine import SunglassesEngine


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


class SunglassesScanner:
    """
    Unified SUNGLASSES scanner with FAST and DEEP modes.

    FAST mode: text + images + small PDFs. Always on, non-blocking.
    DEEP mode: audio + video. Background process, opt-in.
    """

    def __init__(self, whisper_model: str = "base"):
        self.engine = SunglassesEngine()
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

        Returns the canonical result dict (see ``sunglasses.result``) plus
        ``body``, ``attachments`` and ``needs_deep_scan``.

        v0.5.6 repair: the aggregate's coverage spans EVERY attachment, including
        the ones deferred to DEEP. Before this, an ordinary body plus one
        untranscribed audio attachment returned ``is_clean: true`` with the
        attachment sitting in ``needs_deep_scan`` -- the aggregate reported on the
        part it read and stayed silent about the part it did not, which is the
        misleading-success class this release exists to close. Deferring work is
        not the same as finding nothing, and the axes now say so.
        """
        from .result import normalize

        body_result = self.engine.scan(email_body, channel="message")
        body_norm = normalize(body_result, source="<email body>")

        attachments_out = []
        pending = []
        warnings = list(body_norm["warnings"])
        threat_found = bool(body_norm["threat_found"])
        extraction_complete = bool(body_norm["extraction_complete"])
        truncated = bool(body_norm["truncated"])
        findings = list(body_norm["findings"])

        for path in attachments or []:
            if self.needs_deep_scan(path):
                pending.append({
                    "file": path,
                    "reason": "Large media file — requires DEEP scan",
                    "command": f'scanner.scan_deep("{path}")',
                })
                # Deferred is NOT inspected. This is the line ASTRA's R1 rerun
                # was about: nothing in this attachment has been read yet.
                extraction_complete = False
                warnings.append(
                    f"Attachment not inspected — {os.path.basename(path)} requires a "
                    f"DEEP scan and has not been transcribed."
                )
                continue

            try:
                att = self.scan_fast(path)
            except Exception as exc:  # operational failure on one attachment
                # One unreadable attachment must not be reported as a clean email,
                # and must not take down the scan of the others.
                attachments_out.append({
                    "file": path,
                    "error": str(exc),
                    "threat_found": False,
                    "inspection_complete": False,
                    "is_clean": False,
                })
                extraction_complete = False
                warnings.append(f"Attachment not inspected — {os.path.basename(path)}: {exc}")
                continue

            attachments_out.append(att)
            if att.get("threat_found"):
                threat_found = True
            if not att.get("inspection_complete", False):
                extraction_complete = False
            if att.get("truncated"):
                truncated = True
            warnings.extend(att.get("warnings") or [])
            findings.extend(att.get("findings") or att.get("threats") or [])

        aggregate = {
            "threat_found": threat_found,
            "extraction_complete": extraction_complete,
            "truncated": truncated,
            "warnings": warnings,
            "findings": findings,
            "channel": "message",
        }
        return normalize(aggregate, source="<email>", extra={
            "body": body_result.to_dict(),
            "attachments": attachments_out,
            "needs_deep_scan": pending,
        })

    def scan_fast(self, file_path: str) -> dict:
        """
        FAST: Scan a file using the appropriate fast extractor.

        Handles: images (OCR + EXIF), PDFs, QR codes, text files.
        Returns dict with scan results.

        Routing is delegated to ``extractors.dispatch`` so this and
        ``SunglassesEngine.scan_file()`` cannot drift apart. Audit finding C1 was
        exactly that drift: two file-scanning surfaces with two extension tables,
        returning opposite verdicts on one PDF. An unknown extension is now read as
        text rather than refused — refusing it was the older, quieter version of the
        same bug, since the caller got no scan and no threat either.
        """
        from .extractors.dispatch import extract_file_sources

        from .result import normalize

        extraction = extract_file_sources(file_path)
        result = self.engine.scan(extraction.text, channel="file")

        # The axes are no longer computed here. `normalize()` owns that decision for
        # every surface in the package (see sunglasses/result.py) -- this function's
        # job is to say what was extracted and hand the evidence over. Before the
        # round-3 repair each consumer did this arithmetic itself, and they did not
        # all agree.
        return normalize(
            {
                "extraction_complete": bool(extraction.complete),
                "truncated": bool(getattr(result, "truncated", False)),
                "warnings": list(extraction.warnings),
                "findings": list(result.findings),
                "threat_found": bool(getattr(result, "threat_found", not result.is_clean)),
                "decision": result.decision,
                "channel": "file",
                "event_id": getattr(result, "event_id", ""),
                "latency_ms": getattr(result, "latency_ms", 0.0),
            },
            source=file_path,
            extra={
                "file": file_path,
                "sources_found": len(extraction.sources),
                "bytes_scanned": len(extraction.text),
                "sources": extraction.labels,
                # kept for callers that predate the canonical name
                "threats": list(result.findings),
            },
        )

    def _scan_image_fast(self, path: str) -> dict:
        """FAST: Image scan (OCR + EXIF + QR codes).

        Same contract as `_scan_pdf`: a decoder that gives up costs COVERAGE,
        never the scan, and never a traceback. A file with a `\x89PNG` header
        that is not actually a PNG raised `PIL.UnidentifiedImageError` straight
        through to the caller -- the identical defect the corrupt-PDF case
        exposed, one extractor over. Unreadable still propagates as operational.

        v0.5.6 round 4 (ASTRA F2). This checked whether ``extract()`` RAISED, and
        nothing else. ``ImageExtractor.extract()`` returns normally when OCR could
        not run -- it records the loss in ``failures`` and hands back whatever EXIF
        it did get -- so with Tesseract absent from PATH and pyzbar decoding fine,
        this helper started from ``extraction_complete: True``, never consulted
        ``failures``, and returned complete/clean with no warnings for an image
        whose visible text was never read. ``scan_fast()`` on the identical PNG
        said incomplete, because dispatch DOES consume ``failures``.

        The fix is the round-4 principle: stop hand-rolling the fold. The child
        scans and the extractor's own failure list go to the one shared aggregate
        builder, so this helper cannot disagree with `scan_fast` about coverage.
        """
        from .extractors.dispatch import _probe_readable
        from .result import aggregate

        _probe_readable(path)                    # UnreadableFile -> operational

        children = []
        warnings = []

        # EXIF + OCR
        try:
            from .extractors.image import ImageExtractor
            extractor = ImageExtractor()
            texts = extractor.extract(path)
            for source, text in texts:
                children.append((source, text, self.engine.scan(text, channel="file")))
            for failure in getattr(extractor, "failures", []):
                warnings.append(
                    f"OCR/metadata text not read from {os.path.basename(path)} — "
                    f"{failure}. That content was NOT inspected.")
        except ImportError:
            warnings.append(
                "Image scanning requires: pip install sunglasses[image] — "
                "OCR/EXIF content was NOT inspected.")
        except Exception as exc:
            warnings.append(
                f"Image extraction failed ({exc.__class__.__name__}) — "
                f"OCR/EXIF content was NOT inspected.")

        # QR codes in the image
        try:
            from .extractors.qr import QRExtractor
            for source, text in QRExtractor().extract(path):
                children.append((f"qr:{source}", text,
                                 self.engine.scan(text, channel="file")))
        except ImportError:
            # "Optional" described the dependency, not the coverage. A QR code we
            # never decoded is content we never read.
            warnings.append(
                "QR scanning requires: pip install sunglasses[image] — "
                "QR content was NOT inspected.")
        except Exception as exc:
            warnings.append(
                f"QR extraction failed ({exc.__class__.__name__}) — "
                f"QR content was NOT inspected.")

        return aggregate(children, source=path, warnings=warnings,
                         extra={"file": path})

    def _scan_pdf(self, path: str) -> dict:
        """FAST: PDF scan.

        Mirrors ``extractors.dispatch._extract_pdf``: a parser that gives up
        costs COVERAGE, never the scan. With PyPDF2 installed, a structurally
        corrupt PDF (`%PDF` header, a Flate stream, no xref) raised
        `PdfReadError: EOF marker not found` straight through to the caller.
        Not reachable from the CLI or MCP -- `scan_fast` routes through dispatch,
        which already answered 3/incomplete on the same bytes -- but this is a
        public method, and "no traceback on any supported path" is the contract.
        Unreadable is still an OPERATIONAL failure and still propagates: a file
        we could not open is not a file we partly read.
        """
        from .extractors.dispatch import _probe_readable
        from .result import normalize

        _probe_readable(path)                    # UnreadableFile -> operational
        try:
            from .extractors.pdf import scan_pdf
            return normalize(scan_pdf(path, engine=self.engine), source=path)
        except ImportError:
            return normalize(
                {"extraction_complete": False,
                 "warnings": ["PDF scanning requires: pip install sunglasses[pdf] — "
                              "nothing in this PDF was inspected."]},
                source=path, extra={"file": path})
        except Exception as exc:
            # Same sentence dispatch uses, deliberately: one vocabulary for one fact.
            return normalize(
                {"extraction_complete": False,
                 "warnings": [f"PDF extraction failed ({exc.__class__.__name__}) — "
                              f"file not read."]},
                source=path, extra={"file": path})

    def _scan_text_file(self, path: str) -> dict:
        """FAST: Plain text file scan."""
        from .extractors.dispatch import _probe_readable, read_text_source
        from .result import normalize

        _probe_readable(path)
        # `open(..., errors='ignore')` here had the same defect dispatch had: bytes
        # that did not decode were dropped and the result still said complete.
        text, warnings = read_text_source(path)
        result = self.engine.scan(text, channel="file")
        return normalize(
            {
                "threat_found": bool(result.threat_found),
                "extraction_complete": not warnings,
                "truncated": bool(result.truncated),
                "warnings": warnings,
                "findings": list(result.findings),
                "decision": result.decision,
                "channel": "file",
            },
            source=path,
            extra={"file": path, "bytes_scanned": len(text),
                   "threats": list(result.findings)})

    # =========================================================================
    # DEEP MODE — Background, for heavy media
    # =========================================================================

    def scan_deep(self, file_path: str) -> dict:
        """
        DEEP: Scan audio/video files. Slower, runs in background.

        Returns full scan results after processing.
        """
        from .extractors.dispatch import _probe_readable
        from .result import normalize

        # Invariant B (round-3 repair): the readability probe runs at EVERY public
        # entry, not once per branch. The deep path selects its extractor from the
        # file suffix and the missing-decoder branch returns before anything opens
        # the file -- so a chmod-000 mp3 was answered from its name alone and came
        # back through MCP as a successful call. Probing here covers both branches
        # and both `allow_deep` values at once. Raises UnreadableFile (operational).
        _probe_readable(file_path)

        ext = os.path.splitext(file_path)[1].lower()
        start = time.time()

        if ext in ('.mp3', '.wav', '.ogg', '.flac', '.m4a', '.aac', '.wma'):
            result = self._scan_audio(file_path)
        elif ext in ('.mp4', '.avi', '.mov', '.mkv', '.webm', '.flv', '.wmv'):
            result = self._scan_video(file_path)
        else:
            result = {"file": file_path, "error": f"Unsupported deep scan type: {ext}"}

        elapsed = round(time.time() - start, 2)
        if result.get("error"):
            # An operational error is not a verdict; it stays an error document and
            # the caller maps it to exit 2 / isError. Normalizing it would dress a
            # failure up as a scan.
            result["scan_time_seconds"] = elapsed
            return result

        # The dependency-warning dict from `_scan_audio`/`_scan_video` has no axes
        # at all. It gets them here, and they say "not inspected" -- which is the
        # truth when there is no decoder installed.
        return normalize(result, source=file_path,
                         extra={"file": file_path, "scan_time_seconds": elapsed})

    def _scan_audio(self, path: str) -> dict:
        """DEEP: Audio scan via Whisper."""
        try:
            from .extractors.audio import scan_audio
            return scan_audio(path, engine=self.engine, whisper_model=self._whisper_model)
        except ImportError:
            return {"file": path, "warning": "Audio scanning requires: pip install sunglasses[audio]"}

    def _scan_video(self, path: str) -> dict:
        """DEEP: Video scan (subtitles + audio + metadata)."""
        try:
            from .extractors.video import scan_video
            return scan_video(path, engine=self.engine, whisper_model=self._whisper_model)
        except ImportError:
            return {"file": path, "warning": "Video scanning requires: pip install sunglasses[video]"}

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
        from .extractors.dispatch import _probe_readable
        from .result import normalize

        if not os.path.exists(input_path):
            return {"error": f"File not found: {input_path}"}

        # Invariant B: probe at the entry, once, before any routing decision. The
        # media shortcut below picks its branch from the extension and (with
        # allow_deep=False) never opens the file, so without this an unreadable
        # media file was classified from its filename.
        _probe_readable(input_path)

        if self.needs_deep_scan(input_path):
            if allow_deep:
                return self.scan_deep(input_path)
            ext = os.path.splitext(input_path)[1].lower()
            # Nothing was transcribed, so nothing was inspected. The axes come from
            # the one normalizer, like every other document this package emits.
            return normalize(
                {
                    "extraction_complete": False,
                    "warnings": [
                        f"Audio/video content not transcribed — nothing in "
                        f"{os.path.basename(input_path)} was inspected."
                    ],
                },
                source=input_path,
                extra={
                    "file": input_path,
                    "needs_deep_scan": True,
                    "reason": f"Audio/video file ({ext}) requires DEEP scan",
                    "action": "Call scanner.scan_deep() or set allow_deep=True",
                },
            )
        return self.scan_fast(input_path)
