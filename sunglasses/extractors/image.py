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
import struct
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


class ImageRefused(Exception):
    """The opener declined a file. A policy result, not a fault: every entry point
    turns it into a named failure and an empty result, never an exception."""


class ImageOverPixelBudget(ImageRefused):
    """A file declares more pixels than the budget, and opening it would decode them."""


class FrameRefused:
    """What `_reachable_frames` yields in place of a frame it will not seek to."""

    def __init__(self, index, message):
        self.index, self.message = index, message


class _GifPlan:
    """What a GIF's own blocks say about its frames, read without Pillow."""

    def __init__(self, total, allowed, refused_size):
        self.total, self.allowed, self.refused_size = total, allowed, refused_size


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

        # 1. OCR — visible text in EVERY frame, not just the one PIL opens on.
        results.extend(self._ocr_all_frames(image_path))

        # 2. Metadata — hidden text in photo properties, IN EVERY FRAME.
        #    A multi-page TIFF carries a separate IFD per page, and a GIF can
        #    carry a comment block per frame, so reading page 0's metadata and
        #    stopping is the frame bug (G1) again on the metadata side: a
        #    two-page TIFF whose ImageDescription lives only on page 2 returned
        #    exit 0, complete, clean. Found by T9 reasoning from the source; the
        #    fixture turned out to be buildable after all, so it is asserted
        #    rather than filed as an unknown.
        for field, text in self._metadata_all_frames(image_path):
            if text.strip():
                results.append((f"exif:{field}", text))

        # 3. Hidden text regions — suspiciously invisible text
        hidden = self._detect_hidden_text(image_path)
        if hidden:
            results.append(("hidden_text_warning", hidden))

        return results

    def extract_from_bytes(self, image_bytes: bytes, filename: str = "unknown") -> List[Tuple[str, str]]:
        """Extract text from image bytes (for in-memory processing)."""
        results = []

        self.failures = []
        try:
            img = self._open_lazy(image_bytes)
        except ImageRefused as exc:
            # A refusal is a result, not an exception: named, so the scan is
            # incomplete, and nothing was opened.
            self.failures.append(str(exc))
            return results

        # OCR every frame, same contract as `extract()`.
        results.extend(self._ocr_frames_of(img, source=filename))

        # v0.5.6 round 7 (ASTRA I2). Round 6 put a `seek(0)` here and then read
        # metadata ONCE. That fixed the first page by breaking the last: 0 -> 7
        # findings for page-0-only metadata, and 7 -> 0 for page-1-only, with an
        # empty `failures` list both times. A seek to frame 0 is not evidence that
        # every metadata frame was read -- it just moves which page gets lost.
        #
        # The path and bytes APIs now run the SAME bounded walk, which is the only
        # version of "they agree" that survives a fixture on the other page.
        # `_metadata_frames_of` handles its own seeking, so the parked position the
        # OCR walk left behind no longer decides what metadata is seen.
        try:
            # Not when the walk above stopped on a refused frame: rewinding is a
            # seek, and the metadata walk below seeks to frame 0 on its own.
            if getattr(img, "n_frames", 1) > 1 and not self._pixel_cap_failure(img):
                img.seek(0)
        except Exception:
            # Not fatal and not silent: the walk below reports what it cannot reach.
            pass

        for field, text in self._metadata_frames_of(img, source=filename):
            if text.strip():
                results.append((f"exif:{field}", text))

        return results

    # A GIF or a multi-page TIFF is ONE file with N images in it. PIL opens on
    # frame 0 and stays there unless you seek, so OCR read the first frame and the
    # scan reported a complete inspection of the whole file.
    #
    # v0.5.6 round 5 (ASTRA G1): `two-frame.gif` and `two-page.tiff` came back
    # exit 0, complete, clean -- while exporting frame 2 on its own and handing it
    # to the identical scanner produced five findings. Nothing was broken; the
    # attack simply lived in a component nothing looked at, and the document said
    # everything had been looked at.
    #
    # The cap exists because a GIF can carry thousands of frames and OCR is
    # seconds each: an unbounded loop turns a scanner into a denial of service,
    # which is the same reason `MAX_SCAN_BYTES` exists. Frames past the cap are
    # NOT silently dropped -- they are named in `failures`, which costs coverage.
    MAX_OCR_FRAMES = 64

    # A picture can be a few kilobytes on disk and gigabytes once decoded, and PIL
    # only warns between about 89 and 179 million pixels and raises above that.
    # The size is read from the header, and an image over the budget has no pixel
    # decoded by this extractor: not for OCR, not for the hidden text pass, not
    # for metadata and not by the QR reader. Three things make that hold.
    #   * The file is opened only as one of the formats whose open reads a header
    #     (`_open_lazy`). Some containers decode inside `open`, before any size
    #     check could run.
    #   * Metadata of a refused frame is read from the header alone. A PNG reads
    #     its trailing chunks by decoding the pixels, so those are named as not
    #     read instead.
    #   * A GIF frame is built on the frame before it, and a seek allocates for the
    #     frame it lands on before any caller can look at its size. So a GIF's
    #     frame extents are read from its own blocks first (`_gif_plan`), and the
    #     walks (`_reachable_frames`) seek only to frames the plan allows. The walk
    #     stops at the first frame it will not seek to and names what it left.
    # Every refusal is named in `failures`, so the scan says it was not fully
    # inspected instead of calling it clean.
    MAX_IMAGE_PIXELS = 25_000_000

    # The first bytes of the containers `_open_lazy` opens, and the PIL format
    # each one is opened as.
    _LAZY_MAGIC = (
        (b"\x89PNG\r\n\x1a\n", "PNG"),
        (b"\xff\xd8\xff", "JPEG"),
        (b"GIF87a", "GIF"),
        (b"GIF89a", "GIF"),
        (b"BM", "BMP"),
        (b"II*\x00", "TIFF"),
        (b"MM\x00*", "TIFF"),
        (b"II+\x00", "TIFF"),
        (b"MM\x00+", "TIFF"),
    )
    # Formats whose later frames are built on the frame before, so reading past a
    # refused frame decodes it.
    _FRAMES_BUILD_ON_EACH_OTHER = ("GIF", "PNG", "WEBP")
    # Formats whose metadata sits in the header, so a refused frame's metadata is
    # read without a pixel being decoded.
    _METADATA_IN_HEADER = ("JPEG", "TIFF")

    @classmethod
    def _pixel_cap_failure(cls, img, reader="OCR"):
        """Message if this frame is over the pixel budget, else None. Header only.

        The QR reader asks the same question of the same file, so it calls this
        too: one budget for every reader of the image.
        """
        try:
            width, height = img.size
        except Exception:
            return None
        return cls._over_budget(width, height, f"decoded or read by {reader}")

    @classmethod
    def _over_budget(cls, width, height, what):
        if width * height > cls.MAX_IMAGE_PIXELS:
            return (f"{width}x{height} is {width * height:,} pixels, over the "
                    f"{cls.MAX_IMAGE_PIXELS:,} pixel cap, so it was not {what}")
        return None

    @staticmethod
    def _webp_size(head: bytes):
        """The canvas size a WebP's first chunk declares, or None."""
        kind = head[12:16]
        if kind == b"VP8X" and len(head) >= 30:
            return (int.from_bytes(head[24:27], "little") + 1,
                    int.from_bytes(head[27:30], "little") + 1)
        if kind == b"VP8 " and len(head) >= 30 and head[23:26] == b"\x9d\x01\x2a":
            return (int.from_bytes(head[26:28], "little") & 0x3FFF,
                    int.from_bytes(head[28:30], "little") & 0x3FFF)
        if kind == b"VP8L" and len(head) >= 25 and head[20] == 0x2F:
            bits = int.from_bytes(head[21:25], "little")
            return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
        return None

    @classmethod
    def _sniff_format(cls, head: bytes):
        """The PIL format name the first bytes of a file show, or None."""
        if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
            return "WEBP"
        for magic, name in cls._LAZY_MAGIC:
            if head.startswith(magic):
                return name
        return None

    @classmethod
    def _open_lazy(cls, source):
        """OPENER: open a path or bytes as an image whose open reads only a header.

        It hands back an image it has not walked: every caller walks frames through
        `_reachable_frames`, or says in its own docstring that it reads frame 0 only
        (`test_every_caller_of_the_opener_walks_frames_and_only_the_walker_seeks`).

        The format comes from the bytes at the front of the file, not from its
        name, and PIL is told to open it as that format and no other. Any other
        container is refused instead of handed to a plugin that may decode inside
        `open`: an ICO file holding a PNG did, and the PNG's own dimensions were
        decoded before any size could be asked. A WebP is the one listed format
        that decodes its first frame inside `open`, so its declared size is
        checked first and an over budget WebP is not opened.

        CONTRACT: everything `Image.open` can say about a file it cannot read comes
        out of here as `ImageRefused` (Pillow's pixel limit as its subclass
        `ImageOverPixelBudget`), with the exception class and message in the text.
        An entry point therefore needs one `except ImageRefused` and no list of
        Pillow's exceptions. Not folded in: a missing or unreadable FILE (raised by
        the header read before Pillow is involved) stays an operational error, and
        anything that is not an `Exception` (MemoryError, KeyboardInterrupt) is
        never swallowed.
        """
        from PIL import Image, UnidentifiedImageError
        import io

        if isinstance(source, (bytes, bytearray)):
            head, target, label = bytes(source[:32]), io.BytesIO(source), "image bytes"
        else:
            with open(source, "rb") as fh:
                head = fh.read(32)
            target, label = source, repr(os.path.basename(source))
        fmt = cls._sniff_format(head)
        if fmt is None:
            raise ImageRefused(
                f"cannot identify image file {label}: it is not a PNG, JPEG, GIF, "
                f"BMP, TIFF or WebP, and no other container is opened because some "
                f"decode inside open")
        if fmt == "WEBP":
            # A WebP decodes its first frame inside `open`, so its size is read
            # from the first chunk and checked before PIL is involved.
            size = cls._webp_size(head)
            if size is None:
                raise ImageRefused(
                    f"cannot identify image file {label}: its WebP header does not "
                    f"declare a size")
            over = cls._over_budget(*size, "opened")
            if over:
                raise ImageOverPixelBudget(over)
        plan = None
        if fmt == "GIF":
            # A GIF open and every seek allocate for the frame they land on, before
            # a caller can read its size. Its extents come from its own blocks.
            with (io.BytesIO(source) if isinstance(source, (bytes, bytearray))
                  else open(source, "rb")) as fh:
                plan = cls._gif_plan(fh)
            if plan is not None and plan.total and plan.allowed == 0:
                raise ImageOverPixelBudget(
                    cls._over_budget(*plan.refused_size, "opened"))
        try:
            img = Image.open(target, formats=[fmt])
        except Image.DecompressionBombError as exc:
            # Pillow's own pixel limit, hit while it read the header.
            raise ImageOverPixelBudget(
                f"{label} is over Pillow's pixel limit, so it was not opened "
                f"({exc.__class__.__name__}: {exc})") from exc
        except (UnidentifiedImageError, OSError, SyntaxError, ValueError,
                struct.error, EOFError) as exc:
            # Whatever the format plugin says about a file it cannot read is one
            # answer here, so no caller keeps a list of Pillow's exception types.
            # Pillow's "cannot identify" message carries an object repr, which
            # says nothing and changes on every run, so the class name stands alone.
            said = (exc.__class__.__name__ if isinstance(exc, UnidentifiedImageError)
                    else f"{exc.__class__.__name__}: {exc}")
            raise ImageRefused(
                f"cannot read image file {label}: Pillow could not open it as "
                f"{fmt} ({said})") from exc
        if plan is not None:
            img._sg_frame_plan = plan
        return img

    @classmethod
    def _gif_plan(cls, fp):
        """How many frames of a GIF may be seeked to, read without Pillow.

        Walks the blocks the way `GifImageFile._seek` does, so the frames counted
        here are the frames it will find, and keeps the canvas as it grows: the
        logical screen widened by each frame's rectangle. A frame is reachable if
        that canvas is within the budget. The canvas only grows, so the reachable
        frames are a prefix, and a frame's own rectangle sits inside its canvas,
        so the disposal bitmap a seek allocates for it is within the budget too.
        Returns None if the header is too short to say.
        """
        def u16(b, at):
            return b[at] | (b[at + 1] << 8)

        def data():
            # `GifImageFile.data`: one length byte, then that many bytes.
            n = fp.read(1)
            if n and n[0]:
                return fp.read(n[0])
            return None

        head = fp.read(13)
        if len(head) < 13:
            return None
        width, height = u16(head, 6), u16(head, 8)
        if head[10] & 128:
            fp.seek(3 << ((head[10] & 7) + 1), 1)
        total = allowed = 0
        refused = None
        while True:
            s = fp.read(1)
            if not s or s == b";":
                break
            found = False
            while True:
                if not s:
                    s = fp.read(1)
                if not s or s == b";":
                    break
                if s == b"!":
                    label = fp.read(1)
                    if not label:
                        break
                    block = data()
                    if label[0] == 254:
                        while block:
                            block = data()
                        s = b""
                        continue
                    while data():
                        pass
                elif s == b",":
                    d = fp.read(9)
                    if len(d) < 9:
                        break
                    x1 = u16(d, 0) + u16(d, 4)
                    y1 = u16(d, 2) + u16(d, 6)
                    width, height = max(width, x1), max(height, y1)
                    if d[8] & 128:
                        fp.seek(3 << ((d[8] & 7) + 1), 1)
                    if not fp.read(1):
                        break
                    found = True
                    break
                s = b""
            if not found:
                break
            total += 1
            if refused is None:
                if width * height > cls.MAX_IMAGE_PIXELS:
                    refused = (width, height)
                else:
                    allowed += 1
            while data():
                pass
        return _GifPlan(total, allowed, refused)

    @classmethod
    def _reachable_frames(cls, img, reader):
        """Walk the frames of an open image, seeking only where it is allowed.

        The one place a frame walk is driven. It yields the image parked on each
        frame in turn, and where the plan of a GIF says a frame is over the budget
        it yields a `FrameRefused` instead of seeking, and stops: the seek would
        allocate for that frame before its size could be asked. Other formats
        are checked after each seek by the caller, as before.
        """
        plan = getattr(img, "_sg_frame_plan", None)
        index = 0
        while True:
            if plan is not None and plan.allowed < plan.total and index >= plan.allowed:
                yield FrameRefused(index, cls._over_budget(
                    *plan.refused_size, f"decoded or read by {reader}"))
                return
            try:
                img.seek(index)
            except EOFError:
                return
            yield img
            index += 1

    @classmethod
    def _frames_depend(cls, img) -> bool:
        return getattr(img, "format", None) in cls._FRAMES_BUILD_ON_EACH_OTHER

    @staticmethod
    def _left_after_refusal(index, total, total_known, reader) -> str:
        """Name what a walk that stopped at a refused frame did not reach."""
        if total_known and total is not None:
            left = total - index - 1
            if left <= 0:
                return ""
            return (f"{left} later frame{'s' if left != 1 else ''} build on frame "
                    f"{index} and were not read by {reader}")
        return (f"the frames after frame {index} build on it and were not read "
                f"by {reader}")

    def _ocr_all_frames(self, image_path: str) -> List[Tuple[str, str]]:
        try:
            img = self._open_lazy(image_path)
        except Exception as exc:
            self.failures.append(f"image could not be opened for OCR: {exc}")
            return []
        return self._ocr_frames_of(img, source=os.path.basename(image_path))

    def _ocr_frames_of(self, img, source: str = "image") -> List[Tuple[str, str]]:
        """OCR each frame. Complete only if EVERY frame reached OCR."""
        # Frame 0 over the budget: do not walk the file. A GIF shares one canvas
        # size across its frames and each seek decodes, so stepping through 64 of
        # them would pay the cost 64 times. The refusal is named once.
        over = self._pixel_cap_failure(img)
        if over:
            self.failures.append(over)
            return []

        # Round 7 (ASTRA I1, same mechanism as QR): `n_frames` is a property that
        # PARSES, so a damaged later descriptor makes it RAISE -- and the `getattr`
        # default never fires, because it only covers a missing attribute, not a
        # getter that throws. Unguarded, that exception escaped to `dispatch`, which
        # reported "Image extraction failed" and lost OCR and metadata for the whole
        # file including the frames that read perfectly.
        try:
            total = getattr(img, "n_frames", 1) or 1
            total_known = True
        except Exception as exc:
            total, total_known = None, False
            self.failures.append(
                f"frame count unreadable for OCR ({exc.__class__.__name__}) — "
                f"frames after the first were NOT read by OCR")
        results: List[Tuple[str, str]] = []

        if not total_known:
            # Read the frame PIL already holds rather than abandoning the file.
            try:
                text = self._ocr_from_pil(img)
            except OCRUnavailable as exc:
                self.failures.append(str(exc))
                return results
            except Exception as exc:
                self.failures.append(
                    f"first frame not read by OCR ({exc.__class__.__name__})")
                return results
            if text.strip():
                results.append(("ocr", text))
            return results

        if total == 1:
            # The ordinary case, and the label stays `ocr` so nothing downstream
            # of a single-frame image sees a new source name.
            try:
                text = self._ocr_from_pil(img)
            except OCRUnavailable as exc:
                # Partial extraction, honestly labelled: EXIF and hidden-text
                # detection still run and can still catch something, but the image
                # is no longer fully inspected and the dispatcher has to say so.
                self.failures.append(str(exc))
                return results
            if text.strip():
                results.append(("ocr", text))
            return results

        # Round 8 (ASTRA J1). `ImageSequence.Iterator` yields THE SAME mutable
        # image object, re-seeked -- it does not yield independent frames. So
        # `list(...)` does not collect the sequence: it collects N references to
        # one object, and by the time the list is built every one of them is
        # parked on the LAST frame. The loop then OCR'd the final frame N times
        # while labelling the reads 0, 1, 2 -- so a file whose text sits anywhere
        # but the end came back with ZERO findings, `threat_found` False and
        # `inspection_complete` True. A false clean, from an eager list.
        #
        # The rule: READ EACH FRAME BEFORE ADVANCING, and snapshot it while the
        # object is still parked there. `while` + `next()` rather than `for`,
        # because building the iterator and stepping it are separately fallible
        # and everything read before a mid-sequence failure has to survive it.
        index = 0
        iterator = None
        try:
            iterator = iter(self._reachable_frames(img, "OCR"))
        except Exception as exc:
            self.failures.append(
                f"frame sequence unreadable for OCR ({exc.__class__.__name__}) — "
                f"only the first frame was read by OCR")

        if iterator is None:
            # The sequence is unreadable but the open frame is not; read it
            # rather than abandoning a file whose first frame is intact.
            try:
                text = self._ocr_from_pil(img)
            except OCRUnavailable as exc:
                self.failures.append(str(exc))
                return results
            except Exception as exc:
                self.failures.append(
                    f"first frame not read by OCR ({exc.__class__.__name__})")
                return results
            if text.strip():
                results.append(("ocr", text))
            return results

        while index < self.MAX_OCR_FRAMES:
            try:
                frame = next(iterator)
            except StopIteration:
                break
            except Exception as exc:
                # A damaged descriptor part-way through. Keep every frame already
                # read and name where the walk stopped; how much lies beyond it
                # is genuinely unknown, so the message does not pretend to know.
                self.failures.append(
                    f"frame {index} could not be reached for OCR "
                    f"({exc.__class__.__name__}) — that frame and any after it "
                    f"were NOT read by OCR")
                break
            if isinstance(frame, FrameRefused):
                # The plan of a GIF refused it before the seek: nothing was
                # allocated for it, and every later frame builds on it.
                self.failures.append(f"frame {frame.index}: {frame.message}")
                left = self._left_after_refusal(frame.index, total, total_known, "OCR")
                if left:
                    self.failures.append(left)
                break
            over = self._pixel_cap_failure(frame)
            if over:
                self.failures.append(f"frame {index}: {over}")
                if self._frames_depend(img):
                    # The next seek builds the next frame on this one, which
                    # decodes it. Stop here and say what was left.
                    left = self._left_after_refusal(index, total, total_known, "OCR")
                    if left:
                        self.failures.append(left)
                    break
                # Pages of a TIFF stand alone: the others are still read.
                index += 1
                continue
            try:
                # Snapshot AT this position. The iterator hands back the shared
                # object, so anything that defers the actual read until after the
                # next `seek` would read the wrong frame -- which is J1 exactly.
                target = frame.convert("RGB")
            except Exception as exc:
                self.failures.append(
                    f"frame {index} not converted for OCR "
                    f"({exc.__class__.__name__}: {exc}) — its text was NOT read")
                index += 1
                continue
            try:
                text = self._ocr_from_pil(target)
            except OCRUnavailable as exc:
                # OCR being UNAVAILABLE is a property of the machine, not of this
                # frame: Tesseract missing from PATH fails identically on all of
                # them. Retrying would launch it up to 64 times and stack 64
                # copies of one sentence in the warnings a human has to read, so
                # the loss is reported once, for the whole file, and names the
                # scope. (T9's review catch.)
                remaining = min(total, self.MAX_OCR_FRAMES) - index
                self.failures.append(
                    f"{remaining} of {total} frames not read by OCR ({exc})")
                break
            except Exception as exc:
                # A per-FRAME failure, by contrast, really is per frame: one
                # corrupt frame in a GIF costs that frame and nothing else.
                self.failures.append(
                    f"frame {index} not read ({exc.__class__.__name__}: {exc})")
                index += 1
                continue
            if text.strip():
                results.append((f"ocr:frame:{index}", text))
            index += 1

        if total_known and total > self.MAX_OCR_FRAMES:
            self.failures.append(
                f"{total - self.MAX_OCR_FRAMES} of {total} frames not inspected — "
                f"{source} exceeds the {self.MAX_OCR_FRAMES}-frame OCR cap")
        return results

    def _metadata_all_frames(self, image_path: str) -> List[Tuple[str, str]]:
        """EXIF and embedded text from every frame, not just the one PIL opens on."""
        try:
            img = self._open_lazy(image_path)
        except Exception as exc:
            self.failures.append(
                f"image metadata not read ({exc.__class__.__name__}: {exc})")
            return []

        return self._metadata_frames_of(img, source=os.path.basename(image_path))

    def _metadata_frames_of(self, img, source: str = "image") -> List[Tuple[str, str]]:
        """EXIF and embedded text from every frame of an ALREADY-OPEN image.

        v0.5.6 round 7 (ASTRA I2). Split out of `_metadata_all_frames` so the
        in-memory API can run the SAME bounded walk instead of its own single read.
        Round 6 gave `extract_from_bytes` a `seek(0)` and one `_exif_from_pil()`
        call, which fixed the first page by BREAKING the last: on ASTRA's controls
        the bytes API went 0 -> 7 findings for page-0-only metadata and 7 -> 0 for
        page-1-only, with an empty `failures` list either way. Trading one page's
        findings for another's is not a repair, and a silent trade is the same
        false-completeness defect wearing different clothes.

        The frame-count query is also hardened here for the I1 reason: `n_frames`
        is a property that PARSES, so a damaged later descriptor makes it raise, and
        `getattr(..., 1)` does not catch a getter that throws. Frames we can read
        are read; what we cannot reach is named.
        """
        try:
            total = getattr(img, "n_frames", 1) or 1
            total_known = True
        except Exception as exc:
            total, total_known = None, False
            self.failures.append(
                f"frame count unreadable for metadata ({exc.__class__.__name__}) — "
                f"frames after the first were NOT inspected for metadata")

        if total_known and total == 1:
            return self._exif_from_pil(img)

        results: List[Tuple[str, str]] = []
        seen = set()

        def _collect(frame, index):
            for field, text in self._exif_from_pil(frame):
                # Frame 0 keeps the bare label so nothing downstream sees a new
                # source name for the ordinary single-page case; later frames are
                # labelled, and identical values repeated across frames (a tag
                # inherited by every page) are reported once.
                label = field if index == 0 else f"frame:{index}:{field}"
                key = (field, text)
                if key in seen:
                    continue
                seen.add(key)
                results.append((label, text))

        iterator = None
        try:
            iterator = iter(self._reachable_frames(img, "the metadata reader"))
        except Exception as exc:
            self.failures.append(
                f"frame sequence unreadable for metadata ({exc.__class__.__name__}) "
                f"— only the first frame's metadata was inspected")

        if iterator is None:
            # The I1 shape on the metadata side: the sequence is unreadable, the
            # frame PIL already holds is not, and that is where a known finding can
            # live. Read it rather than returning nothing.
            try:
                _collect(img, 0)
            except Exception as exc:
                self.failures.append(
                    f"first frame metadata not read ({exc.__class__.__name__}: {exc})")
            return results

        index = 0
        while index < self.MAX_OCR_FRAMES:
            try:
                frame = next(iterator)
            except StopIteration:
                break
            except Exception as exc:
                self.failures.append(
                    f"frame {index} could not be reached for metadata "
                    f"({exc.__class__.__name__}) — that frame and any after it were "
                    f"NOT inspected for metadata")
                break
            if isinstance(frame, FrameRefused):
                self.failures.append(f"frame {frame.index}: {frame.message}")
                left = self._left_after_refusal(
                    frame.index, total, total_known, "the metadata reader")
                if left:
                    self.failures.append(left)
                break
            try:
                _collect(frame, index)
            except Exception as exc:
                self.failures.append(
                    f"frame {index} metadata not read "
                    f"({exc.__class__.__name__}: {exc})")
            if self._pixel_cap_failure(frame) and self._frames_depend(img):
                # The next seek builds the next frame on this refused one, which
                # decodes it. Stop and say what was left.
                left = self._left_after_refusal(
                    index, total, total_known, "the metadata reader")
                if left:
                    self.failures.append(left)
                break
            index += 1

        if total_known and total > self.MAX_OCR_FRAMES:
            self.failures.append(
                f"metadata for {total - self.MAX_OCR_FRAMES} of {total} frames not "
                f"read — {source} exceeds the "
                f"{self.MAX_OCR_FRAMES}-frame cap")
        return results

    def _extract_ocr(self, image_path: str) -> str:
        """Run OCR on the image to extract visible text. **FRAME 0 ONLY — UNUSED.**

        v0.5.6 round 6 frame sweep: this has NO callers. `extract()` routes through
        `_ocr_all_frames()`, which walks the sequence. It is kept because it is the
        single-image primitive the frame walker is built on, but it reads frame 0
        and nothing else, so wiring it back into an extraction path would silently
        reintroduce the H1/G1 class. Use `_ocr_all_frames()`; if you need one frame,
        say so at the call site.

        Raises OCRUnavailable if OCR could not run. It must NEVER return the error
        as text: the returned string is scanned as document content, so an error
        string was counted as successfully extracted content and an image whose OCR
        never ran came back inspected and clean. That is the same false-success class
        the audio transcription path was repaired for.
        """
        try:
            img = self._open_lazy(image_path)
        except Exception as e:
            raise OCRUnavailable(f"image could not be opened for OCR: {e}") from e
        return self._ocr_from_pil(img)

    def _ocr_from_pil(self, img) -> str:
        """Run OCR on a PIL Image object. Raises OCRUnavailable on any failure."""
        import pytesseract

        over = self._pixel_cap_failure(img)
        if over:
            raise OCRUnavailable(over)
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
        """Extract text-containing EXIF metadata fields. **FRAME 0 ONLY — UNUSED.**

        v0.5.6 round 6 frame sweep: no callers; `extract()` uses
        `_metadata_all_frames()`. Same warning as `_extract_ocr` -- it reads the
        frame PIL opens on, so it must not be re-wired into an extraction path.

        v0.5.6 round 4: `except Exception: return []` made "this image has no
        metadata" and "we could not read this image's metadata" the same answer.
        The second one is a coverage loss and now says so.
        """
        try:
            img = self._open_lazy(image_path)
        except Exception as exc:
            self.failures.append(
                f"image metadata not read ({exc.__class__.__name__}: {exc})")
            return []
        return self._exif_from_pil(img)

    # EXIF text tags whose value can legitimately arrive as BYTES, and how the
    # spec says to read them. v0.5.6 round 5 (ASTRA G2): the extractor named
    # XPComment as a supported field and then admitted `str` values only, so a
    # byte-valued XPComment -- which is the ONLY way Windows writes it -- was
    # dropped, and `exif-xpcomment.jpg` came back exit 0, complete, clean while
    # the same bytes decoded by hand and handed to the same engine produced five
    # findings. Naming a field as supported and then not reading it is the
    # release's own defect in miniature.
    #
    # Scope is deliberately narrow: ONLY these text-typed tags. MakerNote, ICC
    # profiles and other binary blocks are not text and must NOT be reported as
    # failed text -- ASTRA asked for that explicitly, and a scanner that calls
    # every binary EXIF block "undecodable text" is one nobody reads the warnings
    # of.
    _EXIF_TEXT_FIELDS = {
        'ImageDescription', 'Make', 'Model', 'Software',
        'Artist', 'Copyright', 'UserComment', 'XPComment',
        'XPAuthor', 'XPKeywords', 'XPSubject', 'XPTitle',
    }
    # EXIF 2.3: the XP* tags (0x9C9B-0x9C9F) are UTF-16LE, NUL-terminated.
    _EXIF_UTF16_FIELDS = {'XPComment', 'XPAuthor', 'XPKeywords', 'XPSubject', 'XPTitle'}
    # EXIF UserComment: an 8-byte character-code header, then the payload.
    _USER_COMMENT_CHARSETS = {
        b"ASCII\x00\x00\x00": "ascii",
        b"UNICODE\x00": "utf-16",
        b"JIS\x00\x00\x00\x00\x00": "shift_jis",
        b"\x00" * 8: "utf-8",          # "undefined" -- try UTF-8 and say if it fails
    }

    @staticmethod
    def _decode_spans(raw: bytes, encoding: str):
        """Decode with `encoding`, keeping everything that decodes and counting the
        decoder's ACTUAL error spans.

        Returns ``(text, undecodable_bytes, first_bad_offset)``. This is
        `dispatch.decode_lossy`'s method generalised to a named codec: each
        `UnicodeDecodeError` reports the exact ``[start, end)`` it could not read,
        so the count is a fact about the INPUT. A legitimate U+FFFD in the source
        is preserved and NOT counted, which is the whole point (ASTRA I5a).
        """
        # Round 8 (ASTRA J2). A BOM selects byte order ONCE, for the whole field,
        # and it sits only at offset 0. The loop below restarts decoding at the
        # byte after each error span -- past the BOM -- so with the generic
        # "utf-16" codec every recovery read fell back to Python's default LITTLE
        # endian. A big-endian field's readable remainder was then decoded in the
        # wrong order and the known finding was lost, while the byte count stayed
        # right: an honest number attached to unreadable text.
        #
        # So resolve the order once, here, and strip the BOM before the loop; the
        # spans are still measured on the input, and `first_bad` is shifted back
        # to an offset into the ORIGINAL bytes so the number stays a fact about
        # what the caller handed us.
        bom_offset = 0
        if encoding == "utf-16":
            if raw[:2] == b"\xff\xfe":
                encoding, bom_offset = "utf-16-le", 2
            elif raw[:2] == b"\xfe\xff":
                encoding, bom_offset = "utf-16-be", 2
            else:
                # No BOM: Python's "utf-16" reads little endian. Name that, so
                # recovery uses the same order as the first read instead of
                # silently re-deciding it.
                encoding = "utf-16-le"
            raw = raw[bom_offset:]

        parts = []
        undecodable = 0
        first_bad = None
        index = 0
        while index < len(raw):
            try:
                parts.append(raw[index:].decode(encoding))
                break
            except UnicodeDecodeError as exc:
                head = raw[index:index + exc.start]
                if head:
                    parts.append(head.decode(encoding, errors="ignore"))
                if first_bad is None:
                    first_bad = index + exc.start
                undecodable += exc.end - exc.start
                index += exc.end
        if first_bad is not None:
            first_bad += bom_offset
        return "".join(parts), undecodable, first_bad

    def _decode_partial(self, raw: bytes, encoding: str):
        """Decode `raw`, KEEPING every unit that decodes, and name what did not.

        Returns ``(text, loss)`` where `loss` is None or a human phrase describing
        the damage. Both may be set: that is a PARTIAL read -- readable text plus
        a named loss -- and it is the whole point of this helper.

        v0.5.6 round 6 (ASTRA H3). Two measurement rules, both learned the hard way:

          * for a byte-oriented encoding the loss is measured on the INPUT, via
            `decode_lossy`, which sums the exact `[start, end)` spans the decoder
            could not read. That is the G5 rule -- never publish a number about
            the decoder's output as if it were a fact about the input.
          * for UTF-16 there is no such span, so we say what we actually measured:
            REPLACED UNITS, not bytes. A legitimate U+FFFD in the source inflates
            that count, so calling it "bytes not inspected" would be a claim we
            cannot support. The wording is the honest one.
        """
        if not raw:
            return "", None

        if encoding in ("utf-16", "utf-16-le", "utf-16-be"):
            try:
                return raw.decode(encoding).rstrip("\x00"), None
            except UnicodeDecodeError:
                pass
            # v0.5.6 round 7 (ASTRA I5a). Round 6 decoded with `errors="replace"`
            # and counted U+FFFD in the RESULT. Renaming that count from "bytes" to
            # "units" did not fix it: a LEGITIMATE U+FFFD in the source inflates the
            # number, so a field holding one valid replacement character plus one
            # incomplete trailing unit was reported as TWO undecodable units. One of
            # them was valid input. That is the G5 invariant again -- a number about
            # the decoder's output published as a fact about the input -- and I
            # walked into it in the very function whose comment describes it.
            #
            # Count the decoder's OWN error spans instead, exactly as `decode_lossy`
            # does for the byte-oriented encodings, and keep every valid character.
            text, undecodable, first_bad = self._decode_spans(raw, encoding)
            return text.rstrip("\x00"), (
                f"{undecodable} byte(s) could not be decoded and were NOT inspected "
                f"(first at offset {first_bad}); the text that decoded WAS scanned")

        if encoding in (None, "ascii", "utf-8"):
            from .dispatch import decode_lossy
            text, undecodable, first_bad = decode_lossy(raw)
            if not undecodable:
                return text.rstrip("\x00"), None
            return text.rstrip("\x00"), (
                f"{undecodable} byte(s) could not be decoded and were NOT "
                f"inspected (first at offset {first_bad}); the text that "
                f"decoded WAS scanned")

        try:
            return raw.decode(encoding).rstrip("\x00"), None
        except UnicodeDecodeError:
            pass
        text, undecodable, first_bad = self._decode_spans(raw, encoding)
        return text.rstrip("\x00"), (
            f"{undecodable} byte(s) could not be decoded and were NOT inspected "
            f"(first at offset {first_bad}); the text that decoded WAS scanned")

    def _decode_exif_text(self, tag_name: str, value: bytes):
        """Decode one byte-valued EXIF text field per its field encoding.

        Returns ``(text, failure)``. **Either, neither, or BOTH may be set** --
        that signature changed in v0.5.6 round 6 and the caller changed with it.

        It used to be "exactly one of them is None": one undecodable byte rejected
        the WHOLE field and returned text=None. ASTRA H3 showed what that costs. A
        proper nested UserComment with an ASCII header yields six findings, exit 1.
        Add ONE bad byte at either end and this candidate returned zero findings and
        exit 3 -- while the PREVIOUS wheel still found all six. The incomplete flag
        was honest and the finding was still gone, and an honest flag does not
        repair a lost finding: a scanner that drops a whole injection because its
        last byte is malformed is a scanner an attacker appends one byte to.

        So this now behaves like `_decode_embedded_text` already did for GIF/PNG
        chunks: keep what decodes, scan it, and report the loss so coverage is
        still marked incomplete. Retention and honesty are not a trade.
        """
        if tag_name in self._EXIF_UTF16_FIELDS:
            text, loss = self._decode_partial(bytes(value), "utf-16-le")
            if loss is None:
                return text, None
            return text, f"EXIF {tag_name} partially decoded — {loss}"

        if tag_name == "UserComment" and len(value) >= 8:
            encoding = self._USER_COMMENT_CHARSETS.get(bytes(value[:8]))
            payload = bytes(value[8:])
            if encoding:
                text, loss = self._decode_partial(payload, encoding)
                if loss is None:
                    return text, None
                return text, (f"EXIF UserComment partially decoded "
                              f"(declared {encoding}) — {loss}")
            # An unrecognised character-code header is not a reason to throw the
            # payload away either; we read it as bytes and say the header was not
            # understood. Same rule, one step further out.
            text, loss = self._decode_partial(payload, None)
            return text, (f"EXIF UserComment character-code header not recognised "
                          f"({len(payload)} bytes read as UTF-8)"
                          + (f" — {loss}" if loss else ""))

        text, loss = self._decode_partial(bytes(value), "utf-8")
        if loss is None:
            return text, None
        return text, f"EXIF {tag_name} partially decoded — {loss}"

    # PIL puts BINARY blocks in `img.info` beside the text chunks: the raw EXIF
    # segment, ICC profiles, Photoshop resources, palettes. Those are not text and
    # must not be reported as undecodable text -- ASTRA asked for that boundary
    # explicitly, and it matters: on `exif-xpcomment.jpg` the raw `exif` blob has
    # a few bytes that are not UTF-8, which made the file read as INCOMPLETE for a
    # reason that was not true. The XPComment inside it is read properly by the
    # EXIF path above; the container it arrived in is not a text field.
    # Every entry here must be a container that is BINARY BY FORMAT. The test is
    # not "PIL gave me bytes" -- almost everything in `info` is bytes -- it is
    # "there is no text encoding defined for this block".
    #
    # `xmp` was in this list for about twenty minutes and that was a real bug I
    # introduced while fixing G2: XMP is an XML TEXT packet that merely arrives as
    # bytes, and a `dc:description` inside it is exactly the kind of place an
    # instruction hides. It made `xmp-description.jpg` -- 8 findings when the
    # packet is scanned -- come back exit 0, complete, clean. Excluding a text
    # format as "binary" is the same false-coverage move as never reading it, so
    # the bar for adding a key here is a format with no text encoding at all.
    _BINARY_INFO_KEYS = {
        "exif",              # raw EXIF segment; its text fields are read above
        "icc_profile", "photoshop", "adobe", "adobe_transform", "mpinfo",
        "palette", "transparency", "background", "extension",
        "chromaticity", "gamma", "srgb", "interlace",
        "dpi", "aspect", "loop", "duration", "version",
    }

    def _decode_embedded_text(self, key: str, value: bytes):
        """Decode an embedded text chunk (PNG tEXt/iTXt/zTXt, GIF comment).

        Returns (text, failure). Unlike the EXIF path this KEEPS what decoded: a
        GIF comment with three bad bytes and a paragraph of readable instructions
        must still yield the instructions AND report the loss. `errors="ignore"`
        used to do the first half and silently skip the second, which is how
        `partial-comment.gif` produced six findings beside `inspection_complete:
        true` (ASTRA G2).
        """
        try:
            return value.decode("utf-8"), None
        except UnicodeDecodeError as exc:
            first_bad = exc.start      # NOT swallowed -- handled immediately below
        from .dispatch import decode_lossy
        text, undecodable, first_bad = decode_lossy(value)
        return text, (f"embedded text {key!r}: {undecodable} byte(s) undecodable and "
                      f"NOT inspected (first at offset {first_bad}); the rest of the "
                      f"field was scanned")

    @staticmethod
    def _classify_exif_container(raw: bytes):
        """Decide from the CONTAINER whether zero tags means empty or broken.

        Returns ``(state, detail)`` with state in {"empty", "populated", "unreadable"}.

        v0.5.6 round 7 (ASTRA I3). Round 6 asked Pillow's warnings whether the
        parse had failed, and that turned out to be unreliable in both directions:
        the "Corrupt EXIF data" warning escapes a `catch_warnings(record=True)`
        block entirely on the `_getexif()` path (measured -- it prints to stderr
        while `caught` stays empty), so a genuinely broken block could look silent.
        Chattiness is not evidence.

        The container answers the question itself. An EXIF block is a TIFF header
        (byte order, magic 42, IFD0 offset) followed by a 2-byte entry count. A
        count of ZERO is a valid, successful, empty parse -- Pillow writes exactly
        that, and calling it a loss is a false claim about a clean file. A count
        that is nonzero while the block is too short to hold those entries, or a
        header/offset that does not resolve, is a real failure.

        This reads four fixed fields; it is deliberately NOT a parser and decodes no
        tag. ASTRA's bound for this round was to distinguish the states without
        starting a parser project, and reading the one field that states the entry
        count is the smallest thing that can.
        """
        import struct

        blob = raw[6:] if raw[:6] == b"Exif\x00\x00" else raw
        if len(blob) < 8:
            return "unreadable", f"{len(blob)} bytes, shorter than a TIFF header"
        order = blob[:2]
        if order == b"II":
            endian = "<"
        elif order == b"MM":
            endian = ">"
        else:
            return "unreadable", "no TIFF byte-order mark"
        try:
            magic, offset = struct.unpack(endian + "HI", blob[2:8])
        except Exception as exc:
            return "unreadable", f"header not readable ({exc.__class__.__name__})"
        if magic != 42:
            return "unreadable", f"bad TIFF magic {magic}"
        if offset + 2 > len(blob):
            return "unreadable", (f"IFD0 offset {offset} beyond the "
                                  f"{len(blob)}-byte block")
        (count,) = struct.unpack(endian + "H", blob[offset:offset + 2])
        if count == 0:
            return "empty", "0 entries declared"
        needed = offset + 2 + count * 12
        if needed > len(blob):
            return "unreadable", (f"{count} entries declared, needs {needed} bytes, "
                                  f"block is {len(blob)}")
        return "populated", f"{count} entries"

    def _exif_tags(self, img, header_only: bool = False) -> dict:
        """Every EXIF tag PIL can give us, for every format that carries EXIF.

        v0.5.6 round 5, second pass (T9). This used to be
        `img._getexif() if hasattr(img, "_getexif") else None`. `_getexif` is a
        JPEG-era private method: **TIFF does not have it**, so `hasattr` came back
        False and EXIF was skipped ENTIRELY for a format this extractor routes and
        supports. `tiff-description.tiff` -- an ImageDescription tag holding an
        instruction, a field named in `_EXIF_TEXT_FIELDS` -- returned exit 0,
        complete, clean. The capability check was real; it was checking for the
        wrong capability, and the honest-absence branch swallowed the difference.

        The public `getexif()` works on both. `get_ifd(0x8769)` is needed as well
        because the Exif sub-IFD is where `UserComment` actually lives, and the
        old private call merged it silently -- so switching to the public API
        without this would have traded a TIFF miss for a UserComment miss.
        """
        import warnings as _warnings

        tags = {}
        parser_errors = []
        # v0.5.6 round 6 (ASTRA H2). Pillow does NOT raise on a damaged EXIF block:
        # it emits `UserWarning: Corrupt EXIF data` and hands back an empty tag set.
        # Catching exceptions therefore proved nothing about the parsers that warn,
        # and a count of caught exception patterns cannot stand in for handling them.
        # Record warnings around the whole parse and read them as evidence.
        with _warnings.catch_warnings(record=True) as caught:
            _warnings.simplefilter("always")
            getexif = getattr(img, "getexif", None)
            if header_only:
                # `getexif()` on a PNG decodes the pixels to reach chunks stored
                # after them. Read only the EXIF block the header already holds.
                getexif = self._header_exif
            if getexif is not None:
                try:
                    base = getexif(img) if header_only else getexif()
                except Exception as exc:
                    base = None
                    parser_errors.append(f"{exc.__class__.__name__}: {exc}")
                if base:
                    tags.update(dict(base))
                    try:
                        tags.update(dict(base.get_ifd(0x8769)))   # Exif sub-IFD
                    except Exception as exc:
                        # An ABSENT sub-IFD returns {} and never lands here, so
                        # reaching this branch means one exists and would not parse --
                        # and `UserComment` lives in it. Swallowing that is the exact
                        # defect this release is about, so it costs coverage.
                        self.failures.append(
                            f"EXIF sub-IFD not read ({exc.__class__.__name__}: {exc}) — "
                            f"UserComment and other sub-IFD text were NOT inspected")
            if not tags and not header_only and hasattr(img, "_getexif"):
                try:
                    tags = dict(img._getexif() or {})
                except Exception as exc:
                    tags = {}
                    parser_errors.append(f"{exc.__class__.__name__}: {exc}")

            # Only warnings ABOUT metadata parsing count. ASTRA was explicit that an
            # unrelated resource warning (Pillow's "unclosed file", say) must not be
            # rebranded as corrupt metadata -- a scanner that cries corruption at
            # every stray warning is one nobody reads the warnings of.
            metadata_warnings = [
                str(w.message) for w in caught
                if "exif" in str(w.message).lower() or "ifd" in str(w.message).lower()
            ]

        # An absent EXIF block is an HONEST ABSENCE and stays clean: PNGs and most
        # GIFs simply have none, and calling that a failure would make every clean
        # file incomplete. A PRESENT raw container that yielded no tags is the
        # opposite -- bytes that exist, were meant to be read, and were not. The raw
        # container is excluded from the text path (`_BINARY_INFO_KEYS`), and that
        # exclusion is only honest while its failure to parse is reported here.
        raw_exif = b""
        try:
            info = getattr(img, "info", None) or {}
            raw_exif = info.get("exif") or b""
        except Exception:
            raw_exif = b""

        # v0.5.6 round 7 (ASTRA I3). Round 6 treated "container present + zero tags"
        # as failure, and that was too broad: **zero tags is also the correct result
        # of a successful parse of an EMPTY block.** Pillow writes exactly that --
        # `empty-exif.jpg` is a valid 20-byte zero-entry EXIF that decodes cleanly,
        # emits no warning and loads its raster -- and round 6 turned it from
        # 0/complete into 3/incomplete, claiming text fields went uninspected when
        # there were none to inspect. A false loss claim is the mirror image of a
        # false clean, and it costs the warnings their meaning.
        #
        # Three states, not two: ABSENT (no container -> clean), SUCCESSFULLY EMPTY
        # (container, zero tags, parser silent -> clean), and FAILED (container,
        # zero tags, parser warned or raised -> named loss). The evidence that
        # separates the last two is the parser's own complaint, which is why the
        # warning capture above exists -- short-ifd/far-ifd warn, empty-exif does not.
        if raw_exif and not tags:
            state, detail = self._classify_exif_container(raw_exif)
            if state != "empty":
                # Broken, or declaring entries none of which decoded. Either way
                # bytes that were meant to be read were not, and that costs coverage.
                extra = "; ".join(metadata_warnings or parser_errors)
                self.failures.append(
                    f"EXIF present but not parsed ({len(raw_exif)} bytes, {detail}"
                    + (f"; {extra}" if extra else "") +
                    f") — its text fields were NOT inspected")
            # state == "empty" falls through: a successful parse of a block that
            # genuinely holds nothing is CLEAN and COMPLETE, exactly like absence.
        elif metadata_warnings:
            # Tags came back, but the parser still complained: part of the block was
            # readable and part was not, so coverage is partial, not complete.
            self.failures.append(
                f"EXIF partially parsed ({'; '.join(metadata_warnings)}) — some "
                f"metadata text may NOT have been inspected")
        return tags

    @staticmethod
    def _header_exif(img):
        """The EXIF block PIL read while opening, without touching the pixels."""
        from PIL import Image

        exif = Image.Exif()
        raw = (getattr(img, "info", None) or {}).get("exif")
        if raw:
            exif.load(raw)
        return exif

    def _exif_from_pil(self, img) -> List[Tuple[str, str]]:
        """Extract text from EXIF data of a PIL Image."""
        from PIL.ExifTags import TAGS

        results = []

        # A frame over the pixel budget is read from its header alone, unless its
        # format keeps all its metadata there. What the format keeps after the
        # pixels is named, not read, because reading it decodes them.
        header_only = bool(
            self._pixel_cap_failure(img)
            and getattr(img, "format", None) not in self._METADATA_IN_HEADER)
        if header_only:
            self.failures.append(
                f"{getattr(img, 'format', None) or 'image'} metadata stored after the "
                f"pixel data was not read, because the image is over the pixel cap "
                f"and reading it would decode it")

        # Standard EXIF. A format that simply has no EXIF block (PNG, most GIFs)
        # is NOT a failure -- it is an honest absence -- so that case is detected
        # by capability rather than by catching the AttributeError it used to
        # raise into a bare `pass`. Only a real read error is a coverage loss.
        try:
            exif_data = self._exif_tags(img, header_only)
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, str(tag_id))
                    if tag_name not in self._EXIF_TEXT_FIELDS:
                        continue          # not a text tag: not ours to decode
                    if isinstance(value, str):
                        if len(value) > 5:
                            results.append((tag_name, value))
                        continue
                    if isinstance(value, (bytes, bytearray)):
                        text, failure = self._decode_exif_text(tag_name, bytes(value))
                        # `elif` here until v0.5.6 round 6. That single keyword WAS
                        # ASTRA H3: a partial decode reported the loss and then threw
                        # the readable half away, so the finding vanished and only the
                        # warning survived. Both branches now run -- name the loss AND
                        # scan what we read.
                        if failure:
                            self.failures.append(failure)
                        if text and len(text) > 5:
                            results.append((tag_name, text))
        except Exception as exc:
            self.failures.append(
                f"EXIF text fields not read ({exc.__class__.__name__}: {exc})")

        # Embedded text: PNG chunks (tEXt/iTXt/zTXt) and the GIF comment block.
        try:
            if hasattr(img, 'info') and img.info:
                for key, value in img.info.items():
                    if isinstance(value, str) and len(value) > 5:
                        results.append((f"png:{key}", value))
                    elif isinstance(value, (bytes, bytearray)):
                        if key.lower() in self._BINARY_INFO_KEYS:
                            continue      # a binary block, not a text field
                        text, failure = self._decode_embedded_text(key, bytes(value))
                        if failure:
                            self.failures.append(failure)
                        if text and len(text) > 5:
                            results.append((f"png:{key}", text))
        except Exception as exc:
            self.failures.append(
                f"embedded text chunks not read ({exc.__class__.__name__}: {exc})")

        return results

    def _detect_hidden_text(self, image_path: str) -> str:
        """
        Basic hidden text detection.

        FRAME 0 GEOMETRY ONLY, and that is a decision rather than the frame bug
        again (round 5, reviewed by T9; wording corrected in round 6 to ASTRA's
        precision). The claim "not a content source" was too absolute: the string
        this returns DOES include OCR text excerpts, and that string is scanned. So
        state it exactly -- what is limited to frame 0 is the GEOMETRY heuristic
        (tiny glyphs, edge placement), not the reading of later frames. A later
        frame's actual TEXT is already read by `_ocr_frames_of`,
        which walks every frame, so no content is lost by not re-running the
        geometry check per frame. If this ever becomes a content source, it needs
        the frame walk like everything else -- anything that reads "the image" has
        to ask which frame.

        Checks for signs that text might be hidden in the image:
        - Very small text regions (font-size effectively 0)
        - Text matching background color
        - Unusual amount of white/transparent space with OCR hits

        Returns warning string if suspicious, empty string if clean.
        """
        from PIL import Image
        import pytesseract

        try:
            img = self._open_lazy(image_path)
            width, height = img.size

            over = self._pixel_cap_failure(img)
            if over:
                self.failures.append(f"hidden-text detection did not run: {over}")
                return ""

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
        f"{os.path.basename(image_path)} not fully read — {failure}."
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
