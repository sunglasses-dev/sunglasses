"""
SUNGLASSES Video Extractor — Scans video for hidden prompt injection.

Extracts text from video using multiple methods:
1. Subtitle tracks — SRT/VTT/ASS embedded subtitles
2. Audio track — speech-to-text via Whisper
3. Metadata — video file tags and properties
4. Frame OCR — (future) extract text visible in video frames

Usage:
    from sunglasses.extractors.video import scan_video
    result = scan_video("/path/to/meeting.mp4")



Install: pip install sunglasses[all]  (requires whisper + ffmpeg)
"""

import os
import subprocess
import json
import tempfile
import re
from typing import List, Tuple


def _brief(exc, limit=180):
    """First meaningful line of an exception, capped.

    ffmpeg answers a failure with its full build configuration: 1.5 KB of banner
    for one real sentence. A warning nobody reads is only marginally better than
    no warning, so keep the sentence and drop the banner.
    """
    for line in str(exc).splitlines():
        line = line.strip()
        if line and not line.startswith(("built with", "configuration:", "lib")):
            return line[:limit] + ("..." if len(line) > limit else "")
    text = " ".join(str(exc).split())
    return text[:limit] + ("..." if len(text) > limit else "")




def _check_deps():
    """Check that video scanning dependencies are installed."""
    missing = []
    try:
        import whisper  # noqa: F401
    except ImportError:
        missing.append("openai-whisper")
    try:
        subprocess.run(['ffmpeg', '-version'], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        missing.append("ffmpeg (system)")
    if missing:
        raise ImportError(
            f"Video scanning requires: {', '.join(missing)}. "
            f"Install with: pip install sunglasses[all] and brew install ffmpeg (Mac) or apt install ffmpeg (Linux)"
        )


class VideoExtractor:
    """Extract text from video files for SUNGLASSES scanning."""

    def __init__(self, whisper_model: str = "base"):
        _check_deps()
        self._model_name = whisper_model
        self._model = None

    def _get_model(self):
        if self._model is None:
            import whisper
            self._model = whisper.load_model(self._model_name)
        return self._model

    warnings: List[str] = []

    def extract(self, video_path: str) -> List[Tuple[str, str]]:
        """Extract all text from a video file."""
        if not os.path.exists(video_path):
            raise FileNotFoundError(f"Video not found: {video_path}")

        results = []
        self.warnings = []

        # 1. Subtitle tracks
        subs = self._extract_subtitles(video_path)
        for label, text in subs:
            if text.strip():
                results.append((label, text))

        # 2. Audio track → speech-to-text
        audio_text = self._extract_audio_transcript(video_path)
        if audio_text.strip():
            results.append(("audio_transcript", audio_text))

        # 3. Metadata
        meta = self._extract_metadata(video_path)
        for field, text in meta:
            if text.strip():
                results.append((f"metadata:{field}", text))

        return results

    def _extract_subtitles(self, video_path: str) -> List[Tuple[str, str]]:
        """Extract embedded subtitle tracks."""
        results = []
        try:
            # Find subtitle streams
            cmd = [
                'ffprobe', '-v', 'quiet', '-print_format', 'json',
                '-show_streams', '-select_streams', 's', video_path
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if proc.returncode != 0:
                self.warnings.append(
                    f"Subtitle tracks not read (ffprobe exit {proc.returncode}) — "
                    f"text in embedded subtitles was NOT inspected."
                )
                return results

            data = json.loads(proc.stdout)
            streams = data.get('streams', [])

            for i, stream in enumerate(streams):
                # Extract each subtitle track to text
                with tempfile.NamedTemporaryFile(suffix='.srt', delete=False) as tmp:
                    tmp_path = tmp.name

                lang = stream.get('tags', {}).get('language', f'track{i}')
                try:
                    cmd = [
                        'ffmpeg', '-v', 'quiet', '-i', video_path,
                        '-map', f'0:s:{i}', '-f', 'srt', tmp_path, '-y'
                    ]
                    conv = subprocess.run(cmd, capture_output=True, timeout=30)

                    # v0.5.6 round 5 (ASTRA G3). This return code was never read.
                    # ffmpeg fails, writes nothing, and the empty temp file was
                    # then read as "this track has no subtitles" -- so a failed
                    # conversion looked exactly like a track with no text in it,
                    # and the scan reported complete. ASTRA injected a nonzero
                    # code at this one subprocess and watched seven findings
                    # become zero, complete, clean.
                    #
                    # Both halves are checked, because either alone is passable:
                    # a nonzero code with output, and a zero code with an empty
                    # file, both mean we did not get the subtitles.
                    written = os.path.getsize(tmp_path) if os.path.exists(tmp_path) else 0
                    if conv.returncode != 0 or written == 0:
                        self.warnings.append(
                            f"Subtitle track {i} ({lang}) not converted "
                            f"(ffmpeg exit {conv.returncode}, {written} bytes written) — "
                            f"its text was NOT inspected."
                        )
                        continue

                    with open(tmp_path, 'r', errors='ignore') as f:
                        srt_text = f.read()

                    # Strip SRT formatting (timestamps, sequence numbers)
                    clean = self._clean_srt(srt_text)
                    if clean.strip():
                        results.append((f"subtitle:{lang}", clean))
                finally:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        # Temp-file cleanup only. Failing to delete a scratch file
                        # loses no scan coverage, which is why this one handler is
                        # allowed to stay quiet; every handler that CAN lose
                        # coverage names what it gave up on.
                        pass

        except Exception as exc:
            # v0.5.6 round 4: this `pass` made "no subtitle tracks" and "we could
            # not read the subtitle tracks" the same answer. Subtitles are a
            # first-class injection surface; losing them silently is a false clean.
            self.warnings.append(
                f"Subtitle tracks not read ({exc.__class__.__name__}: {_brief(exc)}) — "
                f"text in embedded subtitles was NOT inspected."
            )
        return results

    def _clean_srt(self, srt_text: str) -> str:
        """Strip SRT formatting, keep just the text."""
        lines = srt_text.split('\n')
        text_lines = []
        for line in lines:
            line = line.strip()
            # Skip empty lines, sequence numbers, timestamps
            if not line:
                continue
            if line.isdigit():
                continue
            if '-->' in line:
                continue
            # Strip HTML tags from subtitles
            line = re.sub(r'<[^>]+>', '', line)
            text_lines.append(line)
        return ' '.join(text_lines)

    def _extract_audio_transcript(self, video_path: str) -> str:
        """Extract audio track and transcribe with Whisper."""
        try:
            # Extract audio to temp wav
            with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as tmp:
                tmp_path = tmp.name

            try:
                cmd = [
                    'ffmpeg', '-v', 'quiet', '-i', video_path,
                    '-ac', '1', '-ar', '16000', '-f', 'wav', tmp_path, '-y'
                ]
                proc = subprocess.run(cmd, capture_output=True, timeout=120)
                if proc.returncode != 0:
                    self.warnings.append(
                        f"Video audio track not transcribed (ffmpeg exit "
                        f"{proc.returncode}) — spoken content was NOT inspected."
                    )
                    return ""

                model = self._get_model()
                result = model.transcribe(tmp_path)
                return result.get("text", "").strip()
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass          # temp-file cleanup only; no coverage is lost here

        except Exception as e:
            # Same repair as audio.py: an error string is not a transcript. Returning
            # it made a file we could not open look like a file we cleared.
            self.warnings.append(
                f"Video audio track not transcribed ({e.__class__.__name__}: {_brief(e)})."
            )
            return ""

    def _extract_metadata(self, video_path: str) -> List[Tuple[str, str]]:
        """Extract text from video metadata."""
        results = []
        try:
            cmd = [
                'ffprobe', '-v', 'quiet', '-print_format', 'json',
                '-show_format', video_path
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if proc.returncode == 0:
                data = json.loads(proc.stdout)
                tags = data.get('format', {}).get('tags', {})
                for key, value in tags.items():
                    if isinstance(value, str) and len(value) > 5:
                        results.append((key.lower(), value))
            else:
                self.warnings.append(
                    f"Video metadata tags not read (ffprobe exit {proc.returncode}) — "
                    f"text in the container tags was NOT inspected."
                )
        except Exception as exc:
            self.warnings.append(
                f"Video metadata tags not read ({exc.__class__.__name__}: {_brief(exc)}) — "
                f"text in the container tags was NOT inspected."
            )
        return results


def scan_video(video_path: str, engine=None, whisper_model: str = "base") -> dict:
    """Convenience function: extract text from a video and scan with SUNGLASSES.

    Returns the canonical result document (see ``sunglasses.result``). v0.5.6
    round 4: it built its own per-source dicts and dropped the child's
    ``truncated`` / ``extraction_complete`` -- a long transcript over the engine
    cap came back complete and clean.
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
    _probe_readable(video_path)

    # A decoder that gives up costs COVERAGE, never the scan, and never a
    # traceback -- the same contract `dispatch` has applied to these formats since
    # round 3. Until round 4 these five let ImportError and decoder errors escape
    # to the caller, so "no traceback on any supported path" had an exemption for
    # the public API a user is most likely to call first.
    try:
        extractor = VideoExtractor(whisper_model=whisper_model)
        texts = extractor.extract(video_path)
        _failed = None
    except ImportError as exc:
        extractor, texts, _failed = None, [], (
            f"video scanning requires: pip install sunglasses[video] — nothing in "
            f"{os.path.basename(video_path)} was inspected. ({exc})")
    except Exception as exc:
        extractor, texts, _failed = None, [], (
            f"video extraction failed ({exc.__class__.__name__}) — nothing in "
            f"{os.path.basename(video_path)} was inspected.")

    return aggregate(
        [(source, text, engine.scan(text, channel="file")) for source, text in texts],
        source=video_path,
        warnings=list(getattr(extractor, "warnings", None) or [])
                 + ([_failed] if _failed else []),
        extra={"file": video_path},
    )
