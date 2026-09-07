"""
SUNGLASSES Audio Extractor — Scans audio for hidden prompt injection.

Extracts text from audio using speech-to-text:
1. Whisper transcription — converts speech to text, then scans
2. Metadata — reads audio file tags (title, artist, comment, lyrics)

Attack vectors this catches:
- Spoken prompt injection in voice messages
- Hidden voice commands buried in background audio
- Malicious instructions in podcast/meeting transcripts
- Attack text in audio metadata tags

Usage:
    from sunglasses.extractors.audio import scan_audio
    result = scan_audio("/path/to/voicemail.mp3")



Install: pip install sunglasses[all]  (requires whisper + ffmpeg)
"""

import os
import subprocess
import json
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
    """Check that audio scanning dependencies are installed."""
    missing = []
    try:
        import whisper  # noqa: F401
    except ImportError:
        missing.append("openai-whisper")
    # Check ffmpeg
    try:
        subprocess.run(['ffmpeg', '-version'], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        missing.append("ffmpeg (system)")
    if missing:
        raise ImportError(
            f"Audio scanning requires: {', '.join(missing)}. "
            f"Install with: pip install sunglasses[all] and brew install ffmpeg (Mac) or apt install ffmpeg (Linux)"
        )


class AudioExtractor:
    """Extract text from audio files for SUNGLASSES scanning."""

    def __init__(self, whisper_model: str = "base"):
        _check_deps()
        self._model_name = whisper_model
        self._model = None  # lazy load

    def _get_model(self):
        """Lazy-load Whisper model."""
        if self._model is None:
            import whisper
            self._model = whisper.load_model(self._model_name)
        return self._model

    warnings: List[str] = []

    def extract(self, audio_path: str) -> List[Tuple[str, str]]:
        """
        Extract all text from an audio file.

        Returns list of (source_label, extracted_text) tuples.
        """
        if not os.path.exists(audio_path):
            raise FileNotFoundError(f"Audio not found: {audio_path}")

        results = []
        # Reset per call: a failure from a previous file must never be reported
        # against this one, and a success must never inherit a stale warning.
        self.warnings = []

        # 1. Speech-to-text via Whisper
        transcript = self._transcribe(audio_path)
        if transcript.strip():
            results.append(("speech", transcript))

        # 2. Audio metadata (ID3 tags, etc.)
        meta_texts = self._extract_metadata(audio_path)
        for field, text in meta_texts:
            if text.strip():
                results.append((f"metadata:{field}", text))

        return results

    def _transcribe(self, audio_path: str) -> str:
        """Transcribe audio to text using Whisper.

        v0.5.6: a failure here used to RETURN the error message as the transcript.
        The engine then scanned "[Transcription error: ...]", found no attack in it —
        because there is none in an ffmpeg error — and the CLI reported PASS on a
        file it had never heard a second of. The failure text became the evidence.
        Failures are now recorded as warnings and produce NO content, so the scan is
        reported incomplete instead of clean.
        """
        try:
            model = self._get_model()
            result = model.transcribe(audio_path)
            return result.get("text", "").strip()
        except Exception as e:
            self.warnings.append(
                f"Audio not transcribed ({e.__class__.__name__}: {_brief(e)})."
            )
            return ""

    def _extract_metadata(self, audio_path: str) -> List[Tuple[str, str]]:
        """Extract text from audio file metadata using ffprobe.

        v0.5.6 round 4: this used to `except Exception: pass`. ffprobe missing,
        ffprobe crashing, or unparseable JSON all produced an empty tag list that
        is INDISTINGUISHABLE from a file with no tags -- so an attack hidden in a
        comment tag was reported as a fully inspected, clean file. Recovering the
        tags is not required; hiding that we gave up looking is the bug.
        """
        results = []
        try:
            cmd = [
                'ffprobe', '-v', 'quiet', '-print_format', 'json',
                '-show_format', audio_path
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if proc.returncode != 0:
                self.warnings.append(
                    f"Audio metadata tags not read (ffprobe exit {proc.returncode}) — "
                    f"text in title/comment/lyrics tags was NOT inspected."
                )
                return results
            data = json.loads(proc.stdout)
            tags = data.get('format', {}).get('tags', {})
            text_fields = ['title', 'artist', 'album', 'comment',
                           'description', 'lyrics', 'genre', 'composer']
            for field in text_fields:
                for key, value in tags.items():
                    if key.lower() == field and isinstance(value, str) and len(value) > 3:
                        results.append((field, value))
        except Exception as exc:
            self.warnings.append(
                f"Audio metadata tags not read ({exc.__class__.__name__}: {_brief(exc)}) — "
                f"text in title/comment/lyrics tags was NOT inspected."
            )
        return results


def scan_audio(audio_path: str, engine=None, whisper_model: str = "base") -> dict:
    """
    Convenience function: extract text from audio and scan with SUNGLASSES.

    Returns the canonical result document (see ``sunglasses.result``): the three
    axes, coverage detail, findings, plus ``sources``/``results`` per extracted
    source.

    v0.5.6 round 4: this built its own per-source dictionaries out of the child
    ``ScanResult``, copying ``decision``/``severity``/``findings`` and DISCARDING
    ``truncated`` and ``extraction_complete``. A 1.2 M-character transcript with
    ``truncated: true`` on the child therefore came back through ``scan_deep()``
    as complete and clean. The fold now lives in one place for every extractor.
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
    _probe_readable(audio_path)

    # A decoder that gives up costs COVERAGE, never the scan, and never a
    # traceback -- the same contract `dispatch` has applied to these formats since
    # round 3. Until round 4 these five let ImportError and decoder errors escape
    # to the caller, so "no traceback on any supported path" had an exemption for
    # the public API a user is most likely to call first.
    try:
        extractor = AudioExtractor(whisper_model=whisper_model)
        texts = extractor.extract(audio_path)
        _failed = None
    except ImportError as exc:
        extractor, texts, _failed = None, [], (
            f"audio scanning requires: pip install sunglasses[audio] — nothing in "
            f"{os.path.basename(audio_path)} was inspected. ({exc})")
    except Exception as exc:
        extractor, texts, _failed = None, [], (
            f"audio extraction failed ({exc.__class__.__name__}) — nothing in "
            f"{os.path.basename(audio_path)} was inspected.")

    return aggregate(
        ((source, text, engine.scan(text, channel="file")) for source, text in texts),
        source=audio_path,
        warnings=list(getattr(extractor, "warnings", None) or [])
                 + ([_failed] if _failed else []),
        extra={"file": audio_path},
    )
