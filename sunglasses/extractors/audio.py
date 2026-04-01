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

Install: pip install glasses[audio]  (requires whisper + ffmpeg)
"""

import os
import subprocess
import json
from typing import List, Tuple


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

    def extract(self, audio_path: str) -> List[Tuple[str, str]]:
        """
        Extract all text from an audio file.

        Returns list of (source_label, extracted_text) tuples.
        """
        if not os.path.exists(audio_path):
            raise FileNotFoundError(f"Audio not found: {audio_path}")

        results = []

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
        """Transcribe audio to text using Whisper."""
        try:
            model = self._get_model()
            result = model.transcribe(audio_path)
            return result.get("text", "").strip()
        except Exception as e:
            return f"[Transcription error: {e}]"

    def _extract_metadata(self, audio_path: str) -> List[Tuple[str, str]]:
        """Extract text from audio file metadata using ffprobe."""
        results = []
        try:
            cmd = [
                'ffprobe', '-v', 'quiet', '-print_format', 'json',
                '-show_format', audio_path
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if proc.returncode == 0:
                data = json.loads(proc.stdout)
                tags = data.get('format', {}).get('tags', {})
                text_fields = ['title', 'artist', 'album', 'comment',
                               'description', 'lyrics', 'genre', 'composer']
                for field in text_fields:
                    for key, value in tags.items():
                        if key.lower() == field and isinstance(value, str) and len(value) > 3:
                            results.append((field, value))
        except Exception:
            pass
        return results


def scan_audio(audio_path: str, engine=None, whisper_model: str = "base") -> dict:
    """
    Convenience function: extract text from audio and scan with SUNGLASSES.

    Returns dict with:
        - sources: list of (source, text) extracted
        - results: list of scan results
        - is_clean: True if ALL extractions are clean
        - threats: list of findings from non-clean results
    """
    from sunglasses.engine import SunglassesEngine

    if engine is None:
        engine = SunglassesEngine()

    extractor = AudioExtractor(whisper_model=whisper_model)
    texts = extractor.extract(audio_path)

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
        "file": audio_path,
        "sources_found": len(texts),
        "is_clean": is_clean,
        "threats": threats,
        "results": results,
    }
