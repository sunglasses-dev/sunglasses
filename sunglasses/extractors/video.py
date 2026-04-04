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

    def extract(self, video_path: str) -> List[Tuple[str, str]]:
        """Extract all text from a video file."""
        if not os.path.exists(video_path):
            raise FileNotFoundError(f"Video not found: {video_path}")

        results = []

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
                return results

            data = json.loads(proc.stdout)
            streams = data.get('streams', [])

            for i, stream in enumerate(streams):
                # Extract each subtitle track to text
                with tempfile.NamedTemporaryFile(suffix='.srt', delete=False) as tmp:
                    tmp_path = tmp.name

                try:
                    cmd = [
                        'ffmpeg', '-v', 'quiet', '-i', video_path,
                        '-map', f'0:s:{i}', '-f', 'srt', tmp_path, '-y'
                    ]
                    subprocess.run(cmd, capture_output=True, timeout=30)

                    with open(tmp_path, 'r', errors='ignore') as f:
                        srt_text = f.read()

                    # Strip SRT formatting (timestamps, sequence numbers)
                    clean = self._clean_srt(srt_text)
                    if clean.strip():
                        lang = stream.get('tags', {}).get('language', f'track{i}')
                        results.append((f"subtitle:{lang}", clean))
                finally:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass

        except Exception:
            pass
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
                    return ""

                model = self._get_model()
                result = model.transcribe(tmp_path)
                return result.get("text", "").strip()
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        except Exception as e:
            return f"[Audio extraction error: {e}]"

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
        except Exception:
            pass
        return results


def scan_video(video_path: str, engine=None, whisper_model: str = "base") -> dict:
    """Convenience function: extract text from video and scan with SUNGLASSES."""
    from sunglasses.engine import SunglassesEngine

    if engine is None:
        engine = SunglassesEngine()

    extractor = VideoExtractor(whisper_model=whisper_model)
    texts = extractor.extract(video_path)

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
        "file": video_path,
        "sources_found": len(texts),
        "is_clean": is_clean,
        "threats": threats,
        "results": results,
    }
