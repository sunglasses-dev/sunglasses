"""
SUNGLASSES Extractors — Pull text from non-text sources for scanning.

Each extractor converts a media type into text, which then goes through
the standard SUNGLASSES engine for threat detection.

Architecture:
    Media file → Extractor → Text → SunglassesEngine.scan() → Decision

Available extractors:
    - image: OCR + EXIF metadata + hidden text detection (pip install sunglasses[image])
    - pdf: Page text + metadata + annotations (pip install sunglasses[pdf])
    - qr: QR codes + barcodes in images (pip install sunglasses[qr])
    - audio: Whisper transcription + metadata (pip install sunglasses[all])
    - video: Subtitles + audio transcript + metadata (pip install sunglasses[all])
"""
