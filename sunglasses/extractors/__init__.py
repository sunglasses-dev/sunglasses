"""
SUNGLASSES Extractors — Pull text from non-text sources for scanning.

Each extractor converts a media type into text, which then goes through
the standard SUNGLASSES engine for threat detection.

Architecture:
    Media file → Extractor → Text → SunglassesEngine.scan() → Decision

Available extractors:
    - image: OCR + EXIF metadata + hidden text detection
    - pdf: (coming soon)
    - audio: (coming soon)
    - video: (coming soon)
    - qr: (coming soon)
"""
