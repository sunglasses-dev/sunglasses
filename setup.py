from setuptools import setup, find_packages

setup(
    name="sunglasses",
    version="0.5.3",
    description="The input firewall for AI agents. Local-first, zero network calls, MIT.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://sunglasses.dev",
    author="AZ",
    author_email="contact@sunglasses.dev",
    project_urls={
        "Source": "https://github.com/sunglasses-dev/sunglasses",
        "Threat Database": "https://github.com/sunglasses-dev/sunglasses/tree/main/attack-db",
        "Issues": "https://github.com/sunglasses-dev/sunglasses/issues",
    },
    license="MIT",
    packages=find_packages(),
    # Claim only what CI proves. 3.8 has been EOL since Oct 2024 and was never
    # in the matrix; ">=3.8" was a claim about five versions backed by tests on
    # one. The matrix in .github/workflows/pattern-integrity.yml now covers every
    # version named here.
    python_requires=">=3.9",
    install_requires=[],
    extras_require={
        "dev": ["pytest"],
        "image": ["Pillow", "pytesseract"],
        "pdf": ["PyPDF2"],
        "qr": ["pyzbar", "Pillow"],
        # One name for "everything that reads a file that is not plain text".
        # The per-format extras stay for anyone who wants exactly one of them.
        "media": ["Pillow", "pytesseract", "PyPDF2", "pyzbar"],
        "audio": ["openai-whisper"],
        "video": ["openai-whisper"],
        "all": ["Pillow", "pytesseract", "PyPDF2", "pyzbar", "openai-whisper"],
    },
    include_package_data=True,
    package_data={
        "sunglasses": ["data/attacks/**/*.json"],
    },
    entry_points={
        "console_scripts": [
            "sunglasses=sunglasses.cli:main",
        ],
    },
    classifiers=[
        # 30+ releases, a full CI suite on five Python versions, a reproducible
        # benchmark and a firewall in production use. "Alpha" understated it to
        # every package index reader; Beta is the honest rung, and Production/Stable
        # would overstate it while the API can still move in a minor.
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
