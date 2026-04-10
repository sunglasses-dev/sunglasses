from setuptools import setup, find_packages

setup(
    name="sunglasses",
    version="0.2.7",
    description="Sunglasses for AI agents. Protection layer + neighborhood watch.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://sunglasses.dev",
    project_urls={
        "Source": "https://github.com/sunglasses-dev/sunglasses",
        "Threat Database": "https://github.com/sunglasses-dev/sunglasses/tree/main/attack-db",
        "Issues": "https://github.com/sunglasses-dev/sunglasses/issues",
    },
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[],
    extras_require={
        "dev": ["pytest"],
        "image": ["Pillow", "pytesseract"],
        "pdf": ["PyPDF2"],
        "qr": ["pyzbar", "Pillow"],
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
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
