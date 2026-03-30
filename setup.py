from setuptools import setup, find_packages

setup(
    name="glasses",
    version="0.1.0",
    description="Sunglasses for AI agents. Protection layer + neighborhood watch.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://sunglasses.dev",
    project_urls={
        "Source": "https://github.com/sunglasses-dev/glasses",
        "Threat Registry": "https://github.com/sunglasses-dev/glasses/tree/main/registry",
        "Issues": "https://github.com/sunglasses-dev/glasses/issues",
    },
    license="AGPL-3.0",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[],
    entry_points={
        "console_scripts": [
            "glasses=glasses.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
