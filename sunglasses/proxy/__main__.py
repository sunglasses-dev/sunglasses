"""`python -m sunglasses.proxy`. The whole body is in commands.main.

Kept to three lines so the module that runs on import does nothing a test
cannot also call directly. An entry point with logic in it is an entry point no
test can reach without spawning a process.
"""
import sys

from .commands import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
