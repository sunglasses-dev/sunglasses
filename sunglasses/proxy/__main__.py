"""`python -m sunglasses.proxy`. The whole body is in commands.main.

Kept to three lines so the module that runs on import does nothing a test
cannot also call directly. An entry point with logic in it is an entry point no
test can reach without spawning a process.
"""
import sys

from .commands import main

if __name__ == "__main__":
    # AR14. `serve.exit_process` leaves without finalizers ONLY when the
    # mediator's teardown has already completed, because a daemon thread
    # blocked on this process's stdin turns interpreter shutdown into SIGABRT
    # and the server's exit status is lost. Every other path raises SystemExit
    # exactly as before.
    from .serve import exit_process

    exit_process(main(sys.argv[1:]))
