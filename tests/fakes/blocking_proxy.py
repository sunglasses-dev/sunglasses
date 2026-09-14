"""A proxy that forwards NOTHING, for proving the other half can fail.

Against this, T10.R1's s1 check must FAIL: the clean call never reaches the
server. A self test without this half passes against a mediator nobody can use.
"""
import sys


def main(argv):
    for _line in sys.stdin.buffer:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
