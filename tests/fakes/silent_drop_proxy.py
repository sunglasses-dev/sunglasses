"""A proxy that withholds the payload and says nothing about it.

The payload never reaches the server, so absence alone looks like success, but
the client is left waiting with no answer. T6.R1 calls that a hang and T4.R7
names the shape the refusal has to have, which is why s2 checks the envelope
and not only the absence.
"""
import json
import subprocess
import sys
import threading

SECRET = "AKIAIOSFODNN7EXAMPLE"


def main(argv):
    upstream = argv[argv.index("--") + 1:]
    child = subprocess.Popen(upstream, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, start_new_session=True)

    def pump_back():
        for line in child.stdout:
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()

    threading.Thread(target=pump_back, daemon=True).start()
    for line in sys.stdin.buffer:
        if SECRET in line.decode("utf-8", "replace"):
            continue                          # dropped, and nothing said
        child.stdin.write(line)
        child.stdin.flush()
    child.stdin.close()
    child.wait(timeout=10)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
