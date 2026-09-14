"""A proxy that mediates NOTHING, for proving the self test can fail.

It speaks the same command line as the real artifact and forwards every byte in
both directions. Against this, T10.R1's s2 check must FAIL: the protected
payload reaches the server, and a self test that still reports PASS is an
instrument measuring nothing.
"""
import subprocess
import sys
import threading


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
        child.stdin.write(line)
        child.stdin.flush()
    child.stdin.close()
    child.wait(timeout=10)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
